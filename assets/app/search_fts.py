# -*- coding: utf-8 -*-
"""
全库消息全文检索索引（FTS5）。

解决的问题
----------
微信 4.x 把 248 万条消息散在 6404 张 Msg_<md5> 分表里。
原 WeChatDB.search() 全库检索 = 逐表 LIKE '%kw%'，实测卡死服务
（内存飙到 1.2G、整个 HTTP 服务无响应）。

本模块一次性把所有消息文本抽到**独立**的索引库：
  <data_dir>/.search_fts.sqlite3
  - msgs  : 去规范化表 (talker, name, content, ctime, is_send)
  - fts   : FTS5 虚表(tokenize=trigram)，external content = msgs.content

之后：
  - ≥3 字符关键词 → FTS5 MATCH，毫秒级
  - 1~2 字符关键词 → msgs 单表 LIKE（248 万行单表，仍远快于 6404 张分表）

设计原则：
  - 只读源库；索引库独立，绝不写回解密数据
  - 后台线程构建，服务不阻塞；status() 可查进度
  - 用户名直接用 db 实例解析好的，避免裸 md5
  - 增量：源数据目录 mtime 汇总没变就跳过重建

作者署名：云帆-H1088880
"""
import os
import glob
import time
import sqlite3
import threading

_INDEX_NAME = ".search_fts.sqlite3"

# 构建状态（进程内，供前端展示进度）
_state = {
    "status": "idle",     # idle | building | ready | error
    "progress": 0,        # 已处理文件数
    "total": 0,
    "count": 0,           # 已索引消息数
    "elapsed": 0.0,
    "error": "",
    "dir": "",
    "sig": "",            # 本次构建对应的数据签名
}
_lock = threading.Lock()


def _data_sig(data_dir):
    """数据目录签名：只用文件大小，不用 mtime。

    增量刷新每 20 秒替换页 → mtime 一直变，但**文件大小通常不变**。
    签名若含 mtime，服务一重启就误判"数据变了"→ 反复重建索引（1 分钟/次），
    永远就绪不了。用 size 可保持稳定；真有新库/体积变化才算变化。
    """
    h = 0
    files = sorted(glob.glob(os.path.join(data_dir, "message_*.db")) +
                   glob.glob(os.path.join(data_dir, "biz_message_*.db")))
    for p in files:
        try:
            st = os.stat(p)
            h = (h * 131 + st.st_size) & 0xFFFFFFFFFFFFFFFF
        except Exception:
            pass
    return f"{len(files)}:{h:x}"


def index_path(data_dir):
    return os.path.join(data_dir, _INDEX_NAME)


def status():
    with _lock:
        return dict(_state)


def _open_index(path):
    c = sqlite3.connect(path, timeout=10)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


def _ensure_schema(c):
    c.execute("""CREATE TABLE IF NOT EXISTS msgs (
        id INTEGER PRIMARY KEY,
        talker TEXT, name TEXT, content TEXT, ctime INTEGER, is_send INTEGER
    )""")
    try:
        c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(content, content='msgs', content_rowid='id', tokenize='trigram')")
    except sqlite3.Error:
        # 老版本 sqlite 无 trigram → 退回 unicode61（英文/数字仍可用，中文靠 LIKE 兜底）
        try:
            c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(content, content='msgs', content_rowid='id')")
        except sqlite3.Error:
            pass
    c.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
    c.commit()


def _has_fts(c):
    try:
        r = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='fts'").fetchone()
        return bool(r)
    except Exception:
        return False


def _build_sync(data_dir, db, force=False):
    """同步构建索引（由后台线程调用）。"""
    import db as dbmod
    out = index_path(data_dir)
    sig = _data_sig(data_dir)
    t0 = time.time()

    # 若已有可用索引（有数据），直接标记 ready，不因签名变化重建。
    # 签名只用于记录，真正刷新由 /api/search/rebuild 显式触发（force=True）。
    if not force and os.path.exists(out):
        try:
            c = _open_index(out)
            n = c.execute("SELECT COUNT(*) FROM msgs").fetchone()[0]
            hf = _has_fts(c)
            c.close()
            if n > 0 and hf:
                with _lock:
                    _state.update(status="ready", count=n, sig=sig,
                                  elapsed=round(time.time() - t0, 2), error="")
                return True
        except Exception:
            pass

    tmp = out + ".building"
    for p in (tmp, tmp + "-wal", tmp + "-shm"):
        try:
            os.remove(p)
        except Exception:
            pass

    c = _open_index(tmp)
    try:
        _ensure_schema(c)
        c.execute("DELETE FROM msgs")
        c.execute("DELETE FROM meta")
        c.commit()

        # 收集全部分表 (conn, table, hash)
        dbmod.WeChatDB  # noqa
        db._ensure_msg_index() if getattr(db, "lazy_msg_files", None) else None
        pairs = []
        seen = set()
        for table, conn in db.table_conn.items():
            if table in seen:
                continue
            seen.add(table)
            h = table.split("_", 1)[1] if "_" in table else ""
            pairs.append((conn, table, h))

        total_files = len(pairs)
        with _lock:
            _state.update(status="building", progress=0, total=total_files,
                          count=0, elapsed=0, error="", dir=data_dir, sig=sig)

        n = 0
        batch = []
        BATCH = 5000
        for i, (conn, table, h) in enumerate(pairs):
            try:
                cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")').fetchall()]
                content_c = None
                for cand in ("message_content", "compress_content", "content"):
                    if cand in cols:
                        content_c = cand
                        break
                ctime_c = "create_time" if "create_time" in cols else ("createTime" if "createTime" in cols else None)
                sender_c = "real_sender_id" if "real_sender_id" in cols else None
                if not content_c:
                    continue
                user = db._user_for_table(table, h)
                name = db.contact_name(user) if user else ""
                sel = f'SELECT "{content_c}"' + (f', "{ctime_c}"' if ctime_c else ', NULL')
                sel += (f', "{sender_c}"' if sender_c else ', NULL')
                sel += f' FROM "{table}"'
                for row in conn.execute(sel):
                    txt = dbmod._extract_text(row[0])
                    if not txt:
                        continue
                    ct = row[1] if ctime_c else 0
                    try:
                        ts = dbmod.WeChatDB._norm_time(ct)
                    except Exception:
                        ts = int(ct or 0)
                    batch.append((user, name, txt, ts, 0))
                    if len(batch) >= BATCH:
                        c.executemany("INSERT INTO msgs(talker,name,content,ctime,is_send) VALUES(?,?,?,?,?)", batch)
                        c.commit()
                        n += len(batch)
                        batch = []
            except Exception:
                continue
            with _lock:
                _state["progress"] = i + 1
                _state["count"] = n
                _state["elapsed"] = round(time.time() - t0, 1)
        if batch:
            c.executemany("INSERT INTO msgs(talker,name,content,ctime,is_send) VALUES(?,?,?,?,?)", batch)
            c.commit()
            n += len(batch)

        # 填充 FTS（external content 模式：建好后再 rebuild）
        if _has_fts(c):
            try:
                c.execute("INSERT INTO fts(fts) VALUES('rebuild')")
                c.commit()
            except Exception:
                pass
        c.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('sig',?)", (sig,))
        c.commit()
        c.close()

        # 原子替换
        os.replace(tmp, out)
        with _lock:
            _state.update(status="ready", count=n, sig=sig, progress=total_files,
                          elapsed=round(time.time() - t0, 1), error="")
        return True
    except Exception as e:
        try:
            c.close()
        except Exception:
            pass
        with _lock:
            _state.update(status="error", error=str(e)[:200], elapsed=round(time.time() - t0, 1))
        return False


def ensure_index(data_dir, db, background=True, force=False):
    """确保索引可用。background=True 时立即返回，后台线程构建。
    force=True 时忽略已有索引，强制重建（供手动刷新用）。"""
    st = status()
    if st["status"] == "building" and not force:
        return False
    sig = _data_sig(data_dir)
    path = index_path(data_dir)
    if not force and os.path.exists(path):
        try:
            c = _open_index(path)
            n = c.execute("SELECT COUNT(*) FROM msgs").fetchone()[0]
            has_fts = _has_fts(c)
            c.close()
            # 只要索引库有数据且 FTS 表在，就直接复用。
            # 绝不再因 sig 变化自动重建：增量刷新每 20 秒改文件大小，
            # 签名一直在变，会导致服务每次重启都重建（又慢又白费）。
            # 索引略滞后几分钟无妨——整理历史记录足够用；需要最新数据
            # 时由用户/前端显式调用 /api/search/rebuild 手动重建。
            if n > 0 and has_fts:
                with _lock:
                    _state.update(status="ready", count=n, sig=sig, dir=data_dir)
                return True
        except Exception:
            pass
    if background:
        t = threading.Thread(target=_build_sync, args=(data_dir, db, force), daemon=True)
        t.start()
        with _lock:
            _state.update(status="building", dir=data_dir, error="")
        return False
    return _build_sync(data_dir, db, force)


def search(q, limit=200, talker=None, data_dir=None, offset=0):
    """在索引里搜索。返回与 WeChatDB.search 相同结构的 dict 列表。"""
    if not q:
        return []
    limit = max(1, int(limit))
    offset = max(0, int(offset))
    path = index_path(data_dir) if data_dir else None
    if not path or not os.path.exists(path):
        return []
    try:
        c = _open_index(path)
    except Exception:
        return []
    out = []
    try:
        if len(q) >= 3 and _has_fts(c):
            sql = "SELECT m.talker,m.name,m.content,m.ctime,m.is_send FROM fts f JOIN msgs m ON m.id=f.rowid WHERE fts MATCH ?"
            params = [q]
            if talker:
                sql += " AND m.talker=?"
                params.append(talker)
            sql += " ORDER BY m.ctime DESC, m.id DESC LIMIT ? OFFSET ?"
            params.extend((limit, offset))
            for r in c.execute(sql, params):
                out.append({"talker": r[0] or "", "name": r[1] or "", "content": r[2] or "",
                            "time": r[3] or 0, "isSend": int(r[4] or 0)})
        if not out:  # <3 字符 或 FTS 无结果 → 单表 LIKE 兜底
            like = f"%{q}%"
            sql = "SELECT talker,name,content,ctime,is_send FROM msgs WHERE content LIKE ?"
            params = [like]
            if talker:
                sql += " AND talker=?"
                params.append(talker)
            sql += " ORDER BY ctime DESC, id DESC LIMIT ? OFFSET ?"
            params.extend((limit, offset))
            for r in c.execute(sql, params):
                out.append({"talker": r[0] or "", "name": r[1] or "", "content": r[2] or "",
                            "time": r[3] or 0, "isSend": int(r[4] or 0)})
    except Exception:
        pass
    finally:
        c.close()
    return out
