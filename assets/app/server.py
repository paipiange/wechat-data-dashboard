# -*- coding: utf-8 -*-
"""
WeChatDataAnalysis 精简版 · 本地只读分析服务（纯标准库 + pycryptodome）。
启动：python server.py [port] [--auto] [--data DIR] [--key HEX] [--open] [--bigscreen URL]

自动探测：启动时若未指定 --data，会扫描本机已解密输出（如你已装工具的解密目录），
命中即自动加载，无需手动填密钥。所有接口均为只读：不写库、不发消息、不连微信。
"""
import os
import sys
import json
import time
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from functools import partial

# 诊断开关：设置 WB_FAULT_DUMP=N 后，每 N 秒把所有线程栈写入 wa_fault.log。
# 只在排查卡死时临时启用，正常运行时不产生任何开销。
if os.environ.get("WB_FAULT_DUMP"):
    try:
        import faulthandler
        _fh = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "wa_fault.log"), "a", encoding="utf-8")
        faulthandler.enable(file=_fh)
        faulthandler.dump_traceback_later(
            int(os.environ["WB_FAULT_DUMP"]), repeat=True, file=_fh)
    except Exception:
        pass

import db as dbmod
import decrypt as decmod
import export as expmod
import digest_docx as docxmod
import search_fts as ftsmod
import annual as annualmod
import autodetect as admod
import keyring
import accounts as acctmod
import refresh as refreshmod
import platforms as platmod
import cloudstore

BASE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.join(BASE, "sample")
CONFIG_PATH = os.path.join(BASE, "config.json")   # 兼容旧位置，实际读写走 env


def _resolve_dirs():
    """解密产物目录统一由 env 决定（代码目录只读时自动回落状态目录）。"""
    global DECRYPTED_DIR
    try:
        import env as _env
        DECRYPTED_DIR = _env.decrypted_dir()
    except Exception:
        DECRYPTED_DIR = os.path.join(BASE, "decrypted")
    return DECRYPTED_DIR


_resolve_dirs()

# 当前分析的数据目录
CURRENT_DIR = None
_DB_CACHE = {"db": None, "path": None}

# 会话列表缓存：dir -> {"ts":, "data":}
_CONV_CACHE = {}
_CONV_LOCK = threading.Lock()
_CONV_THREAD = None
_CONV_DISK_LOADED = set()   # 已经尝试过从磁盘恢复的目录（避免每次请求都读文件）

# 解密任务状态（大库解密耗时较长，放后台线程跑，前端轮询进度）
_DECRYPT = {
    "running": False, "done": 0, "total": 0, "current": "",
    "ok": 0, "error": None, "dir": None, "out_dir": None,
    "started_at": 0, "finished": False,
}
_DECRYPT_LOCK = threading.Lock()

# 大屏窗口拉起：3 秒内重复点击只当一次（否则浏览器里连点会一屏堆好几个窗口）
_SCREEN_LOCK = threading.Lock()
_SCREEN_LAST = {"at": 0.0}

# 增量刷新器：只重新解密变化的页，让大屏始终显示最新消息
REFRESHER = refreshmod.Refresher(DECRYPTED_DIR)   # DECRYPTED_DIR 已由 _resolve_dirs() 就绪

# 登录二维码缓存：platform -> 二维码文件路径
# login 接口写入，qr 接口只读（避免每次取图都重跑一次 CLI 登录流程）
_QR_CACHE = {}
_QR_LOCK = threading.Lock()

# ---------- 自动增量刷新守护 ----------
# 微信开着时，新消息会持续写进 xwechat_files 的加密源库；
# 但大屏读的是「解密快照」目录。两者之间以前没有自动同步，
# 所以微信明明在发消息、大屏却一直显示老数据。
# 这里起一个守护线程：周期性做增量解密（只解变化的页，秒级），
# 解完就失效缓存并重建会话列表，大屏下一轮轮询就能看到新消息。
_AUTO_REFRESH = {"running": False, "last": 0, "changed": 0, "cycles": 0,
                 "last_error": "", "err_streak": 0, "interval": 20,
                 "stats_marked_at": 0}
_AUTO_REFRESH_LOCK = threading.Lock()


def start_auto_refresh(interval=20):
    """启动自动增量刷新守护线程（幂等）。"""
    with _AUTO_REFRESH_LOCK:
        if _AUTO_REFRESH["running"]:
            return
        _AUTO_REFRESH["running"] = True
        _AUTO_REFRESH["interval"] = max(5, int(interval))

    def loop():
        while True:
            try:
                acct = (CFG.get("account") or "").strip()
                if acct and not REFRESHER.running:
                    # 增量解密：只处理源库里新写入/变动的页。
                    # 刷新完成后由 REFRESHER.after_refresh 统一负责
                    # 重开连接 + 作废会话缓存 + 重建会话缓存（见 _reload_after_refresh）。
                    res = REFRESHER.refresh(acct)
                    now = __import__("time").time()
                    with _AUTO_REFRESH_LOCK:
                        _AUTO_REFRESH["last"] = now
                        _AUTO_REFRESH["changed"] = res.get("changed", 0)
                        _AUTO_REFRESH["cycles"] += 1
                        # 记录真实错误：之前只在 ok 时清空，
                        # 失败时 last_error 永远为空 → 看起来「一切正常」，
                        # 实际是每轮都在静默失败。
                        err = res.get("error") or ""
                        if not err:
                            for f in res.get("files") or []:
                                if f.get("error"):
                                    err = "%s: %s" % (f.get("file"), f.get("error"))
                                    break
                        if res.get("ok") and not err:
                            _AUTO_REFRESH["err_streak"] = 0
                            _AUTO_REFRESH["last_error"] = ""
                        else:
                            # 单轮失败很常见：微信正在写某个页、读者正好占着明文库，
                            # os.replace 抢不到空档就会报一次，下一轮（20s 后）通常自愈。
                            # 所以**连续 2 轮**失败才在界面上报「同步异常」，
                            # 否则两三个页面同时开着就会一闪一闪地变红，看着像坏了。
                            _AUTO_REFRESH["err_streak"] += 1
                            if _AUTO_REFRESH["err_streak"] >= 2:
                                _AUTO_REFRESH["last_error"] = (err or "刷新失败")[:200]
                __import__("time").sleep(_AUTO_REFRESH["interval"])
            except Exception as e:
                with _AUTO_REFRESH_LOCK:
                    _AUTO_REFRESH["err_streak"] += 1
                    if _AUTO_REFRESH["err_streak"] >= 2:
                        _AUTO_REFRESH["last_error"] = str(e)[:200]
                    _AUTO_REFRESH["last"] = __import__("time").time()
                __import__("time").sleep(_AUTO_REFRESH["interval"])

    threading.Thread(target=loop, daemon=True).start()

# ---------- 缓存落盘 ----------
# 为什么要落盘：会话列表和统计结果原来只存在内存里，
# 服务一重启（崩溃、看门狗拉起、计划任务重跑）缓存就全没了，
# 大屏首屏就变成一整屏「正在载入…」，看起来像坏了/乱码。
# 现在把两份缓存写到状态目录，下次启动先读旧数据顶上，
# 后台再慢慢重算 —— 重启前后大屏内容不跳变。
#
# 写文件用「先写 .tmp 再 os.replace」的原子替换，
# 否则服务被强杀时会留下半截 JSON，下次启动读坏了就再也起不来。
def _cache_file(tag, path):
    """缓存文件路径：状态目录 + 账号目录名哈希。"""
    import hashlib
    h = hashlib.md5(_norm_path(path).encode("utf-8")).hexdigest()[:12]
    try:
        import env as _env
        d = _env.ensure_dir(_env.state_dir())
    except Exception:
        d = BASE
    return os.path.join(d, "wb_cache_%s_%s.json" % (tag, h))


def _cache_write(tag, path, payload):
    try:
        fp = _cache_file(tag, path)
        tmp = fp + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
        os.replace(tmp, fp)
        return True
    except Exception:
        return False


def _cache_read(tag, path):
    try:
        with open(_cache_file(tag, path), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


# ---------- 大屏统计缓存 ----------
# 热力图要扫 230 万条消息（冷启动 2.6s），词频要读 4 万条正文。
# 大屏每 15 秒轮询一次，若每次都重算，白屏会被反复触发。
# 这里做「后台异步重算 + 前台立刻返回上次结果」的缓存。
_STATS_CACHE = {}       # dir -> {"ts":, "heatmap":, "words":, "emojis":, "building": bool}
_STATS_LOCK = threading.Lock()
# 统计全量扫描一次约 40 秒，不必每分钟重算：
# 数据只在「增量刷新解出新页」后才会变，invalidate_stats 会在那时清缓存。
# TTL 设长一些，避免无谓的周期性重算占用 CPU。
_STATS_TTL = 1800.0     # 缓存有效期（秒）


def _stats_debug():
    """统计缓存内部状态（诊断用）。"""
    import time as _t
    now = _t.time()
    with _STATS_LOCK:
        out = {}
        for p, c in _STATS_CACHE.items():
            out[p] = {
                "building": bool(c.get("building")),
                "stale": bool(c.get("stale")),
                "ts_age": round(now - c.get("ts", 0), 1),
                "heatmap": len(c.get("heatmap") or []),
                "words": len(c.get("words") or []),
                "emojis": len(c.get("emojis") or []),
            }
    # 注意：get_db() 绝不能在持有 _STATS_LOCK 时调用（会触发库重建并锁住别的路径）
    out["_threads"] = [t.name for t in threading.enumerate()]
    out["_current_dir"] = CURRENT_DIR
    return out


def get_stats(path, force=False):
    """取大屏统计（热力图/词频/表情）。

    命中缓存直接返回；否则返回旧值（若有）并在后台重建，
    绝不因为统计慢而阻塞 HTTP 响应。
    """
    now = __import__("time").time()
    path = _norm_path(path)
    with _STATS_LOCK:
        c = _STATS_CACHE.get(path)
        stale = bool(c and c.get("stale"))
        fresh = (c and (now - c.get("ts", 0)) < _STATS_TTL
                 and not c.get("building") and not stale)
        if fresh and not force:
            return c
        if c and c.get("building") and not force:
            return c          # 正在重建，先用旧值
        if c is None:
            # 进程刚起：内存里没有 → 先从磁盘读上次的结果顶上来，
            # 大屏立刻就有热力图/词频/表情可看，后台再重算一遍。
            disk = _cache_read("stats", path)
            if disk and (disk.get("heatmap") or disk.get("words") or disk.get("emojis")):
                # stale 保持 False：磁盘这份就是"上次的结果"，
                # 本轮只重算一次（worker 跑完即可收手），别来回重算两遍。
                c = {"ts": disk.get("ts", 0), "heatmap": disk.get("heatmap") or [],
                     "words": disk.get("words") or [], "emojis": disk.get("emojis") or [],
                     "building": True, "stale": False}
                _STATS_CACHE[path] = c
            else:
                c = {"ts": 0, "heatmap": [], "words": [], "emojis": [],
                     "building": True, "stale": False}
                _STATS_CACHE[path] = c
        else:
            # 已完成但被标记过期：先把旧值留着给前端用，同时后台重算
            c["building"] = True
            c["stale"] = False

    def worker():
        d = None
        own_db = False
        # 后台统计等得起「文件正被替换」：最多等 60 秒。
        # （请求线程只等 3 秒，优先保证接口不卡）
        try:
            dbmod.set_block_wait(60.0)
        except Exception:
            pass
        try:
            # 用**独立**的 db 实例，不复用请求线程的缓存实例。
            #
            # 原因：请求线程在增量刷新后会重建实例并 close() 旧的，
            # 而 close() 会清空旧实例的表映射（table_conn / aux）。
            # 统计线程手里正好是那个旧实例 → 遍历不到任何表
            # → text_corpus() 返回空 → 词频/表情统计恒为 0，
            # 而且日志里连一行错误都没有（因为压根没抛异常，是"查了个空"）。
            #
            # 独立实例有自己的连接，与请求线程互不影响；
            # 增量刷新关连接时也只关连接（映射保留 + 代次自动重开），
            # 所以统计既不会被清空，也不会被 use-after-free 打断。
            try:
                with dbmod.file_access_lock():
                    d = dbmod.WeChatDB(CURRENT_DIR or DECRYPTED_DIR)
                    own_db = True
            except Exception:
                d = get_db()
                own_db = False
            heat = d.time_heatmap(None)
            texts = d.text_corpus(None)
            # 通讯录里的英文人名（jason/xiao/hl…）不是词，从词频里剔除
            en_stop = d.english_name_stopwords() if hasattr(d, "english_name_stopwords") else None
            words, emojis = dbmod.word_emoji_freq(texts, top=40, extra_stop=en_stop)
            with _STATS_LOCK:
                # 注意：worker 跑的这 90 秒里，自动刷新可能又标记了一次 stale。
                # 这里保留那个标记，之后自动再跑一轮，不用等下次请求。
                still_stale = bool(c.get("stale")) if c else False
                _STATS_CACHE[path] = {
                    "ts": __import__("time").time(),
                    "heatmap": heat,
                    "words": [{"w": w, "c": n} for w, n in words],
                    "emojis": [{"e": e, "c": n} for e, n in emojis],
                    "building": False,
                    "stale": still_stale,
                }
            # 落盘：下次服务重启直接读这份结果，大屏不会退回一屏「正在载入…」
            _cache_write("stats", path, {
                "ts": __import__("time").time(),
                "heatmap": heat,
                "words": [{"w": w, "c": n} for w, n in words],
                "emojis": [{"e": e, "c": n} for e, n in emojis],
            })
            # 期间又有新数据进来：不等用户下次请求，自己接着再算一轮
            if still_stale:
                __import__("time").sleep(2)
                get_stats(path)
        except Exception as e:
            # 统计失败要留痕：之前这里完全静默，表现就是面板一直空白，
            # 根本看不出是"还在算"还是"算崩了"。
            try:
                with open(os.path.join(BASE, "wa_stats.log"), "a", encoding="utf-8") as f:
                    f.write("[%s] 统计失败: %r\n" % (
                        __import__("time").strftime("%Y-%m-%d %H:%M:%S"), e))
            except Exception:
                pass
            with _STATS_LOCK:
                cur = _STATS_CACHE.get(path)
                if cur is not None:
                    cur["building"] = False
                    cur["ts"] = __import__("time").time()
        finally:
            # 独立实例用完就关：否则 44 个库的连接句柄会一直挂着，
            # 增量刷新替换文件时 os.replace 会因为句柄被占而失败。
            try:
                # 只关**自己建**的独立实例；
                # 万一走了 fallback（用请求线程的缓存实例），绝不能关它。
                if d is not None and own_db:
                    d.close()
            except Exception:
                pass

    threading.Thread(target=worker, daemon=True).start()
    with _STATS_LOCK:
        return _STATS_CACHE.get(path) or c


def invalidate_stats(path):
    """把统计缓存标记为过期（下次读取时重建），而不是直接删掉。

    直接 pop 有个致命问题：自动增量刷新每 20 秒就可能标记一次，
    而一次全量统计要几十秒（zstd 解压后更慢），
    于是统计永远在「重建 → 被作废 → 再重建」之间循环，面板一直空白。
    改成打标记后，正在跑的 worker 跑完就能把结果落下来，
    下一轮再看标记决定要不要重来。
    """
    with _STATS_LOCK:
        path = _norm_path(path)
        c = _STATS_CACHE.get(path)
        if c is not None:
            c["stale"] = True
        else:
            _STATS_CACHE[path] = {"ts": 0, "heatmap": [], "words": [],
                                  "emojis": [], "building": True, "stale": True}


def _account_for_msg_dir(msg_dir):
    """把加密源库目录映射成 accounts 里的账号标识（keyring 以它做命名空间）。"""
    try:
        want = os.path.normcase(os.path.abspath(msg_dir))
        for row in acctmod.list_accounts():
            d = row.get("msg_dir") or ""
            if d and os.path.normcase(os.path.abspath(d)) == want:
                return row.get("account")
    except Exception:
        pass
    return os.path.basename((msg_dir or "").rstrip("/\\")) or None


def start_decrypt_account(account, msg_dir):
    """后台：走微信 4.x 的正确路径 —— keyring 逐库密钥 → 缺的从进程只读补提取 → 逐库解密。

    为什么不能只用一个密钥：4.x 里**每个 .db 有自己的 salt + 32 字节 key**，
    单密钥最多解开其中一个库，其余 19 个会全部失败（旧 /api/auto 就是这样）。
    """
    with _DECRYPT_LOCK:
        if _DECRYPT["running"]:
            return False
        _DECRYPT.update({"running": True, "done": 0, "total": 0, "current": "",
                         "ok": 0, "error": None, "needs_key": False,
                         "dir": msg_dir, "out_dir": "",
                         "started_at": __import__("time").time(), "finished": False})

    def progress(idx, total=None, name=None):
        if name is None:
            _DECRYPT.update({"current": str(idx)})
        else:
            _DECRYPT.update({"done": idx, "total": total, "current": name})

    def worker():
        try:
            res = acctmod.decrypt_account(account, progress=progress)
            if res.get("ok"):
                out = res.get("out_dir")
                if out and os.path.isdir(out):
                    get_db(out)
                    ensure_conv_cache(out)
                _DECRYPT.update({"ok": res.get("ok_count") or 0,
                                 "error": None, "out_dir": out or ""})
            else:
                err = res.get("error") or "解密失败"
                _DECRYPT.update({"error": err,
                                 "needs_key": ("密钥" in err)})
        except Exception as e:
            _DECRYPT.update({"error": str(e)})
        finally:
            _DECRYPT.update({"running": False, "finished": True})

    threading.Thread(target=worker, daemon=True).start()
    return True


def start_decrypt(enc, out_dir, key):
    """后台线程执行解密，返回是否成功启动。"""
    with _DECRYPT_LOCK:
        if _DECRYPT["running"]:
            return False
        _DECRYPT.update({"running": True, "done": 0, "total": 0, "current": "",
                         "ok": 0, "error": None, "dir": enc, "out_dir": out_dir,
                         "started_at": __import__("time").time(), "finished": False})

    def progress(idx, total, name):
        _DECRYPT.update({"done": idx, "total": total, "current": name})

    def worker():
        try:
            res = decmod.auto_decrypt(enc, out_dir, key_hex=key, progress=progress)
            if res.get("ok"):
                get_db(out_dir)
                ensure_conv_cache(out_dir)
                if key and key != CFG.get("key"):
                    CFG["key"] = key
                    save_config()
                _DECRYPT.update({"ok": res.get("ok_count") or 0, "error": None})
            else:
                first_err = ""
                for r in res.get("results") or []:
                    if not r.get("ok"):
                        first_err = f'{r.get("file")}: {r.get("error")}'
                        break
                _DECRYPT.update({"error": res.get("error") or first_err or "解密失败"})
        except Exception as e:
            _DECRYPT.update({"error": str(e)})
        finally:
            _DECRYPT.update({"running": False, "finished": True})

    threading.Thread(target=worker, daemon=True).start()
    return True

# 运行配置（命令行 / config.json）
CFG = {
    "auto": True,
    "data": None,      # 显式指定的已解密数据目录
    "key": None,       # 解密密钥（十六进制）
    # 大屏地址：留空 = 跟随当前页面（同源）。
    # 以前默认写死成 http://127.0.0.1:7391 —— 那是开发机上的 CodeScreen 反代入口，
    # 需要输 PIN 码，别人装完点"大屏"必然打不开。只有用户显式配置（隧道/局域网/反代）时才写死。
    "bigscreen": "",
    "host": "127.0.0.1",
}


def _env_info():
    """运行环境诊断（供 /api/status 展示，排查跨环境差异用）。"""
    try:
        import env as _env
        import keyring as _kr
        d = _env.describe()
        d["keyring_accounts"] = len(_kr.accounts())
        d["keyring_path"] = _kr.KEYRING_PATH
        d["config_path"] = _env.config_path()
        return d
    except Exception as e:
        return {"error": str(e)}


def load_config():
    """
    读取运行配置。

    优先读状态目录（~/.wb_analyzer/config.json，可写、跨环境一致）；
    若不存在，再回落到代码目录下的 config.json（旧版位置，只读兼容）。
    """
    global CFG
    import env as _env
    candidates = [_env.config_path()] + [
        p for p in _env.legacy_config_paths() if p != _env.config_path()]
    for path in candidates:
        if not path or not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                CFG.update(json.load(f))
            return
        except Exception:
            continue


def save_config():
    """写回状态目录的配置文件（代码目录可能只读）。"""
    try:
        import env as _env
        path = _env.config_path()
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(CFG, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _norm_path(p):
    """
    规范化路径，用于缓存键比较。

    为什么要规范化：同一个目录可能以不同分隔符/大小写出现
    （如 'D:/wb-analyzer/decrypted/acc' 与 'D:\\wb-analyzer\\decrypted\\acc'）。
    若拿原始字符串当缓存键，自动刷新每 20 秒就会"认为路径变了"，
    从而关闭正在被统计线程使用的 sqlite 连接并重建 —— 统计永远算不完，
    面板一直空白。这里统一规范化，避免无意义的重建。
    """
    if not p:
        return ""
    try:
        return os.path.normcase(os.path.abspath(p))
    except Exception:
        return str(p)


def get_db(data_dir=None):
    global CURRENT_DIR, _DB_CACHE
    path = data_dir or CURRENT_DIR or (DECRYPTED_DIR if (os.path.isdir(DECRYPTED_DIR) and os.listdir(DECRYPTED_DIR)) else SAMPLE_DIR)
    key = _norm_path(path)
    # 闸门：与「原子替换明文副本」互斥。
    # 少了它，替换窗口内新建的连接会重新占住文件 → os.replace 失败。
    with dbmod.file_access_lock():
        if _DB_CACHE["db"] is not None and _DB_CACHE["path"] == key:
            # 连接被 close_file 关掉过（增量解密替换文件前会这么做）→
            # 这个实例已经是僵尸，必须重建，否则查询报 "closed database"。
            if not getattr(_DB_CACHE["db"], "invalid", False):
                return _DB_CACHE["db"]
        if _DB_CACHE["db"] is not None:
            try:
                _DB_CACHE["db"].close()
            except Exception:
                pass
        CURRENT_DIR = path
        invalidate_conv_cache(path)
        d = dbmod.WeChatDB(path)
        _DB_CACHE["db"] = d
        _DB_CACHE["path"] = key
        return d


def _release_thread_conns():
    """请求结束：释放**本线程**持有的 SQLite 连接。

    必须做：HTTP 是「一请求一线程」，线程退出后连接还留在代理里，
    文件句柄一直被占着 → Windows 上 os.replace 替换不了明文副本
    → 增量刷新每轮失败（数据链路显示「同步异常」）。
    """
    d = _DB_CACHE.get("db")
    if d is None:
        return
    try:
        d.close_thread_conns()
    except Exception:
        pass


# ---------- 刷新完成后的统一重载 ----------
_RELOAD_LOCK = threading.Lock()


def _close_conn_for_replace(out_path):
    """增量解密替换明文副本**之前**关闭指向该文件的 SQLite 连接。

    Windows 特有坑：os.replace 的实现是「删除目标 → 改名」，而 SQLite 打开的
    文件不允许被删除，会直接报 [WinError 5] 拒绝访问。
    结果是增量刷新每轮都失败（changed=0），看板永远停在旧数据。

    这里在替换前把**所有** db 实例里指向该文件的连接关掉。
    注意不能只关当前缓存的那个实例：历史重建过的实例仍握着句柄，
    也会让 os.replace 失败（实测这就是 changed 一直是 0 的根因）。

    关掉后 _DB_CACHE["db"] 仍指向旧实例，但它的连接已失效 ——
    替换完成后 _reload_after_refresh 会重建实例，一切恢复正常。
    """
    try:
        dbmod.close_file_everywhere(out_path, timeout=1.0)
    except Exception:
        pass
    # 当前缓存实例也要标记为失效（close_file_everywhere 内部已置位，
    # 这里再兜一次，防止异常路径漏掉）
    try:
        d = _DB_CACHE.get("db")
        if d is not None:
            d.invalid = True
    except Exception:
        pass


# 把钩子挂到增量解密器上：每次 os.replace 之前都会调用
try:
    REFRESHER.dec.before_replace.append(_close_conn_for_replace)
except Exception:
    pass


def _reload_after_refresh(account, stats=None):
    """增量刷新完成后统一重载（自动刷新和手动刷新共用同一入口）。

    做三件事：
      1) 重开数据库连接 —— 明文副本被原子替换过，旧连接指向旧 inode，看不到新数据
      2) 作废会话缓存与统计缓存
      3) 重新构建会话列表（TOP 会话按最后活跃时间排序）
    """
    target = os.path.join(DECRYPTED_DIR, account)
    with _RELOAD_LOCK:
        try:
            reopen_db(target)
            # 统计重建很慢（全量扫 + zstd 解压），不能每 20 秒就作废一次，
            # 否则永远算不完。这里做节流：距上次标记至少 5 分钟才作废统计。
            # 只有「消息库」真的变了才失效统计缓存；session/contact 这类库
            # 几乎每秒都在变，如果也跟着失效，统计重建永远完不成（面板一直空白）。
            msg_changed = 0
            for f in (stats or {}).get("files") or []:
                name = (f.get("file") or "").lower()
                if name.startswith("message") and f.get("changed"):
                    msg_changed += f.get("changed") or 0
            if msg_changed:
                last_mark = _AUTO_REFRESH.get("stats_marked_at") or 0
                if __import__("time").time() - last_mark > 300:
                    invalidate_stats(target)
                    _AUTO_REFRESH["stats_marked_at"] = __import__("time").time()
            ensure_conv_cache(target)
        except Exception as e:
            with _AUTO_REFRESH_LOCK:
                _AUTO_REFRESH["last_error"] = "重建缓存失败: " + str(e)[:120]


# 注入回调：刷新一完成就重连 + 重建缓存
REFRESHER.after_refresh = _reload_after_refresh


def reopen_db(path):
    """增量刷新后重开数据库连接。

    明文副本在增量解密时会被原子替换（os.replace），旧连接仍然指向
    **旧的 inode**——它看不到新解出来的页，统计和会话排序都会停在旧数据上。
    这里换一个新连接，并顺手作废会话/统计缓存，让大屏立刻读到新数据。

    放置在刷新之后调用，是修复「大屏显示的不是最新会话」的关键一步。

    注意：**不要 close() 旧连接**。会话计数 worker 可能正拿着它跑
    （300 个会话逐个统计消息数，要跑几十秒），中途 close 会让 worker 抛
    "Cannot operate on a closed database"，缓存被清成空列表，
    大屏的 TOP 会话就会整块消失。旧连接指向旧 inode（数据旧但完整），
    等 worker 用完由引用计数自然回收即可。
    """
    global CURRENT_DIR, _DB_CACHE
    key = _norm_path(path)
    invalidate_conv_cache(path)
    # 旧实例如果已经被 close_file 关过（增量解密替换文件时），
    # 它的连接处于失效状态 —— 这里统一关掉，避免句柄泄漏。
    # 注意：**只关已失效的**。还在正常使用的旧实例不能关：
    # 会话计数 worker 可能正拿着它跑（300 个会话逐个统计消息数），
    # 中途 close 会让 worker 抛 "Cannot operate on a closed database"，
    # 缓存被清成空列表，大屏的 TOP 会话就会整块消失。
    old = _DB_CACHE.get("db")
    if old is not None and getattr(old, "invalid", False):
        try:
            old.close()
        except Exception:
            pass
    # 注意：统计缓存**不在这里**作废。
    # 统计全量重建要几十秒，自动刷新每 20 秒就来一次，
    # 每次都作废 → 统计永远在「重建 → 被作废 → 再重建」里循环，面板一直空白。
    # 统计的失效由调用方按 5 分钟节流处理（见 _reload_after_refresh）。
    CURRENT_DIR = path
    # 闸门：重建时打开文件会占住句柄，
    # 若正好撞上增量替换的窗口，替换就会失败。
    with dbmod.file_access_lock():
        d = dbmod.WeChatDB(path)
    _DB_CACHE["db"] = d
    _DB_CACHE["path"] = key
    return d


# ---------- 会话列表后台缓存 ----------
def _conv_count_from_cache(talker):
    """从会话列表缓存里取某个会话的消息条数。

    会话缓存里每个条目已经带 count（统计会话时顺带算出来的），
    复用它可以避免每翻一页都做一次 SELECT COUNT(*) 全表扫描。
    缓存里没有这个会话时返回 None，由调用方回退到实算。
    """
    if not talker or not CURRENT_DIR:
        return None
    try:
        with _CONV_LOCK:
            c = _CONV_CACHE.get(_norm_path(CURRENT_DIR))
            data = (c or {}).get("data") or []
        for item in data:
            if item.get("talker") == talker:
                n = item.get("count")
                if isinstance(n, int) and n > 0:
                    return n
    except Exception:
        pass
    return None


def invalidate_conv_cache(path):
    """把会话缓存标记为过期（保留旧数据），而不是直接删掉。

    直接 pop 的问题：清空后到重建完成之间（清单阶段就要几秒到十几秒），
    大屏的 TOP 会话会整块消失 —— 表现为「刷新一下就空了」。
    改成打标记：旧数据继续给前端用，后台悄悄换成新的。
    """
    with _CONV_LOCK:
        key = _norm_path(path)
        c = _CONV_CACHE.get(key)
        if c is not None:
            c["stale"] = True
        else:
            # 注意 loading 必须是 False：
            # 这里只是放一个「还没有数据、待重建」的占位，
            # 若置成 True，ensure_conv_cache 会以为「已经在算了」而直接返回，
            # 后台 worker 就永远起不来（会话列表一直是空）。
            _CONV_CACHE[key] = {"ts": 0, "data": None, "loading": False,
                                "counting": False, "stale": True}


_RECENT_CACHE = {}          # talker -> {"ts": float, "items": [...]}
_RECENT_CACHE_LOCK = threading.Lock()
_RECENT_TTL = 8.0           # 秒：recent 消息 8 秒内复用，够新又不卡
_RECENT_BLOCK_WAIT = 1.5    # 秒：单次查询最多等文件替换这么久


def _recent_messages_cached(db, top):
    """取 TOP 会话的最新消息，带短 TTL 缓存。

    为什么必须有缓存（实测）：
    `/api/dash` 每次轮询都要给 6 个会话各查一次最新消息，
    而增量刷新每 20 秒会**原子替换**消息库文件。
    替换期间文件被"隔离"，读者线程要等它放行（默认 12 秒），
    6 个会话串行等下来 → 接口耗时 15~25 秒 → 大屏看起来就是"卡住不动"。

    两道措施：
      1) 短 TTL 缓存：同一会话 8 秒内的请求直接复用上次结果。
      2) 单次查询最多只等 1.5 秒文件替换，超时就用旧缓存
         （宁可消息晚 20 秒，也不能让整块面板转圈）。
    """
    now = __import__("time").time()
    out = []
    with _RECENT_CACHE_LOCK:
        # 先把仍然新鲜的缓存项挑出来
        fresh = {}
        for c in top[:6]:
            talker = c.get("talker")
            hit = _RECENT_CACHE.get(talker)
            if hit and (now - hit["ts"]) < _RECENT_TTL:
                fresh[talker] = hit
        _RECENT_CACHE.update(fresh)

    missing = [c for c in top[:6] if c.get("talker") not in fresh]
    if missing:
        # 只让当前线程在文件替换时最多等 1.5 秒
        try:
            dbmod.set_block_wait(_RECENT_BLOCK_WAIT)
        except Exception:
            pass
        try:
            for c in missing:
                talker = c.get("talker")
                items = []
                try:
                    ms = db.messages(talker, page=0, page_size=6, order="desc")
                except Exception:
                    ms = []
                for m in ms:
                    items.append({"name": c["name"], "talker": talker,
                                  "time": m.get("time") or 0,
                                  "sender": m.get("sender") or "",
                                  "sender_name": m.get("sender_name") or "",
                                  "isSend": int(m.get("isSend") or 0),
                                  "content": (m.get("content") or "")[:120]})
                with _RECENT_CACHE_LOCK:
                    _RECENT_CACHE[talker] = {"ts": now, "items": items}
                out.extend(items)
        finally:
            try:
                dbmod.set_block_wait(12.0)
            except Exception:
                pass

    with _RECENT_CACHE_LOCK:
        for c in top[:6]:
            talker = c.get("talker")
            hit = fresh.get(talker) or _RECENT_CACHE.get(talker)
            if hit:
                # 会话名可能被改名/重建 → 用最新的 name 覆盖缓存里的
                for it in hit["items"]:
                    it["name"] = c.get("name") or it.get("name") or ""
                out.extend(hit["items"])
        # 清理已不在 TOP 里的缓存，避免无限增长
        keep = {c.get("talker") for c in top[:12]}
        for k in list(_RECENT_CACHE.keys()):
            if k not in keep:
                _RECENT_CACHE.pop(k, None)

    out.sort(key=lambda x: -x["time"])
    return out[:24]


def ensure_conv_cache(path, limit=300):
    """后台计算会话列表并缓存。

    两阶段：
      1) 立刻出「会话清单 + 最后活跃时间」（读 session 表）
      2) 再分批补每会话的消息数，每批之间 sleep 让出 GIL，
         避免大库统计把整个 HTTP 服务卡住（表现为白屏）

    重建期间**保留旧数据**（stale 标记），前端始终有内容可显示，
    不会因为一次重建就整块变空白。
    """
    path = _norm_path(path)
    # 内存里没有可用数据 → 先从磁盘恢复上一份（服务重启后大屏立刻有内容）。
    # 读文件放在锁外面，避免把 _CONV_LOCK 持有时间拉长。
    with _CONV_LOCK:
        cached = _CONV_CACHE.get(path)
        need_disk = not (cached and cached.get("data"))
    if need_disk:
        disk = _cache_read("conv", path)
        if disk and isinstance(disk.get("data"), list) and disk["data"]:
            with _CONV_LOCK:
                _CONV_CACHE[path] = {"ts": disk.get("ts", 0), "data": disk["data"],
                                     "loading": False, "counting": False, "stale": True}
                _CONV_DISK_LOADED.add(path)
    with _CONV_LOCK:
        cached = _CONV_CACHE.get(path)
        if cached is not None:
            if cached.get("loading"):
                return              # 正在算，别重复启动
            if cached.get("data") is not None and not cached.get("stale"):
                return              # 有新鲜数据
            # 有旧数据但已过期 → 保留旧数据，后台悄悄重算
            cached["stale"] = True
            cached["loading"] = True
            cached["counting"] = False
            cached["error"] = None
        else:
            _CONV_CACHE[path] = {"ts": 0, "data": None, "loading": True,
                                 "counting": False, "stale": False}

    def worker():
        try:
            d = get_db(path)
            # ── 阶段 1：清单（快） ──
            data = d.conversations(limit=limit)
            # 沿用上一轮已经算好的条数：否则每次重建都会把 count 归零，
            # 大屏「总消息」会先掉一大截、再随后台计数慢慢涨回来，
            # 看起来像丢了数据。这里按 talker 继承旧值，数字只增不乱跳。
            with _CONV_LOCK:
                prev = _CONV_CACHE.get(path) or {}
                old_counts = {c.get("talker"): c.get("count")
                              for c in (prev.get("data") or []) if c.get("count")}
            if old_counts:
                for c in data:
                    if not c.get("count"):
                        v = old_counts.get(c.get("talker"))
                        if v:
                            c["count"] = v
            with _CONV_LOCK:
                _CONV_CACHE[path] = {"ts": __import__("time").time(), "data": data,
                                     "loading": True, "counting": True, "stale": False}

            # ── 阶段 2：分批补计数（慢，但可中断） ──
            # 同时算「最后一条消息的时间」——这是 TOP 会话按最新排序的依据。
            # 只算前 80 个会话（按 session 表的最近活跃预排），
            # 因为 TOP 只需要最靠前的那批；全量 300 个太慢。
            budget = 20.0
            started = __import__("time").time()
            BATCH = 20
            TOP_N = 80
            gentle = False
            for i in range(0, len(data), BATCH):
                if not gentle and __import__("time").time() - started > budget:
                    # 预算用尽不要直接 break —— 那样后面的会话永远是 0 条，
                    # 大屏上大半会话都显示「0 条」，看着像数据丢了。
                    # 改成转入「慢速补齐」：每批多睡一会儿，后台慢慢算完。
                    gentle = True
                chunk = data[i:i + BATCH]
                for c in chunk:
                    try:
                        # 连接可能在批次之间被增量解密关掉（close_file），
                        # 此时要重新取 db —— get_db 会重建失效的实例。
                        if getattr(d, "invalid", False):
                            d = get_db(path)
                        c["count"] = d.count_conversation(c.get("talker"))
                    except Exception:
                        # 计数失败时保留原值，不要清零：
                        # 清零会让「消息数」列变成 0，看起来像数据丢了。
                        if "count" not in c:
                            c["count"] = 0
                    # 精确的最后消息时间（消息表 MAX(create_time)）
                    # 比 session 表的 sort_timestamp 更准：
                    # 后者是「会话排序」用的，微信会因置顶/未读等原因重排。
                    if i < TOP_N:
                        try:
                            lm = d.last_message_time(c.get("talker"))
                            if lm:
                                c["last_msg_time"] = lm
                        except Exception:
                            pass
                with _CONV_LOCK:
                    _CONV_CACHE[path] = {"ts": __import__("time").time(), "data": list(data),
                                         "loading": True, "counting": True, "stale": False}
                # 每批结束释放本线程的连接：
                # 不释放的话这些消息库的文件句柄一直被占着，
                # 增量刷新 os.replace 替换不进去 → 该库永远刷不新。
                try:
                    d.close_thread_conns()
                except Exception:
                    pass
                # 让出 GIL，保证 HTTP 线程能响应（慢速补齐阶段睡更久）
                __import__("time").sleep(0.15 if gentle else 0.02)

            with _CONV_LOCK:
                _CONV_CACHE[path] = {"ts": __import__("time").time(), "data": list(data),
                                     "loading": False, "counting": False, "stale": False}
            # 落盘：服务重启后直接读这份，大屏 TOP 会话不会整块空掉
            _cache_write("conv", path, {"ts": __import__("time").time(),
                                         "data": list(data)})
        except Exception as e:
            # 出错时**不要**把缓存清空成空列表：清空会让大屏的 TOP 会话整块消失。
            # 保留上一份可用数据（哪怕是旧的），同时记下错误，下一轮刷新会重试。
            with _CONV_LOCK:
                prev = _CONV_CACHE.get(path) or {}
                keep = prev.get("data")
                _CONV_CACHE[path] = {"ts": __import__("time").time(),
                                     "data": keep if keep is not None else [],
                                     "loading": False, "counting": False,
                                     "error": str(e)[:200]}
            import traceback
            traceback.print_exc()
            # 稍后自动重试一次
            def _retry():
                import time as _t
                _t.sleep(3)
                try:
                    with _CONV_LOCK:
                        _CONV_CACHE.pop(_norm_path(path), None)
                    ensure_conv_cache(path, limit=limit)
                except Exception:
                    pass
            threading.Thread(target=_retry, daemon=True).start()

    t = threading.Thread(target=worker, daemon=True)
    t.start()


def get_conv_cache(path):
    """取会话缓存。

    进程刚起时内存里是空的 —— 原来直接返回 None，
    大屏首屏整个 TOP 会话是空的（看着像坏了/乱码），要等十几秒重算才有内容。
    现在先从磁盘把上次的结果读回来顶上一阵（标记 stale 让后台照常重建），
    重启前后大屏内容不跳变。
    """
    key = _norm_path(path)
    with _CONV_LOCK:
        c = _CONV_CACHE.get(key)
        # 注意：不能只看"内存里没有这个 key"——
        # get_db() 建连接时会先放一个 data=None 的占位（invalidate_conv_cache），
        # 那样就永远轮不到磁盘恢复，大屏还是会一屏空。
        # 所以只要内存里没有"可用的数据"，就试一次磁盘。
        need_disk = (not (c and c.get("data"))) and (key not in _CONV_DISK_LOADED)
        if need_disk:
            _CONV_DISK_LOADED.add(key)
    if need_disk:
        disk = _cache_read("conv", key)
        if disk and isinstance(disk.get("data"), list) and disk["data"]:
            with _CONV_LOCK:
                _CONV_CACHE[key] = {"ts": disk.get("ts", 0), "data": disk["data"],
                                    "loading": False, "counting": False, "stale": True}
            with _CONV_LOCK:
                c = _CONV_CACHE.get(key)
    return c


# ── 账号列表缓存 ─────────────────────────────────────────────────────────
# list_accounts() 要全盘 os.walk 扫微信加密目录 + 逐库读 salt，实测 0.9 秒。
# 它只是给账号下拉框用的，账号信息几乎不变 —— 缓存 60 秒，
# 让 /api/dash 从 ~0.93 秒降到 ~0.02 秒，不再占着 SQLite 读锁。
_ACCT_CACHE = {"ts": 0, "data": None}
_ACCT_CACHE_LOCK = threading.Lock()
_ACCT_CACHE_TTL = 60.0


def _accounts_cached():
    """账号列表带 TTL 缓存；过期时后台刷新，当前请求先用旧值顶上。"""
    now = __import__("time").time()
    with _ACCT_CACHE_LOCK:
        cached = _ACCT_CACHE.get("data")
        fresh = cached is not None and (now - _ACCT_CACHE.get("ts", 0)) < _ACCT_CACHE_TTL
    if fresh:
        return cached

    def _worker():
        try:
            data = acctmod.list_accounts()
        except Exception:
            data = []
        with _ACCT_CACHE_LOCK:
            _ACCT_CACHE["ts"] = __import__("time").time()
            _ACCT_CACHE["data"] = data

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return cached if cached is not None else []


# ── 多平台状态（飞书 / 钉钉 / 企业微信）────────────────────────────────────
# 平台可用性检测要调 CLI，可能耗时；这里做缓存，避免拖慢 /api/dash 首屏。
_PLAT_STATUS_CACHE = {"ts": 0, "data": None}
_PLAT_STATUS_LOCK = threading.Lock()


def _platform_status_safe(force=False):
    """返回各平台状态，失败时返回空列表而不是让整个 dash 挂掉。

    平台探测要调三个外部 CLI（wecom-cli / lark-cli / dws），实测首次要 15 秒以上。
    如果放在请求线程里同步跑，大屏首屏会被拖到十几秒才出数据。
    所以改成：缓存过期时立刻返回当前缓存（没有就返回空列表），
    同时丢到后台线程去刷新，下次请求就能拿到最新状态。
    """
    now = __import__("time").time()
    with _PLAT_STATUS_LOCK:
        cached = _PLAT_STATUS_CACHE.get("data")
        fresh = (cached is not None and now - _PLAT_STATUS_CACHE.get("ts", 0) < 60)
        if not force and fresh:
            return cached

    def _worker():
        try:
            data = platmod.platform_status()
        except Exception as e:
            data = []
            # 注意：server.py 里没有 log() 函数，写文件前不要调用它，
            # 否则 NameError 会把整个 worker 线程打死，缓存永远写不进去。
            try:
                with open(os.path.join(BASE, "wa_plat.log"), "a", encoding="utf-8") as f:
                    f.write("[%s] 平台状态检测失败: %s\n" % (
                        __import__("time").strftime("%Y-%m-%d %H:%M:%S"), e))
            except Exception:
                pass
        with _PLAT_STATUS_LOCK:
            _PLAT_STATUS_CACHE["ts"] = __import__("time").time()
            _PLAT_STATUS_CACHE["data"] = data

    # 后台刷新，绝不阻塞当前请求
    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    # 已有旧缓存就先用旧缓存顶上；首次没有就返回空列表（前端会显示未授权/检测中）
    return cached if cached is not None else []


# ---------- HTTP 辅助 ----------
def send_json(handler, obj, status=200):
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    try:
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
        # 客户端提前断开（超时/关页面/浏览器刷新）——这是正常情况，
        # 不能让它冒泡成 500，更不能影响其他请求线程。
        pass
    except OSError:
        # Windows 上 socket 断开可能抛别的 OSError 子类
        # （如 ConnectionError / WSAECONNRESET），一并吞掉。
        pass


def send_file(handler, body, mime, fname):
    try:
        # 文件名含中文时，HTTP 头默认 latin-1 编码会抛异常、导致响应头残缺/
        # 连接中断（表现为 IncompleteRead、curl "Header without colon"）。
        # 用 RFC 5987 的 filename*=UTF-8''... 编码，同时给一个 ASCII 兜底名。
        import urllib.parse as _up
        ascii_fname = "".join(c if (32 <= ord(c) < 127) else "_" for c in fname) or "download"
        disp = f'attachment; filename="{ascii_fname}"; filename*=UTF-8\'\'{_up.quote(fname)}'
        handler.send_response(200)
        handler.send_header("Content-Type", mime)
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Content-Disposition", disp)
        handler.end_headers()
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
        pass


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """多线程 HTTP 服务。

    单线程的 HTTPServer 一次只能处理一个连接：CodeScreen 反代会为每个请求
    新建一条连接，大屏页面又是"轮询 + 并发拉数据"，请求一多就会排队、
    被拒（表现为大屏一直"未加载"或反代 502）。这里改成每请求一线程。
    """

    daemon_threads = True

    # 【Windows 致命坑】allow_reuse_address 在 Windows 上语义与 POSIX **相反**。
    #   POSIX : SO_REUSEADDR 只允许绑定 TIME_WAIT 状态的端口（无害）。
    #   Windows: SO_REUSEADDR 允许**抢占另一个进程已占用的端口**（有害）。
    # 后果（实测必现）：
    #   两个 server.py 实例能同时"成功"绑定 7890 →
    #   两个进程各自跑增量刷新（os.replace 同一批 decrypted/*.db）→
    #   SQLite 原生 ACCESS_VIOLATION 段错误，Python 层抓不到任何 traceback，
    #   进程直接消失 → watchdog 拉起 → 再崩 → 无限重启风暴，
    #   表现为「大屏一直正在载入 / 服务时通时断」。
    # 所以只在非 Windows 上开启。
    allow_reuse_address = (os.name != "nt")

    def handle_error(self, request, client_address):
        """请求线程里的异常绝不能让整个服务进程退出。

        默认实现会打印 traceback，但更重要的是：未捕获的
        ConnectionResetError 之类会让 socketserver 认为服务挂了。
        这里统一吞掉 —— 单个请求失败不该拖垮整个大屏。
        """
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionAbortedError,
                            ConnectionResetError, OSError)):
            return
        try:
            import traceback
            traceback.print_exc()
        except Exception:
            pass


class Handler(BaseHTTPRequestHandler):
    # ---- CORS ----
    # 大屏有三种打开方式：
    #   1) http://127.0.0.1:7890/bigscreen.html  → 同源，相对路径即可
    #   2) 反代 /wa/bigscreen.html               → 同源，相对路径即可
    #   3) file:// 直接打开（IDE 预览 / 双击 HTML）→ 相对路径会被解析成
    #      file:///.../api/dash，浏览器直接拒绝并抛 "Failed to fetch"，
    #      这时只能改用绝对地址，而绝对地址属于跨源，需要服务端放行。
    # 统一在 end_headers 里注入，JSON / 静态文件 / 图片都带上。
    def end_headers(self):
        try:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Requested-With")
            # Chrome 的 Private Network Access：file:// 这类不透明来源访问
            # 127.0.0.1 会被强制走一次预检，必须显式允许，否则直接被拦。
            self.send_header("Access-Control-Allow-Private-Network", "true")
        except Exception:
            pass
        BaseHTTPRequestHandler.end_headers(self)

    def do_OPTIONS(self):
        # 预检请求：file:// 入口（origin=null）发起的跨源请求会先问一次
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _api(self):
        parsed = urllib.parse.urlparse(self.path)
        path = self._strip_wa(parsed.path)
        qs = urllib.parse.parse_qs(parsed.query)
        def g(k, default=None):
            return qs.get(k, [default])[0]

        # ---- 路由 ----
        if path == "/api/detect":
            return send_json(self, admod.detect_all(extra=CFG.get("data")))

        if path == "/api/screen":
            # 在独立窗口中打开大屏（web 形态：--app 无地址栏，铺满全屏，
            # 任务栏不显示浏览器图标，全程不弹任何控制台窗口）。
            # 由**服务进程**来拉起 —— 服务在交互式会话且脱离沙箱 Job Object，
            # 浏览器才能长期存活（从命令行拉起会随调用方退出被回收）。
            #
            # 也是首页「📺 大屏」按钮的正路：无论在浏览器标签页还是大屏窗口里点，
            # 都由这里判断「已有窗口就提到前台 / 没有才新开」，不会开成浏览器标签页。
            with _SCREEN_LOCK:
                now = time.time()
                dup = (now - _SCREEN_LAST["at"]) < 3.0
                if not dup:
                    _SCREEN_LAST["at"] = now

            def _open_screen():
                try:
                    import launch_big
                    url = launch_big.add_appwin(launch_big.DEFAULT_URL)
                    # 记到 wa_stdout.log：出问题（比如窗口地址被改坏）时能直接对账
                    print("[大屏] 拉起窗口: %s" % url, flush=True)
                    launch_big.open_window(url)
                except Exception as e:
                    print("[大屏] 拉起失败: %r" % (e,), flush=True)

            if not dup:
                threading.Thread(target=_open_screen, daemon=True).start()
            return send_json(self, {"ok": True, "started": True, "dedup": dup})

        if path == "/api/screen/close":
            # 关掉大屏的 --app 窗口。它没有标题栏、任务栏也没图标，
            # 直连 7890 时前端自己关不掉，只能由服务端按窗口标题发 WM_CLOSE。
            ok = False
            try:
                import launch_big
                ok = launch_big.close_window()
            except Exception:
                ok = False
            return send_json(self, {"ok": ok, "note": "" if ok else
                                    "未找到大屏窗口（或当前系统不支持），可用 Alt+F4 / Cmd+Q 关闭"})

        if path == "/api/auto":
            # 一键闭环：探测本机加密账号 → 用给定密钥或尽力从进程提密钥 → 解密 → 加载
            key = g("key") or CFG.get("key")
            enc = admod.auto_pick_encrypted()
            if not enc:
                dec = admod.auto_pick_our_decrypted(extra=CFG.get("data"))
                if dec:
                    get_db(dec)
                    ensure_conv_cache(dec)
                    return send_json(self, {"ok": True, "dir": dec, "version": get_db().version, "source": "decrypted"})
                return send_json(self, {"ok": False, "reason": "未检测到本机微信数据，请确认微信已登录，或手动指定目录。"})
            out_dir = os.path.join(DECRYPTED_DIR, os.path.basename(enc.rstrip("/\\")))
            if not key:
                # 没给密钥：不再直接甩"需要密钥"。
                # 先按 4.x 正确路径跑 —— 复用 keyring，缺的从微信进程只读补提取，再逐库解密。
                acct = _account_for_msg_dir(enc)
                if acct and start_decrypt_account(acct, enc):
                    return send_json(self, {"ok": True, "started": True, "auto_keys": True,
                                            "dir": os.path.join(DECRYPTED_DIR, acct),
                                            "msg_dir": enc,
                                            "note": "未提供密钥：复用本机密钥环，"
                                                    "缺的从微信进程内存只读提取后逐库解密"})
                dbs = decmod.recursive_find_dbs(enc)
                return send_json(self, {"ok": False, "needs_key": True, "msg_dir": enc,
                    "db_count": len(dbs),
                    "reason": "已找到加密数据库，但需要密钥。请在「① 解密」填入密钥，或用 --key 启动。"})
            if not start_decrypt(enc, out_dir, key):
                return send_json(self, {"ok": False, "busy": True, "error": "已有解密任务在进行中"})
            return send_json(self, {"ok": True, "started": True, "dir": out_dir, "msg_dir": enc})

        if path == "/api/decrypt-progress":
            st = dict(_DECRYPT)
            if st.get("started_at"):
                st["elapsed"] = round(__import__("time").time() - st["started_at"], 1)
            return send_json(self, st)

        if path == "/api/key-extract":
            # 优先走跨平台的逐库提取（keycap → wcdb_ctx：解析 SQLCipher codec 上下文，
            # 一个账号里每个 .db 的 key 都能拿到，并按 salt 记进本机密钥环）。
            # 老的 extract_key_from_process 只做高熵暴力扫描、只在 Windows 可用、只出一个 key，
            # 仅作为兜底保留 —— 它以前是一线入口，这也是"一键提取"在 mac/linux 上必失败的原因。
            enc = admod.auto_pick_encrypted()
            if not enc:
                return send_json(self, {"ok": False, "reason": "未检测到本机微信加密数据"})
            dbs = decmod.recursive_find_dbs(enc)
            acct = _account_for_msg_dir(enc)
            err = None
            res = {}
            if acct:
                try:
                    res = acctmod.ensure_keys(acct)
                except Exception as e:
                    err = "密钥提取模块异常：%s" % e
                else:
                    if not res.get("ok"):
                        err = res.get("error") or "未能提取到密钥"
            else:
                err = "未识别账号目录，无法写入密钥环"
            if res.get("ok"):
                keys = keyring.keys_for("wechat", acct) or {}
                # 只把"真属于某个库（有 salt）"的 key 填进输入框；level_key 是账号级兜底，不往里塞
                db_keys = [v for s, v in sorted(keys.items()) if s]
                first = (db_keys or [None])[0]
                return send_json(self, {"ok": True, "key": first, "count": len(db_keys),
                                        "msg_dir": enc, "account": acct,
                                        "note": "从运行中的微信进程内存只读提取，"
                                                "已按 salt 逐库记入本机密钥环（下次无需再提取）"})
            # 兜底：老的高熵暴力扫描（仅 Windows，最多解一个库）
            key = None
            try:
                key = decmod.extract_key_from_process(dbs[0]) if dbs else None
            except Exception as e:
                err = err or str(e)
            return send_json(self, {"ok": bool(key), "key": key, "msg_dir": enc,
                                    "account": acct, "db_count": len(dbs),
                                    "reason": err or "未能提取到密钥",
                                    "note": "从运行中的微信进程提取；失败则需手动提供密钥"})

        if path == "/api/load":
            d = g("dir")
            key = g("key")
            if not d or not os.path.isdir(d):
                return send_json(self, {"ok": False, "error": "目录不存在"}, 400)
            if key:
                # 加密库：先解密再加载
                out_dir = os.path.join(DECRYPTED_DIR, os.path.basename(d.rstrip("/\\")))
                try:
                    decmod.decrypt_account(d, key, out_dir)
                except Exception as e:
                    return send_json(self, {"ok": False, "error": str(e)}, 400)
                d = out_dir
            get_db(d)
            ensure_conv_cache(d)
            return send_json(self, {"ok": True, "dir": d, "version": get_db().version})

        if path == "/api/sample":
            # 先释放旧连接，否则 Windows 下示例库文件删不掉
            if _DB_CACHE["db"] is not None:
                try:
                    _DB_CACHE["db"].close()
                except Exception:
                    pass
            _DB_CACHE["db"] = None
            _DB_CACHE["path"] = None
            import sample
            sample.gen()
            get_db(SAMPLE_DIR)
            ensure_conv_cache(SAMPLE_DIR)
            return send_json(self, {"ok": True, "dir": SAMPLE_DIR})

        if path == "/api/setdir":
            d = g("dir")
            if d and os.path.isdir(d):
                get_db(d)
                ensure_conv_cache(d)
                return send_json(self, {"ok": True, "dir": d})
            return send_json(self, {"ok": False, "error": "目录不存在"}, 400)

        if path == "/api/status":
            db = get_db()
            cached = get_conv_cache(CURRENT_DIR) if CURRENT_DIR else None
            cur_acct = os.path.basename(CURRENT_DIR.rstrip("/\\")) if CURRENT_DIR else ""
            return send_json(self, {
                "dir": CURRENT_DIR,
                "account": cur_acct,
                "version": db.version,
                "has_msg": bool(db.msg_conns),
                "tables": list(db.aux.keys()),
                "conv_loading": bool(cached and cached.get("loading")),
                "conv_count": len(cached["data"]) if (cached and cached.get("data")) else None,
                "bigscreen": CFG.get("bigscreen"),
                "env": _env_info(),
                "stats_debug": _stats_debug(),
            })

        if path == "/api/accounts":
            # 各账号的「解密状态」总览：
            #   key_known = 密钥已记住 → 以后（含退出重登/重装）都不需要再解密
            #   decrypted = 明文产物已就绪
            rows = acctmod.list_accounts()
            cur_acct = ""
            if CURRENT_DIR:
                cur_acct = os.path.basename(CURRENT_DIR.rstrip("/\\"))
            for r in rows:
                r["current"] = (r["account"] == cur_acct)
                r["encrypted"] = bool(r.get("encrypted_db_count"))
            return send_json(self, {
                "accounts": rows,
                "keyring": keyring.accounts(),
                "current": CURRENT_DIR,
                "current_account": cur_acct,
            })

        if path == "/api/account/use":
            # 切换到指定账号：只读该账号自己的数据目录，绝不混读
            acct = (g("account") or "").strip()
            if not acct:
                return send_json(self, {"ok": False, "error": "缺少 account 参数"}, 400)
            row = None
            for r in acctmod.list_accounts():
                if r["account"] == acct:
                    row = r
                    break
            if row is None:
                return send_json(self, {"ok": False, "error": "未找到该账号"}, 404)
            target = row["decrypted_dir"]
            if not row["decrypted"]:
                return send_json(self, {
                    "ok": False, "error": "该账号尚未解密",
                    "account": acct, "key_known": row["key_known"],
                    "hint": "密钥已记住，直接解密即可；否则需微信在线以提取密钥",
                }, 409)
            get_db(target)
            ensure_conv_cache(target)
            CFG["data"] = target
            CFG["account"] = acct
            save_config()
            return send_json(self, {"ok": True, "account": acct, "dir": target,
                                    "version": get_db().version})

        if path == "/api/account/decrypt":
            # 解密指定账号（密钥自动：仓库 → 进程补提取）
            acct = (g("account") or "").strip()
            if not acct:
                return send_json(self, {"ok": False, "error": "缺少 account 参数"}, 400)
            res = acctmod.decrypt_account(acct)
            if res.get("ok"):
                target = res.get("out_dir")
                get_db(target)
                ensure_conv_cache(target)
                CFG["data"] = target
                CFG["account"] = acct
                save_config()
            return send_json(self, res)

        if path == "/api/account/ensure-keys":
            # 只补密钥（不解密），用于「以后不需要再解密」的确认
            acct = (g("account") or "").strip()
            if not acct:
                return send_json(self, {"ok": False, "error": "缺少 account 参数"}, 400)
            return send_json(self, acctmod.ensure_keys(acct))

        if path == "/api/keys/import":
            n = keyring.import_third_party("wechat")
            return send_json(self, {"ok": True, "imported": n})

        if path == "/api/refresh":
            # 增量刷新当前账号：只重新解密变化的页，秒级完成
            acct = (g("account") or CFG.get("account") or "").strip()
            if not acct:
                return send_json(self, {"ok": False, "error": "缺少 account 参数"}, 400)
            only = None
            raw = g("only")
            if raw:
                only = set(x.strip() for x in raw.split(",") if x.strip())
            # 默认后台异步执行，避免大屏自动刷新阻塞 HTTP 服务
            if g("wait") == "1":
                res = REFRESHER.refresh(acct, only=only)
                if res.get("updated"):
                    target = os.path.join(DECRYPTED_DIR, acct)
                    # 重开连接，让新解出来的页真正生效
                    reopen_db(target)
                    ensure_conv_cache(target)
                    res["reloaded"] = True
                return send_json(self, res)
            res = REFRESHER.refresh_async(acct, only=only)
            return send_json(self, res)

        if path == "/api/refresh/status":
            acct = (g("account") or CFG.get("account") or "").strip()
            last = REFRESHER.last_result or {}
            return send_json(self, {
                "ok": True, "account": acct,
                "running": REFRESHER.running,
                "last_run": REFRESHER.last_run,
                "changed": last.get("changed", 0),
                "elapsed": last.get("elapsed", 0),
                "updated": last.get("updated", False),
                "missing_key": last.get("missing_key", []),
            })

        # ── 多平台（飞书 / 钉钉 / 企业微信）─────────────────────────────
        if path == "/api/stats/rebuild":
            # 强制重建大屏统计缓存（词频/热力图/表情）。
            # 用于改了分词或过滤规则之后，让新结果立刻生效，
            # 不必等 TTL 到期，也不必等增量刷新碰巧触发。
            target = _norm_path(CURRENT_DIR) if CURRENT_DIR else ""
            invalidate_stats(target)
            st = get_stats(target, force=True)
            return send_json(self, {
                "ok": True,
                "dir": target,
                "building": bool(st.get("building")),
                "words": len(st.get("words") or []),
                "emojis": len(st.get("emojis") or []),
            })

        if path == "/api/platforms":
            # 各平台可用性 + 已同步数据量
            # 探测外部 CLI 要十几秒，这里走后台异步：先给缓存，后台刷新
            return send_json(self, {"platforms": _platform_status_safe(force=(g("force") == "1"))})

        if path == "/api/platform/sync":
            # 触发指定平台同步；platform 省略则同步全部已授权平台
            key = g("platform", "")
            days = int(g("days", "7") or 7)
            results = []
            adapters = platmod.all_adapters()
            if key:
                a = platmod.get_adapter(key)
                adapters = [a] if a else []
            for a in adapters:
                if not a:
                    continue
                try:
                    r = a.sync(days=days, limit_convs=int(g("limit", "50") or 50))
                except Exception as e:
                    r = {"ok": False, "platform": getattr(a, "key", "?"),
                         "reason": str(e)[:300]}
                results.append(r)
            return send_json(self, {"results": results})

        if path == "/api/platform/login":
            # 触发某个平台的登录流程，返回扫码链接 / user_code 等信息。
            # 只做登录，不碰消息数据。
            key = g("platform", "")
            a = platmod.get_adapter(key) if key else None
            if not a:
                return send_json(self, {"ok": False, "error": "未知平台"}, 400)
            try:
                info = a.login()
            except Exception as e:
                return send_json(self, {"ok": False, "error": str(e)[:300]})
            # 记住本次生成的二维码路径：/api/platform/qr 只读这里，
            # 不能再调一次 login()（那样会重跑 CLI、生成另一个文件，路径对不上）
            if info and info.get("qrcode"):
                with _QR_LOCK:
                    _QR_CACHE[key] = info["qrcode"]
            return send_json(self, {"ok": True, "platform": key, **(info or {})})

        if path == "/api/platform/qr":
            # 返回登录二维码图片（企微）
            key = g("platform", "")
            if not key:
                return send_json(self, {"error": "未知平台"}, 404)
            with _QR_LOCK:
                p = _QR_CACHE.get(key) or ""
            # 缓存里没有就退回适配器当前记住的路径（有些适配器自己会存）
            if not p:
                a = platmod.get_adapter(key)
                if a:
                    p = getattr(a, "_last_qrcode", "") or ""
            if not p or not os.path.exists(p):
                return send_json(self, {"error": "无二维码，请重新点击授权"}, 404)
            try:
                with open(p, "rb") as f:
                    data = f.read()
            except Exception as e:
                return send_json(self, {"error": str(e)}, 500)
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/platform/conversations":
            # 某个平台（云端）的会话列表
            pk = g("platform", "")
            if not pk:
                return send_json(self, {"conversations": []})
            try:
                convs = cloudstore.conversations(pk, limit=int(g("limit", "300") or 300))
            except Exception as e:
                return send_json(self, {"conversations": [], "error": str(e)})
            return send_json(self, {"platform": pk, "conversations": convs})

        if path == "/api/platform/messages":
            pk = g("platform", "")
            cid = g("conversation", "") or g("chat_id", "")
            if not pk or not cid:
                return send_json(self, {"messages": []})
            try:
                msgs = cloudstore.messages(pk, cid, limit=int(g("limit", "200") or 200))
            except Exception as e:
                return send_json(self, {"messages": [], "error": str(e)})
            return send_json(self, {"platform": pk, "conversation": cid, "messages": msgs})

        if path == "/api/platform/recent":
            pk = g("platform", "")
            try:
                msgs = cloudstore.recent(pk, limit=int(g("limit", "100") or 100))
            except Exception as e:
                return send_json(self, {"messages": [], "error": str(e)})
            return send_json(self, {"platform": pk, "messages": msgs})

        if path == "/api/platform/stats":
            # 云端平台（钉钉/飞书/企微）的统计：活跃热力 + 高频词 + 表情。
            # 微信侧走 /api/dash + 本地 db；云端这边数据在 cloudstore 里，
            # 但词频算法要复用 db.word_emoji_freq（噪声过滤/人名停用词都在那）。
            pk = g("platform", "")
            if not pk:
                return send_json(self, {"error": "缺少 platform"}, 400)
            try:
                heat = cloudstore.time_heatmap(pk)
            except Exception as e:
                heat = {"grid": [[0] * 24 for _ in range(7)], "max": 0,
                        "error": str(e)}
            words = []
            emojis = []
            try:
                corpus = cloudstore.text_corpus(pk, limit=20000)
                if corpus:
                    # db.word_emoji_freq 返回 (words, emojis)，元素是 (词, 次数) 元组；
                    # 前端渲染要的是 {w,c} / {e,c} 对象，这里做一次形状转换。
                    w, e = dbmod.word_emoji_freq(corpus, top=60)
                    words = [{"w": x[0], "c": x[1]} for x in (w or [])
                             if isinstance(x, (list, tuple)) and len(x) >= 2]
                    emojis = [{"e": x[0], "c": x[1]} for x in (e or [])
                              if isinstance(x, (list, tuple)) and len(x) >= 2]
            except Exception:
                pass
            return send_json(self, {
                "platform": pk, "heatmap": heat,
                "words": words, "emojis": emojis,
            })

        if path == "/api/conversations":
            db = get_db()
            cached = get_conv_cache(CURRENT_DIR) if CURRENT_DIR else None
            if cached and cached.get("data") is not None and not cached.get("loading"):
                data = cached["data"]
            elif cached and cached.get("loading"):
                return send_json(self, {"loading": True})
            else:
                ensure_conv_cache(CURRENT_DIR)
                return send_json(self, {"loading": True})
            total = sum(c["count"] for c in data)
            return send_json(self, {"conversations": data, "total_messages": total})

        if path == "/api/messages":
            db = get_db()
            talker = g("talker", "")
            page = int(g("page", "0"))
            # order=desc 取最新的（会话详情默认）；asc 从最早开始往历史翻
            order = g("order", "desc")
            msgs = db.messages(talker, page=page, page_size=80, order=order)
            # raw = 本页命中的原始行数（过滤前）。
            # 前端判断「还有没有更早的消息」必须用 raw：
            # 过滤后可能不足 80 条（如空内容/纯表情），用过滤后的条数
            # 会误判成最后一页 → 「加载更早的消息」按钮永远不出现。
            raw = getattr(db, "_last_msgs_raw", len(msgs))
            # total：会话的消息总数。
            # message_count() 在 4.x 上是 SELECT COUNT(*) 全表扫描，
            # 大群（3 万条）每次翻页都扫一遍会明显拖慢。
            # 会话列表缓存里本来就有每个会话的 count，直接复用；
            # 缓存里没有（会话不在 TOP 列表里）才回退到实算。
            total = _conv_count_from_cache(talker)
            if total is None:
                total = db.message_count(talker)
            return send_json(self, {
                "talker": talker, "page": page, "order": order,
                "count": total, "messages": msgs, "raw": raw,
                "page_size": 80,
                "has_more": (page + 1) * 80 < total,
            })

        if path == "/api/search":
            # 走 FTS 全文索引（毫秒级），彻底避开 6404 张分表 LIKE 卡死服务。
            # 索引未就绪时返回 index_status，前端提示"索引构建中"，并回退到
            # 带 talker 的限定搜索（快路径），绝不再触发全库 LIKE。
            q = g("q", "")
            talker = g("talker", "")
            if not q:
                return send_json(self, {"results": []})
            try:
                page = max(0, int(g("page", 0)))
                page_size = min(200, max(1, int(g("page_size", 200))))
            except (TypeError, ValueError):
                return send_json(self, {"error": "page/page_size 必须是整数"}, 400)
            offset = page * page_size
            st = ftsmod.status()
            if st["status"] == "ready" and CURRENT_DIR:
                res = ftsmod.search(q, limit=page_size + 1, offset=offset,
                                    talker=talker or None, data_dir=CURRENT_DIR)
                return send_json(self, {"results": res[:page_size], "source": "index",
                                        "page": page, "page_size": page_size,
                                        "has_more": len(res) > page_size})
            # 索引未就绪：只在指定会话里搜（快），不碰全库
            if talker:
                db = get_db()
                res = db.search(q, limit=offset + page_size + 1, talker=talker)[offset:]
                return send_json(self, {"results": res[:page_size], "source": "limited",
                                        "page": page, "page_size": page_size,
                                        "has_more": len(res) > page_size})
            return send_json(self, {"results": [], "source": "index-building",
                                    "index_status": st})

        if path == "/api/search/status":
            # 索引构建进度，供前端展示
            st = ftsmod.status()
            if CURRENT_DIR and st["status"] != "building":
                ftsmod.ensure_index(CURRENT_DIR, get_db(), background=True)
            return send_json(self, ftsmod.status())

        if path == "/api/search/rebuild":
            # 手动重建索引（后台线程，不阻塞），force=True 忽略旧索引
            if not CURRENT_DIR:
                return send_json(self, {"error": "无数据目录"}, 400)
            ftsmod.ensure_index(CURRENT_DIR, get_db(), background=True, force=True)
            return send_json(self, {"started": True, "status": ftsmod.status()})

        if path == "/api/digest":
            # 一键整理：关键词搜索 → 按关键词分组 → 生成 Word 文档下载
            q = (g("q") or "").strip()
            if not q:
                return send_json(self, {"error": "缺少关键词 q"}, 400)
            st = ftsmod.status()
            if st["status"] != "ready" or not CURRENT_DIR:
                return send_json(self, {"error": "索引尚未就绪",
                                        "index_status": st}, 503)
            keywords = [k.strip() for k in q.replace("，", ",").split(",") if k.strip()]
            per = min(int(g("per") or 100), 500)
            groups = []
            seen_ids = set()
            total = 0
            for kw in keywords:
                rows = ftsmod.search(kw, limit=per, data_dir=CURRENT_DIR)
                rows = [r for r in rows if (r.get("content"), r.get("talker"), r.get("time")) not in seen_ids]
                for r in rows:
                    seen_ids.add((r.get("content"), r.get("talker"), r.get("time")))
                groups.append((kw, rows))
                total += len(rows)

            import datetime
            def _fmt_time(ts):
                try:
                    ts = int(ts)
                    if ts > 1e11:
                        ts //= 1000
                    if ts <= 0:
                        return "时间未知"
                    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
                except Exception:
                    return "时间未知"

            blocks = [
                {"t": "p", "text": f"生成时间：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"},
                {"t": "p", "text": f"搜索关键词：{q}"},
                {"t": "p", "text": f"命中记录：{total} 条（按关键词分组，同一条只归入首次命中的关键词）"},
                {"t": "hr"}, {"t": "blank"},
            ]
            for kw, rows in groups:
                blocks.append({"t": "h1", "text": f"关键词：{kw}（{len(rows)} 条）"})
                if not rows:
                    blocks.append({"t": "p", "text": "（无匹配记录）"})
                    blocks.append({"t": "blank"})
                    continue
                for r in rows:
                    who = r.get("name") or r.get("talker") or "未知会话"
                    direction = "我" if r.get("isSend") else "对方"
                    label = f"[{_fmt_time(r.get('time'))}] {who} · {direction}："
                    content = str(r.get("content") or "").strip()
                    blocks.append({"t": "item", "label": label, "text": content})
                blocks.append({"t": "blank"})
            blocks.append({"t": "hr"})
            blocks.append({"t": "p", "text": "微信数据分析大屏 · 一键整理 · 署名 云帆-H1088880"})

            try:
                body = docxmod.build_document(f"重要记录整理：{q}", blocks)
            except Exception as e:
                return send_json(self, {"error": f"生成文档失败：{e}"}, 500)
            safe = "".join(c for c in q if c not in '\\/:*?"<>|')[:40].strip() or "记录"
            fname = f"重要记录_{safe}_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.docx"
            return send_file(self, body, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", fname)

        if path == "/api/analyze":
            db = get_db()
            talker = g("talker", "") or None
            heat = db.time_heatmap(talker)
            texts = db.text_corpus(talker)
            words, emojis = dbmod.word_emoji_freq(texts, top=50)
            return send_json(self, {
                "heatmap": heat,
                "words": [{"w": w, "c": c} for w, c in words],
                "emojis": [{"e": e, "c": c} for e, c in emojis],
                "sampled": len(texts),
            })

        if path == "/api/favorites":
            db = get_db()
            return send_json(self, {"favorites": db.favorites(limit=300)})

        if path == "/api/moments":
            db = get_db()
            return send_json(self, {"moments": db.moments(limit=300),
                                    "note": "本地通常仅有你自己发的朋友圈"})

        if path == "/api/annual":
            db = get_db()
            year = int(g("year", "2024"))
            return send_json(self, annualmod.annual_summary(db, year))

        if path == "/api/snapshot":
            # 给大屏用的精简快照（只读统计）
            db = get_db()
            cached = get_conv_cache(CURRENT_DIR) if CURRENT_DIR else None
            convs = (cached["data"] if (cached and cached.get("data")) else db.conversations(limit=50))
            snap = {
                "source": CURRENT_DIR,
                "version": db.version,
                "total_conversations": len(convs),
                "total_messages": sum(c["count"] for c in convs),
                "top_conversations": [{"name": c["name"], "count": c["count"]} for c in convs[:10]],
            }
            return send_json(self, snap)

        if path == "/api/export":
            db = get_db()
            fmt = (g("format") or "json").lower()
            talker = g("talker") or None
            year = int(g("year")) if g("year") else None
            try:
                mime, body, fname = expmod.build(fmt, db, talker=talker, year=year)
            except Exception as e:
                return send_json(self, {"error": str(e)}, 400)
            return send_file(self, body, mime, fname)

        if path == "/api/dash":
            # 大屏专用聚合面板：一次请求拿全部看板数据（只读）
            db = get_db()
            cached = get_conv_cache(CURRENT_DIR) if CURRENT_DIR else None
            convs = (cached["data"] if (cached and cached.get("data")) else [])
            loading = bool(cached and cached.get("loading"))
            stale = bool(cached and cached.get("stale"))
            if (not convs and not loading) or (stale and not loading):
                # 首次访问、或缓存已过期：触发后台统计。
                # 过期重建期间旧数据仍然返回给前端，大屏不会闪空白。
                ensure_conv_cache(CURRENT_DIR)
                loading = True
            # TOP 会话：按「最后一条消息的时间」降序 —— 最近在聊的排最前。
            #
            # 排序依据优先级：
            #   1) last_msg_time —— 消息表 MAX(create_time)，最准
            #   2) last_time     —— session 表 sort_timestamp，兜底
            #   （微信给 session 排序用的字段，微信会因置顶/未读重排，
            #     所以只在拿不到精确时间时才用）
            #
            # 为什么不用消息数排序：消息数是历史总量，排在前面不代表最近有动静，
            # 而这个看板的价值就是「一眼看到刚才谁在说话」。
            # 消息数仍保留在行内（条形长度），作为热度参考。
            def _top_key(c):
                return -(c.get("last_msg_time") or c.get("last_time") or 0)
            top = sorted(convs, key=_top_key)[:12] if convs else []
            # 最近消息：取前几个会话的最新若干条，合并按时间倒序
            recent = _recent_messages_cached(db, top)
            # 热力图/词频走后台缓存，避免每次轮询都扫 230 万条消息
            st = get_stats(CURRENT_DIR)
            cur_acct = os.path.basename(CURRENT_DIR.rstrip("/\\")) if CURRENT_DIR else ""
            return send_json(self, {
                "ok": True,
                "dir": CURRENT_DIR,
                "account": cur_acct,
                "accounts": _accounts_cached(),
                "version": db.version,
                "conv_loading": loading,
                "stats_building": bool(st.get("building")),
                "total_conversations": len(convs),
                "total_messages": sum(c["count"] for c in convs),
                "top_conversations": [{"name": c["name"], "talker": c["talker"],
                                       "count": c["count"],
                                       "last_time": c.get("last_msg_time")
                                       or c.get("last_time") or 0}
                                      for c in top],
                "recent": recent,
                "heatmap": st.get("heatmap") or [],
                "words": st.get("words") or [],
                "emojis": st.get("emojis") or [],
                "bigscreen": CFG.get("bigscreen"),
                "platforms": _platform_status_safe(),
                "auto_refresh": {
                    "running": _AUTO_REFRESH["running"],
                    "interval": _AUTO_REFRESH["interval"],
                    "last": _AUTO_REFRESH["last"],
                    "changed": _AUTO_REFRESH["changed"],
                    "cycles": _AUTO_REFRESH["cycles"],
                    "last_error": _AUTO_REFRESH["last_error"],
                    "err_streak": _AUTO_REFRESH.get("err_streak", 0),
                },
            })

        if path == "/api/config" and self.command == "GET":
            return send_json(self, CFG)

        if path == "/api/config" and self.command == "POST":
            length = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                return send_json(self, {"error": "参数解析失败"}, 400)
            for k in ("auto", "data", "key", "bigscreen", "host"):
                if k in payload:
                    CFG[k] = payload[k]
            save_config()
            return send_json(self, {"ok": True, "cfg": CFG})

        if path == "/api/decrypt" and self.command == "POST":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw)
            except Exception:
                return send_json(self, {"error": "参数解析失败"}, 400)
            msg_dir = payload.get("msg_dir")
            key_hex = payload.get("key")
            if not msg_dir or not key_hex:
                return send_json(self, {"error": "需要提供 msg_dir 与 key"}, 400)
            out_dir = os.path.join(DECRYPTED_DIR, os.path.basename(msg_dir.rstrip("/\\")))
            if not start_decrypt(msg_dir, out_dir, key_hex):
                return send_json(self, {"ok": False, "busy": True, "error": "已有解密任务在进行中"})
            return send_json(self, {"ok": True, "started": True, "out_dir": out_dir})

        return send_json(self, {"error": "unknown api " + path}, 404)

    # CodeScreen 反代用 /wa/* 前缀转发到本服务；直连 7890 时也可能被粘上
    # 这个前缀。这里统一剥掉前缀再路由，保证 /wa/bigscreen.html、
    # /wa/api/xxx、/wa/static/xxx 都能正常工作。
    @staticmethod
    def _strip_wa(path):
        if path == "/wa":
            return "/"
        if path.startswith("/wa/"):
            return path[3:]
        return path

    def do_GET(self):
        # 最外层兜底：客户端断开（浏览器刷新/超时/关页面）会让 socket 写入
        # 抛 ConnectionAbortedError / ConnectionResetError。
        # 这种异常如果冲出 do_GET，会被 socketserver 当成致命错误 →
        # 整个 server.py 进程退出 → watchdog 拉起 → 用户看到服务反复重启。
        # 所以整个处理过程都包在保护里，socket 层面的错误一律吞掉。
        try:
            self._do_GET_inner()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            pass
        except Exception:
            try:
                send_json(self, {"error": "internal error"}, 500)
            except Exception:
                pass
        finally:
            _release_thread_conns()

    def do_POST(self):
        try:
            self._do_POST_inner()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            pass
        except Exception:
            try:
                send_json(self, {"error": "internal error"}, 500)
            except Exception:
                pass
        finally:
            _release_thread_conns()

    def _do_GET_inner(self):
        parsed = urllib.parse.urlparse(self.path)
        path = self._strip_wa(parsed.path)
        if path.startswith("/api/"):
            try:
                return self._api()
            except Exception as e:
                return send_json(self, {"error": str(e)}, 500)
        if path in ("/", "/index.html"):
            return self._serve(os.path.join(BASE, "templates", "index.html"), "text/html; charset=utf-8")
        if path in ("/bigscreen.html", "/bigscreen"):
            return self._serve(os.path.join(BASE, "templates", "bigscreen.html"), "text/html; charset=utf-8")
        if path.startswith("/static/"):
            fpath = os.path.join(BASE, path[1:])
            if os.path.isfile(fpath):
                ext = os.path.splitext(fpath)[1]
                mime = {"css": "text/css", "js": "application/javascript",
                        "png": "image/png", "svg": "image/svg+xml"}.get(ext, "application/octet-stream")
                return self._serve(fpath, mime)
        return send_json(self, {"error": "not found"}, 404)

    def _do_POST_inner(self):
        parsed = urllib.parse.urlparse(self.path)
        path = self._strip_wa(parsed.path)
        if path.startswith("/api/"):
            try:
                return self._api()
            except Exception as e:
                return send_json(self, {"error": str(e)}, 500)
        return send_json(self, {"error": "not found"}, 404)

    def _serve(self, fpath, mime):
        try:
            with open(fpath, "rb") as f:
                body = f.read()
        except Exception:
            return send_json(self, {"error": "file not found"}, 404)
        try:
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            # 看板 HTML/JS 改完必须立刻生效，不能被浏览器缓存住
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
            # 客户端中途断开：正常现象，不能让服务进程崩掉
            pass

    def log_message(self, *args):
        pass


def parse_args(argv):
    port = 7890
    if argv and argv[0].isdigit():
        port = int(argv[0])
        argv = argv[1:]
    for i, a in enumerate(argv):
        if a == "--data" and i + 1 < len(argv):
            CFG["data"] = argv[i + 1]
            CFG["auto"] = False
        elif a == "--key" and i + 1 < len(argv):
            CFG["key"] = argv[i + 1]
        elif a == "--bigscreen" and i + 1 < len(argv):
            CFG["bigscreen"] = argv[i + 1]
        elif a == "--host" and i + 1 < len(argv):
            CFG["host"] = argv[i + 1]
        elif a == "--auto":
            CFG["auto"] = True
        elif a == "--no-auto":
            CFG["auto"] = False
        elif a == "--open":
            CFG["_open"] = True
    return port


def _acquire_single_instance_lock(port):
    """抢占进程级单例锁，确保同一台机器上只有一个 server.py 在跑。

    【为什么端口还不够】
    Windows 上 SO_REUSEADDR 允许两个进程绑同一端口（见 ThreadedHTTPServer 注释），
    所以「能不能绑上 7890」不能当作「是不是唯一实例」的判据。
    这里额外用一把 OS 级文件锁做硬保证：
      · 第一个进程拿到锁 → 正常启动；
      · 第二个进程拿不到   → 打印明确原因并退出（而不是两个进程互相踩文件）。

    锁用 msvcrt.locking(LK_NBLCK) 实现：
      · 进程正常退出或被强杀时，OS 自动释放文件锁，不会留死锁；
      · 锁的是**整个文件**，不能只锁一段，否则两个进程锁不同区间会双双成功。

    返回 True=拿到锁（继续启动）；False=已有实例（应退出）。
    """
    if os.name != "nt":
        return True
    lock_path = os.path.join(BASE, "wa_instance.lock")
    try:
        import msvcrt
    except Exception:
        return True
    fh = None
    try:
        fh = open(lock_path, "a+b")
        fh.seek(0)
        # 确保文件至少有 1 字节，否则 msvcrt.locking 会报错
        if fh.seek(0, os.SEEK_END) == 0:
            fh.write(b"\0")
            fh.flush()
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        # 成功后写上自己的 PID，方便人工排查
        try:
            fh.seek(0)
            fh.write(("pid=%d\n" % os.getpid()).encode("utf-8"))
            fh.flush()
        except Exception:
            pass
        # 保持句柄存活：进程退出时自动释放
        _INSTANCE_LOCK_HANDLE.append(fh)
        return True
    except Exception:
        # 拿不到锁 = 已有实例在跑
        try:
            if fh is not None:
                fh.close()
        except Exception:
            pass
        return False


# 持有锁的文件句柄（模块级，避免被 GC 关闭 → 锁被意外释放）
_INSTANCE_LOCK_HANDLE = []


def _release_single_instance_lock():
    for fh in _INSTANCE_LOCK_HANDLE:
        try:
            if os.name == "nt":
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
        try:
            fh.close()
        except Exception:
            pass
    _INSTANCE_LOCK_HANDLE.clear()


def main():
    # 无窗口兜底：任何 subprocess 调用都不会再弹控制台窗口
    try:
        import env as _env_mod
        _env_mod.patch_subprocess_nowindow()
    except Exception:
        pass
    load_config()
    argv = sys.argv[1:]
    port = parse_args(argv)
    host = CFG.get("host", "127.0.0.1")

    # 【单例守卫】同一台机器只允许一个 server.py。
    # 两个实例会互相 os.replace 同一批解密库 → SQLite 原生段错误 → 进程静默消失。
    if not _acquire_single_instance_lock(port):
        print("[启动失败] 已有另一个 server.py 实例在运行（端口 %s），本次退出。" % port)
        print("           如需强制重启：先结束占用端口的进程，或删除 %s 后重试。"
              % os.path.join(BASE, "wa_instance.lock"))
        _release_single_instance_lock()
        return 3

    # 启动时自动加载数据源（一键闭环）
    loaded = None
    if CFG.get("data") and os.path.isdir(CFG["data"]):
        loaded = CFG["data"]
    elif CFG.get("auto", True):
        # 优先用「本工具自己解密」的目录；没有再走 自动探测 → 提取密钥 → 解密
        rows = acctmod.list_accounts()
        for r in rows:
            if r.get("decrypted"):
                loaded = r["decrypted_dir"]
                CFG["account"] = r["account"]
                print(f"[自动] 加载已解密目录: {loaded}（账号 {r['account']}，"
                      f"密钥已记住，无需再次解密）")
                break
        if not loaded:
            for r in rows:
                if not r.get("has_message"):
                    continue
                print(f"[自动] 账号 {r['account']} 尚未解密，正在解密"
                      f"（{'密钥已记住' if r.get('key_known') else '需从微信进程提取密钥'}）…")
                res = acctmod.decrypt_account(r["account"])
                if res.get("ok"):
                    loaded = res.get("out_dir")
                    CFG["account"] = r["account"]
                    CFG["data"] = loaded
                    save_config()
                    print(f"[自动] 已解密并加载: {loaded}"
                          f"（{res.get('ok_count')} 个库，缓存命中 {res.get('cached')}）")
                else:
                    print(f"[提示] 账号 {r['account']} 解密失败: {res.get('error')}")
                break
    if loaded:
        get_db(loaded)
        ensure_conv_cache(loaded)
        print(f"        当前数据: {loaded}  (微信版本 {get_db().version})")
    else:
        print("[提示] 未自动加载到数据，将使用内置示例。可在「① 解密」加载真实数据。")

    try:
        srv = ThreadedHTTPServer((host, port), Handler)
    except OSError as e:
        # 端口被占用是重启风暴里最常见的一种死法：
        # 新进程绑定失败 → 立刻退出 → watchdog 再拉一个 → 永远起不来。
        # 明确打出来，别让「服务反复重启」变成无头案。
        print("[启动失败] 无法绑定 %s:%s —— %r" % (host, port, e))
        print("           端口被占用：先结束占用该端口的旧进程再启动。")
        _release_single_instance_lock()
        return 4
    print(f"WeChatDataAnalysis 精简版已启动: http://{host}:{port}")

    # 预热平台探测：三个外部 CLI 要十几秒，启动后台先跑一次，
    # 这样大屏第一次请求 /api/platforms 就能直接拿到真实状态，不用干等。
    threading.Thread(target=_platform_status_safe, daemon=True).start()

    # 自动增量刷新：微信开着时源库一直在写新消息，
    # 这里周期性把变化的页解密进快照目录，大屏才能真正"实时"。
    start_auto_refresh(interval=20)
    print("[自动刷新] 已开启：每 20 秒增量解密一次源库，大屏自动同步新消息。")

    # 统计预热：热力图 + 词频要全量扫（90 秒左右），
    # 等到第一次 /api/dash 才算的话，用户会盯着空白面板干等一分半。
    # 这里启动就跑，等用户打开大屏时基本已经算好。
    if loaded:
        threading.Thread(target=get_stats, args=(loaded,), daemon=True).start()
        print("[统计] 正在后台预热热力图/词频（约 1-2 分钟）…")
        # 全文检索索引：一次建好（约 1 分钟），之后搜索/一键整理毫秒级。
        # 数据没变则跳过；变了才重建。构建在后台线程，完全不阻塞服务。
        ftsmod.ensure_index(loaded, get_db(loaded), background=True)
        print("[索引] 正在后台构建全文检索索引（供一键整理用，约 1 分钟）…")
    print("所有分析均为只读，不写库、不发消息、不连微信。")
    if CFG.get("_open"):
        try:
            webbrowser.open(f"http://{host}:{port}/")
        except Exception:
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    # 返回码是给 watchdog 看的信号：
    #   0 = 正常退出；3 = 已有实例；4 = 端口被占用。
    # watchdog 据此判断「主动退出就别再重启」，避免重启风暴。
    sys.exit(main() or 0)
