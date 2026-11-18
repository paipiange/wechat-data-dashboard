# -*- coding: utf-8 -*-
"""
本机微信数据自动探测（只读）。

设计目标：让 wb-analyzer 完全独立工作，不依赖任何第三方微信分析软件。
- 加密数据：扫描本机微信数据根（Documents\\WeChat Files / xwechat_files），
  找到用户自己的加密数据库，配合密钥（命令/UI 提供或由本工具尽力从进程提取）解密。
- 已解密数据：本工具自己解密后写入 decrypted/ 目录；也支持用户手动指定。

所有操作仅读取目录结构与少量表头，不写任何微信/第三方数据。
"""
import os
import sqlite3

import env as _env

BASE = os.path.dirname(os.path.abspath(__file__))

# 本工具自己解密后的数据库存放目录（代码目录只读时自动回落状态目录）
OWN_DECRYPTED_DIR = _env.decrypted_dir()


def _dir_has_dbs(d, ext=".db"):
    try:
        return any(f.lower().endswith(ext) for f in os.listdir(d))
    except Exception:
        return False


def _looks_wechat(d):
    """快速判断一个目录是否像微信数据库目录（含 MSG/Msg_/Contact 等表）。"""
    try:
        dbs = [f for f in os.listdir(d) if f.lower().endswith(".db")]
    except Exception:
        return False
    if not dbs:
        return False
    for f in dbs[:6]:
        try:
            conn = sqlite3.connect(os.path.join(d, f), timeout=3)
            tabs = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            conn.close()
            if any(t.startswith("Msg_") or t in ("ChatName2Id", "MSG", "message",
                                                "Contact", "contact", "favorite",
                                                "fav_db_item") for t in tabs):
                return True
        except Exception:
            continue
    return False


def _count_dbs(d):
    try:
        return sum(1 for f in os.listdir(d) if f.lower().endswith(".db"))
    except Exception:
        return 0


# ---------------- 本机自己的加密微信数据 ----------------
def scan_encrypted_accounts():
    """扫描本机微信数据根，返回加密账号目录（优先含 message*.db 的真实账号）。"""
    import db as _db
    results = []
    for root in _db.candidate_wechat_roots():
        for acc, acc_dir in _db.list_accounts(root):
            for msg_dir in _db.find_msg_dirs(acc_dir):
                dbs = _db.find_encrypted_dbs(msg_dir)
                if not dbs:
                    continue
                names = [os.path.basename(x).lower() for x in dbs]
                has_msg = any(n.startswith("message") or n.startswith("msg") for n in names)
                latest_mtime = max((os.path.getmtime(x) for x in dbs), default=0)
                results.append({
                    "account": acc,
                    "msg_dir": msg_dir,
                    "db_count": len(dbs),
                    "has_message": has_msg,
                    "latest_mtime": latest_mtime,
                    "dbs": [os.path.basename(x) for x in dbs[:20]],
                })
    # 含消息库的账号优先，再选最近正在写入的账号；不能让库更多的旧版 3.x 数据
    # 挤到当前 4.x 账号前面，否则当前微信进程中的密钥不可能匹配旧库。
    results.sort(key=lambda r: (not r["has_message"], -r["latest_mtime"],
                                -r["db_count"]))
    return results


def auto_pick_encrypted():
    """返回第一个检测到的本机加密账号 msg_dir（优先含 message*.db 的账号）。"""
    accs = scan_encrypted_accounts()
    for a in accs:
        if a.get("has_message"):
            return a["msg_dir"]
    return accs[0]["msg_dir"] if accs else None


# ---------------- 本工具已解密的目录 ----------------
def scan_own_decrypted(extra=None):
    """扫描本工具可直载的已解密目录。优先 extra（用户显式指定），其次本工具 decrypted/。"""
    roots = []
    if extra:
        roots.append(extra)
    roots.append(OWN_DECRYPTED_DIR)
    found = []
    for root in roots:
        rp = os.path.normpath(root)
        if not os.path.isdir(rp):
            continue
        if _looks_wechat(rp):
            found.append({"dir": rp, "kind": "decrypted", "db_count": _count_dbs(rp)})
            continue
        # 扫描两层子目录（如 decrypted/<account>/）
        try:
            for name in os.listdir(rp):
                sub = os.path.join(rp, name)
                if os.path.isdir(sub) and _looks_wechat(sub):
                    found.append({"dir": sub, "kind": "decrypted", "db_count": _count_dbs(sub)})
        except Exception:
            pass
    seen = set()
    uniq = []
    for f in found:
        if f["dir"] in seen:
            continue
        seen.add(f["dir"])
        uniq.append(f)
    uniq.sort(key=lambda x: -x["db_count"])
    return uniq


def auto_pick_our_decrypted(extra=None):
    dec = scan_own_decrypted(extra=extra)
    return dec[0]["dir"] if dec else None


# ---------------- 综合探测（供前端展示） ----------------
def detect_all(extra=None):
    """
    返回 {encrypted:[本机自己的加密账号], decrypted:[本工具已解密目录]}。
    注意：不再自动包含任何第三方软件的输出目录；第三方数据需用户手动用 /api/load 指定。
    """
    return {
        "encrypted": scan_encrypted_accounts(),
        "decrypted": scan_own_decrypted(extra=extra),
    }
