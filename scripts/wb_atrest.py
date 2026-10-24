#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WorkBuddy 登录态读取器（兼容 5.5.x 明文 / 5.6.2+ AtRestEncryption 加密）。

背景
----
WorkBuddy 5.6.2 起把 AtRestEncryption 的 buildMode 从 disabled 改为 required，
`workbuddy-desktop.info` 里的 `auth.accessToken` / `auth.refreshToken` 不再是明文 JWT，
而是 AES-256-GCM 信封：

    {"$wbEncrypted": 1, "envelope": "<base64>"}
    envelope = {suite:1, keyId:"<16hex>", nonce:"<b64,12B>", authTag:"<b64,16B>", ciphertext:"<b64>"}

旧脚本直接把字段当明文 JWT 读 → 鉴权失败。本模块复刻客户端
`packages/at-rest-crypto` 的读端算法，把 token 还原出来。

算法（与客户端 byte-for-byte 一致）
----------------------------------
    key    = SHA256(atRestSecretKey 字符串的 UTF-8 字节)          -> 32B
    keyId  = SHA256(key).hexdigest()[:16]
    AAD    = buildAuthenticatedContextAad(keyId, suite=1, {framing:"field"}, "sym-v1")
    明文   = AES-256-GCM-Decrypt(key, nonce, ciphertext, AAD, authTag)

`atRestSecretKey` 的定位顺序（全部只读、绝不写盘、绝不打印）
----------------------------------------------------------
    1. 环境变量 WORKBUDDY_ATREST_KEY          —— 44 字符规范 base64（32 字节）
    2. 环境变量 WORKBUDDY_ATREST_KEY_FILE     —— 指向密钥文件（明文或 DPAPI 密文）
    3. 登录态 Data 目录下的 DPAPI blob 扫描    —— 兼容历史上曾落盘的设备
    4. 运行中 WorkBuddy 客户端进程内存扫描      —— 5.6.2 实测唯一可靠途径：
       原生模块 electron.workbuddyStorage.loggerGet() 在运行时提供密钥，不落盘。

因此第 4 条要求：执行时刻客户端已启动且已登录，且脚本与客户端在同一 Windows 用户下。

安全约定
--------
- 密钥与 token 只在内存中参与校验/解密，不写入任何文件、不打印任何片段。
- 仅读取本机登录态文件（只读打开），绝不修改客户端数据。
- 所有失败都抛出带可操作提示的 RuntimeError，绝不静默返回空 token。

依赖
----
解密路径需要 AES-256-GCM，采用**三级降级**：cryptography → pycryptodome → 纯 Python
兜底（见 `_aes_gcm`）。因此本模块**零硬依赖**：即使某个第三方库缺失或损坏（真实案例：
老版本 cryptography 内部 `from six.moves import range`，而 six<1.16 在 Python 3.12+
上已无法提供 `six.moves`，一 import 就炸），本模块依然能正常解密。
云端走明文 JWT，根本不经过这里。

用法
----
    import wb_atrest
    token, domain, auth_path = wb_atrest.load_token_best()
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time

# --------------------------------------------------------------------------- #
# 登录态文件候选路径
# --------------------------------------------------------------------------- #
AUTH_FILE_NAME = "workbuddy-desktop.info"


def auth_candidates():
    """按操作系统返回 WorkBuddy 登录态文件候选路径，依次探测。"""
    home = os.path.expanduser("~")
    cands = []
    if sys.platform.startswith("win"):
        for env in ("LOCALAPPDATA", "APPDATA"):
            base = os.environ.get(env, "")
            if base:
                cands.append(os.path.join(
                    base, "CodeBuddyExtension", "Data", "Public",
                    "auth", AUTH_FILE_NAME))
    elif sys.platform == "darwin":
        cands.append(os.path.join(
            home, "Library", "Application Support", "CodeBuddyExtension",
            "Data", "Public", "auth", AUTH_FILE_NAME))
    else:  # linux / 其他类 Unix
        cands.append(os.path.join(
            home, ".config", "CodeBuddyExtension", "Data", "Public",
            "auth", AUTH_FILE_NAME))
    # 兜底：便携版 / 未知布局（与 ~/.workbuddy 同根）
    cands.append(os.path.join(home, ".workbuddy", "auth", AUTH_FILE_NAME))
    return [p for p in cands if p]


def find_auth_file():
    for p in auth_candidates():
        if os.path.isfile(p):
            return p
    return None


# --------------------------------------------------------------------------- #
# 常量（与客户端 at-rest-crypto/dist 的 key-normalize / field.mjs 完全一致）
# --------------------------------------------------------------------------- #
AAD_DOMAIN = b"WB-AAD\x00"
ENVELOPE_SUITE = 1


# --------------------------------------------------------------------------- #
# 密钥派生 / AAD 构造
# --------------------------------------------------------------------------- #
def b64_canonical_decode(value, field):
    """复刻 decodeCanonicalBase64：标准 base64，且与重编码一致才算合法。"""
    if not isinstance(value, str):
        raise ValueError("%s 不是字符串" % field)
    decoded = base64.b64decode(value)
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("%s 不是规范 base64" % field)
    return decoded


def derive_at_rest_key(at_rest_secret_key):
    """复刻 normalizeAtRestKeyPayload。

    返回 (key_32bytes, key_id_16hex)：
      key    = SHA256(secret 字符串 UTF-8)
      key_id = SHA256(key)[:16]
    """
    if not isinstance(at_rest_secret_key, str) or len(at_rest_secret_key) != 44:
        raise ValueError("atRestSecretKey 必须是 44 字符规范 base64（32 字节）")
    raw = b64_canonical_decode(at_rest_secret_key, "atRestSecretKey")
    if len(raw) != 32:
        raise ValueError("atRestSecretKey 解码后必须是 32 字节")
    key = hashlib.sha256(at_rest_secret_key.encode("utf-8")).digest()
    return key, hashlib.sha256(key).hexdigest()[:16]


def build_field_aad(key_id):
    """复刻 buildAuthenticatedContextAad(keyId, 1, {framing:'field'}, 'sym-v1')。"""
    def u32(v):
        return v.to_bytes(4, "big")

    def length_prefixed(s):
        b = s.encode("utf-8")
        return u32(len(b)) + b

    return b"".join([
        AAD_DOMAIN,
        bytes([1]),
        length_prefixed("WBEV1"),
        length_prefixed("sym-v1"),
        u32(ENVELOPE_SUITE),
        length_prefixed(key_id),
        bytes([2]),                                      # framing="field"
        bytes([0]),                                    # sequence 缺失
        bytes([0]),                                    # final 缺失
    ])


# --------------------------------------------------------------------------- #
# 信封解析（复刻 parseSupportedEnvelope，仅 suite=1）
# --------------------------------------------------------------------------- #
def parse_suite1_envelope(envelope_bytes):
    try:
        env = json.loads(envelope_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError("信封不是合法 JSON: %s" % e)
    if not isinstance(env, dict):
        raise ValueError("信封必须是对象")
    if env.get("suite") != ENVELOPE_SUITE:
        raise ValueError("只支持 suite=1，实际 %r" % env.get("suite"))
    key_id = env.get("keyId")
    nonce = b64_canonical_decode(env.get("nonce"), "nonce")
    auth_tag = b64_canonical_decode(env.get("authTag"), "authTag")
    ct = env.get("ciphertext")
    ciphertext = b"" if (isinstance(ct, str) and ct == "") else b64_canonical_decode(ct, "ciphertext")
    if len(nonce) != 12 or len(auth_tag) != 16:
        raise ValueError("nonce(12)/authTag(16) 长度错误")
    return key_id, nonce, ciphertext, auth_tag


# --------------------------------------------------------------------------- #
# AES-256-GCM 后端：三级降级，绝不因「第三方库装了但坏了」而整体失败
# --------------------------------------------------------------------------- #
# 为什么不能裸 import（真实故障复盘）
# ------------------------------------------------------------------
# 「装了 cryptography」不等于「import 得动」。用户环境 C:\Program Files\python 上的
# cryptography 是 3.x 之前的老版本，模块内部 `from six.moves import range`；而同环境
# six==1.15.0——six 直到 1.16.0 才适配 Python 3.12+ 的导入协议，于是 `six.moves`
# 这个虚拟子模块根本不存在：
#     ModuleNotFoundError: No module named 'six.moves'
# 裸 import 会让这种「依赖损坏」一路炸到用户面前，而脚本其实完全有能力自己算。
#
# 因此改为三级降级，每一级都包在 try 里，失败就记下原因继续往下：
#   1) cryptography  —— OpenSSL 后端，最快，首选
#   2) pycryptodome  —— C 实现，与 cryptography 无共同依赖（不吃 six）
#   3) pure          —— 纯 Python 兜底，零依赖，任何 Python 3 都能跑
# 只有三级全废才报错，且错误里带齐每一级的失败原因（便于定位环境问题）。
#
# 且必须区分两类失败，否则会破坏 GCM 的语义：
#   · 后端不可用（缺库 / 坏库）     -> 静默降级
#   · 认证失败（密文/tag/AAD 不符）  -> 这是**明确结论**，直接抛出、绝不降级，
#     免得三个后端各跑一遍，把真正的失败原因淹进噪声里。
# --------------------------------------------------------------------------- #
BACKEND_ORDER = ("cryptography", "pycryptodome", "pure")

_AEAD_BACKEND = None        # 进程内缓存：已确认可用的后端名（None = 还没调用过）
_BACKEND_ERRORS = {}        # 后端名 -> 最后一次失败原因（诊断用，不含任何密钥）


class GcmAuthError(ValueError):
    """AES-GCM 认证失败（密文 / authTag / AAD 被篡改，或密钥不对）。"""


def _sub_word(t):
    """对一个 32 位字做 SubWord（逐字节查 S-box）。"""
    return ((AES_STD_SBOX[(t >> 24) & 0xFF] << 24)
            | (AES_STD_SBOX[(t >> 16) & 0xFF] << 16)
            | (AES_STD_SBOX[(t >> 8) & 0xFF] << 8)
            | AES_STD_SBOX[t & 0xFF])


def _load_backend(name):
    """取出统一签名的后端函数：run(decrypt, key, nonce, data, aad, auth_tag)。

    缺库 / 坏库（例如上面说的 six.moves）会在这一步抛异常，由 `_aes_gcm` 决定降级。
    """
    if name == "cryptography":
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        def run(decrypt, key, nonce, data, aad, auth_tag):
            if decrypt:
                try:
                    return AESGCM(key).decrypt(nonce, data + auth_tag, aad)
                except InvalidTag as e:
                    raise GcmAuthError("GCM 认证标签校验失败：%s" % e)
            out = AESGCM(key).encrypt(nonce, data, aad)
            return out[:-16], out[-16:]

        return run

    if name == "pycryptodome":
        from Crypto.Cipher import AES  # type: ignore

        def run(decrypt, key, nonce, data, aad, auth_tag):
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            if decrypt:
                try:
                    return cipher.decrypt_and_verify(data, auth_tag)
                except ValueError as e:
                    raise GcmAuthError("GCM 认证标签校验失败：%s" % e)
            return cipher.encrypt_and_digest(data)

        return run

    if name == "pure":
        return _aes_gcm_pure

    raise ValueError("未知 AES 后端：%r" % name)


def _aes_gcm(decrypt, key, nonce, data, aad, auth_tag=None):
    """AES-256-GCM 统一入口：按 BACKEND_ORDER 降级，返回明文或 (密文, tag)。"""
    global _AEAD_BACKEND
    order = list(BACKEND_ORDER)
    if _AEAD_BACKEND in order:                     # 上次成功的后端优先重试
        order.remove(_AEAD_BACKEND)
        order.insert(0, _AEAD_BACKEND)
    problems = []
    for name in order:
        try:
            run = _load_backend(name)
        except Exception as e:                     # 缺库 / 坏库（six.moves 那类）
            _BACKEND_ERRORS[name] = "%s: %s" % (type(e).__name__, e)
            if _AEAD_BACKEND == name:
                _AEAD_BACKEND = None
            problems.append("%s 不可用（%s: %s）" % (name, type(e).__name__, e))
            continue
        try:
            out = run(decrypt, key, nonce, data, aad, auth_tag)
        except GcmAuthError:
            _AEAD_BACKEND = name                   # 后端是好的：结论就是「认证失败」
            raise
        except Exception as e:                     # 能 import 但跑不通（旧版 API 等）
            _BACKEND_ERRORS[name] = "%s: %s" % (type(e).__name__, e)
            if _AEAD_BACKEND == name:
                _AEAD_BACKEND = None
            problems.append("%s 调用失败（%s: %s）" % (name, type(e).__name__, e))
            continue
        _AEAD_BACKEND = name
        _BACKEND_ERRORS.pop(name, None)
        return out
    raise RuntimeError(
        "AES-256-GCM %s失败：所有后端均不可用\n  - %s"
        % ("解密" if decrypt else "加密", "\n  - ".join(problems)))


def aes_gcm_decrypt(key, nonce, ciphertext, aad, auth_tag):
    """AES-256-GCM 解密，返回明文 bytes；认证失败抛 GcmAuthError。"""
    return _aes_gcm(True, key, nonce, ciphertext, aad, auth_tag)


def aes_gcm_encrypt(key, nonce, plaintext, aad):
    """AES-256-GCM 加密，返回 (ciphertext, auth_tag)；供自测 roundtrip 使用。"""
    return _aes_gcm(False, key, nonce, plaintext, aad)


def aes_backend_name():
    """当前进程实际使用的后端名（还没调用过任何加解密时为 None）。"""
    return _AEAD_BACKEND


def aes_backend_report():
    """各后端可用性报告（诊断/自测用，不含密钥与 token 片段）。"""
    report = {}
    for name in BACKEND_ORDER:
        if name == "pure":
            report[name] = "ok（纯 Python，零依赖）"
            continue
        try:
            _load_backend(name)
            report[name] = "ok"
        except Exception as e:
            report[name] = "%s: %s" % (type(e).__name__, e)
    if _AEAD_BACKEND:
        report[_AEAD_BACKEND] = "%s ← 正在使用" % report.get(_AEAD_BACKEND, "ok")
    return report


# --------------------------------------------------------------------------- #
# 纯 Python AES-256-GCM 兜底（零依赖，约 1 页；仅当上面两级都不可用时启用）
# --------------------------------------------------------------------------- #
# 只实现 GCM 需要的「分组加密 + GHASH」，不支持其它模式 / 其它密钥长度。
# 正确性由 `self_test()` 的**交叉对拍**兜住：同一 key/nonce 下，三个后端算出的
# 密文与 authTag 必须逐字节一致——这就消掉了「两套实现结果不一致」的风险。
def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox():
    """由 GF(2^8) 求逆 + 仿射变换现场推导 S-box。

    手抄 256 字节常量表，抄错一个字节就是灾难性且极难察觉的 bug；这里用生成式
    写法，再用若干公开的 S-box 锚点校验，写歪了会在 import 时立刻炸掉。
    """
    p = q = 1
    sbox = [0] * 256
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF   # p *= 3
        q ^= q << 1                                             # q /= 3（= ×0xf6）
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        xformed = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = (xformed ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


AES_STD_SBOX = _build_sbox()

# 已知锚点（AES 标准 S-box 的公开取值，[0]=0x63、[1]=0x7C、[0x53]=0xED、[0xFF]=0x16）
if (AES_STD_SBOX[0x00], AES_STD_SBOX[0x01],
        AES_STD_SBOX[0x53], AES_STD_SBOX[0xFF]) != (0x63, 0x7C, 0xED, 0x16):
    raise RuntimeError("AES S-box 生成异常（内部实现缺陷，请反馈）")

_AES_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
# GCM 的归约多项式 x^128+x^7+x^2+x+1，最高字节 0xE1。
# 用移位写法而不是手敲 32 个十六进制位——手敲极容易多写/少写一个 0（已踩过）。
_GF128_R = 0xE1 << 120
if _GF128_R.bit_length() != 128:                      # 防御：常量自检
    raise RuntimeError("GF(2^128) 归约常量位宽错误（内部实现缺陷，请反馈）")


def _gmul(a, b):
    """GF(2^8) 乘法（模 x^8+x^4+x^3+x+1）。"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return p


def _expand_key_256(key):
    """AES-256 密钥扩展：32 字节密钥 -> 60 个轮密钥字。"""
    if len(key) != 32:
        raise ValueError("纯 Python 后端只实现 AES-256（需 32 字节密钥）")
    nk, nr = 8, 14
    w = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = w[i - 1]
        if i % nk == 0:
            t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF       # RotWord
            t = _sub_word(t) ^ (_AES_RCON[i // nk - 1] << 24)
        elif i % nk == 4:
            t = _sub_word(t)
        w.append(w[i - nk] ^ t)
    return w


def _mix_columns(s):
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out[4 * c + 0] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        out[4 * c + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        out[4 * c + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        out[4 * c + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
    return out


def _shift_rows(s):
    return [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]


def _encrypt_block(w, block):
    """AES-256 单块加密（16 字节）；GCM 只需要加密方向。"""
    s = [block[i] ^ ((w[i // 4] >> (24 - 8 * (i % 4))) & 0xFF) for i in range(16)]
    for rnd in range(1, 14):
        s = _mix_columns([AES_STD_SBOX[b] for b in _shift_rows(s)])
        s = [s[i] ^ ((w[4 * rnd + i // 4] >> (24 - 8 * (i % 4))) & 0xFF)
             for i in range(16)]
    s = [AES_STD_SBOX[b] for b in _shift_rows(s)]
    return bytes(s[i] ^ ((w[56 + i // 4] >> (24 - 8 * (i % 4))) & 0xFF)
                 for i in range(16))


def _gf128_mul(x_bytes, y_bytes):
    """GF(2^128) 乘法（GCM 约定：位序反转，模 x^128+x^7+x^2+x+1）。"""
    x = int.from_bytes(x_bytes, "big")
    v = int.from_bytes(y_bytes, "big")
    z = 0
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (_GF128_R if v & 1 else 0)
    return z.to_bytes(16, "big")


def _ghash(h_bytes, aad, ciphertext):
    """GHASH_H(AAD, C)：两段数据各自补零到 16 字节边界，末尾附 64 位长度块。"""
    def pad16(b):
        return b + b"\x00" * (-len(b) % 16)

    data = (pad16(aad) + pad16(ciphertext)
            + (len(aad) * 8).to_bytes(8, "big")
            + (len(ciphertext) * 8).to_bytes(8, "big"))
    y = bytes(16)
    for off in range(0, len(data), 16):
        y = _gf128_mul(bytes(a ^ b for a, b in zip(y, data[off:off + 16])), h_bytes)
    return y


def _inc32(block):
    ctr = (int.from_bytes(block[12:], "big") + 1) & 0xFFFFFFFF
    return block[:12] + ctr.to_bytes(4, "big")


def _gctr(w, icb, data):
    out = bytearray()
    cb = icb
    for off in range(0, len(data), 16):
        ks = _encrypt_block(w, cb)
        out += bytes(a ^ b for a, b in zip(ks, data[off:off + 16]))
        cb = _inc32(cb)
    return bytes(out)


def _aes_gcm_pure(decrypt, key, nonce, data, aad, auth_tag):
    """纯 Python AES-256-GCM（与 `_aes_gcm` 统一签名，不直接对外暴露）。"""
    if len(nonce) != 12:
        raise ValueError("纯 Python 后端只支持 12 字节 nonce（GCM 标准形态）")
    w = _expand_key_256(key)
    h = _encrypt_block(w, bytes(16))
    j0 = nonce + b"\x00\x00\x00\x01"
    if decrypt:
        plaintext = _gctr(w, _inc32(j0), data)
        expected = bytes(a ^ b for a, b in
                         zip(_encrypt_block(w, j0), _ghash(h, aad, data)))
        if not auth_tag or not hmac.compare_digest(expected, auth_tag):
            raise GcmAuthError("GCM 认证标签校验失败（密文/authTag/AAD 不匹配）")
        return plaintext
    ciphertext = _gctr(w, _inc32(j0), data)
    tag = bytes(a ^ b for a, b in
                zip(_encrypt_block(w, j0), _ghash(h, aad, ciphertext)))
    return ciphertext, tag


# --------------------------------------------------------------------------- #
# DPAPI（Windows）：解开历史上曾落盘的密钥 blob
# --------------------------------------------------------------------------- #
def dpapi_unprotect(blob):
    """调用 crypt32.CryptUnprotectData（当前用户）解开 DPAPI blob，返回原文 bytes。"""
    if not sys.platform.startswith("win"):
        raise OSError("DPAPI 仅在 Windows 可用")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_byte))]

    crypt32 = ctypes.windll.crypt32  # type: ignore
    blob_buf = ctypes.create_string_buffer(blob, len(blob))
    in_blob = DATA_BLOB(len(blob), ctypes.cast(blob_buf, ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0,
                                      ctypes.byref(out_blob)):
        raise OSError("CryptUnprotectData 失败（可能不是当前用户/本机加密的 blob）")
    try:
        ptr = ctypes.cast(out_blob.pbData, ctypes.POINTER(ctypes.c_byte * out_blob.cbData))
        return bytes(ptr.contents[:out_blob.cbData])
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)  # type: ignore


# --------------------------------------------------------------------------- #
# 运行中客户端进程内存扫描（5.6.2 密钥不落盘时的唯一途径）
# --------------------------------------------------------------------------- #
# 定向锚点：密钥载荷字段名（最贴近密钥本体）。信封 keyId 同样是锚点，但它随字段变化，
# 由 discover_key_from_memory() 在运行时拼进锚点列表，不写死在这里。
ANCHOR_NAMES = (b"atRestSecretKey",)
MAX_MEMORY_CANDIDATES = 200000
ANCHOR_HIT_LIMIT = 4096           # 单个锚点在一段内存里的命中上限（噪声保护）
KEY_WINDOW_BYTES = 4096

# 44 字符 canonical base64 的候选模式，按编码选字节层模式：
# UTF-16LE 的字符间夹着 NUL，解码成 str 后 NUL 就没了、只剩连续 44 个普通字符，
# 与定宽模式对不上；只能反过来用带 NUL 的模式匹配**字节流**，才能表达「隔一字节一字符」。
_B64_PATTERNS = {
    "ascii": rb"[A-Za-z0-9+/]{43}=",
    "utf-16-le": rb"(?:[A-Za-z0-9+/]\x00){43}=\x00",
}


def list_client_pids():
    """枚举运行中的 WorkBuddy 客户端进程 PID（仅 Windows）。"""
    if not sys.platform.startswith("win"):
        return []
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t),   # ULONG_PTR
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", wintypes.WCHAR * 260)]

    names = {"workbuddy.exe"}
    extra = os.environ.get("WORKBUDDY_PROCESS_NAMES", "")
    if extra:
        names |= {n.strip().lower() for n in extra.split(",") if n.strip()}

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    snap = kernel32.CreateToolhelp32Snapshot(0x2, 0)   # TH32CS_SNAPPROCESS
    if not snap or snap == ctypes.c_size_t(-1).value:
        return []
    pids = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile and entry.szExeFile.lower() in names:
                pids.append(int(entry.th32ProcessID))
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return pids


def iter_readable_regions(kernel32, handle, max_total_bytes=3 * 1024 * 1024 * 1024):
    """逐段产出目标进程「已提交且可读」的内存块。只读，跳过守护页。"""
    import ctypes
    from ctypes import wintypes

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("PartitionId", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                    ("PartitionId2", wintypes.DWORD)]

    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                                        ctypes.c_size_t]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_size_t,
                                           ctypes.POINTER(ctypes.c_size_t)]
    MEM_COMMIT = 0x1000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100
    CHUNK = 8 * 1024 * 1024
    total = 0
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while total < max_total_bytes:
        if not kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                       ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        base = mbi.BaseAddress or addr
        region_size = mbi.RegionSize or 0
        if region_size <= 0:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect != PAGE_NOACCESS and not (mbi.Protect & PAGE_GUARD):
            read = 0
            while read < region_size and total < max_total_bytes:
                n = min(CHUNK, region_size - read)
                buf = ctypes.create_string_buffer(n)
                got = ctypes.c_size_t(0)
                if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(base + read),
                                              buf, n, ctypes.byref(got)) and got.value:
                    data = buf.raw[:got.value]
                    total += len(data)
                    yield data
                    read += got.value
                else:
                    read = region_size   # 该子段不可读，跳到区域尾
        nxt = base + region_size
        if nxt <= addr:
            break
        addr = nxt


def key_candidate_matches(candidate_text, target_key_id):
    """校验 44 字符 base64 候选是否派生出目标 keyId（严格校验，杜绝误报）。"""
    try:
        return derive_at_rest_key(candidate_text)[1] == target_key_id
    except Exception:
        return False


def _iter_b64_candidates(data, encoding):
    """按 encoding 逐段产出 44 字符 base64 候选（模式说明见 `_B64_PATTERNS`）。"""
    try:
        pattern = _B64_PATTERNS[encoding]
    except KeyError:
        raise ValueError("未知编码 %r（仅支持 %s）"
                         % (encoding, " / ".join(sorted(_B64_PATTERNS))))
    for m in re.finditer(pattern, data):
        yield m.group(0).decode(encoding, "ignore")


def _extract_key_near_hits(data, hit_indexes, pattern_len, target_key_id, encoding="ascii"):
    """在命中点 ±4KB 窗口内提取 base64 候选并校验。"""
    for h in hit_indexes:
        lo = max(0, h - KEY_WINDOW_BYTES)
        hi = min(len(data), h + pattern_len + KEY_WINDOW_BYTES)
        for cand in _iter_b64_candidates(data[lo:hi], encoding):
            if key_candidate_matches(cand, target_key_id):
                return cand
    return None


def discover_key_from_memory(target_key_id):
    """扫描运行中客户端进程内存，定位 atRestSecretKey（仅 Windows）。

    策略（两遍，第二遍不被第一遍的命中与否门控——这是关键，否则 keyId 噪声会
    让整轮扫描被误判为「已尝试但取不到」而提前放弃）：
      Pass 1（定向）：搜索 `atRestSecretKey` 字段名与信封 keyId 的 ASCII / UTF-16LE 串，
                      在命中点 ±4KB 窗口内提取 44 字符 canonical base64 候选并严格校验；
      Pass 2（兜底）：对全部可读内存做 base64 候选（ASCII / UTF-16LE）扫描逐个校验。

    找到返回密钥字符串；找不到或任何异常返回 None（上层给出可操作提示）。
    """
    if not sys.platform.startswith("win"):
        return None
    try:
        import ctypes

        pids = list_client_pids()
        if not pids:
            return None
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        # (bytes, 编码)：锚点同时按 ASCII / UTF-16LE 两种编码出现
        anchors = []
        for needle in (target_key_id.encode("ascii"),) + ANCHOR_NAMES:
            anchors.append((needle, "ascii"))
            anchors.append((needle.decode("ascii").encode("utf-16-le"), "utf-16-le"))
        seen = set()
        for pid in pids:
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not handle:
                continue
            try:
                for data in iter_readable_regions(kernel32, handle):
                    # Pass 1：定向锚点邻域
                    for pat, encoding in anchors:
                        idxs = []
                        start = 0
                        while True:
                            i = data.find(pat, start)
                            if i < 0:
                                break
                            idxs.append(i)
                            if len(idxs) > ANCHOR_HIT_LIMIT:   # 噪声上限
                                break
                            start = i + 1
                        if idxs:
                            key = _extract_key_near_hits(data, idxs, len(pat),
                                                         target_key_id, encoding)
                            if key:
                                return key
                    # Pass 2：全段候选兜底（不被 Pass 1 命中与否门控）
                    for encoding in ("ascii", "utf-16-le"):
                        for cand in _iter_b64_candidates(data, encoding):
                            if cand in seen:
                                continue
                            seen.add(cand)
                            if len(seen) > MAX_MEMORY_CANDIDATES:
                                return None
                            if key_candidate_matches(cand, target_key_id):
                                return cand
            finally:
                kernel32.CloseHandle(ctypes.c_void_p(handle))
        return None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# 密钥定位（多级降级）与字段解密
# --------------------------------------------------------------------------- #
SCAN_ROOTS_SKIP_DIRS = {
    "cache", "code cache", "gpucache", "file-tree", "extensions", "blob_storage",
    "indexeddb", "service worker", "logs", "crashpad", "swreporter", "network",
    "application cache", "shadercache", "webrtc", "videodecodestats",
}
DPAPI_MAGIC = b"\x01\x00\x00\x00\xd0\x8c\x9d\x0a"


def _scan_roots():
    roots = []
    home = os.path.expanduser("~")
    for env in ("LOCALAPPDATA", "APPDATA"):
        base = os.environ.get(env, "")
        if base:
            roots.append(os.path.join(base, "CodeBuddyExtension", "Data"))
            roots.append(os.path.join(base, "WorkBuddyExtension", "Data"))
    roots.append(os.path.join(home, ".config", "CodeBuddyExtension", "Data"))
    roots.append(os.path.join(home, ".workbuddy"))
    seen, out = set(), []
    for r in roots:
        if r and r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _iter_candidate_files(root, limit=4000):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in SCAN_ROOTS_SKIP_DIRS]
        for fn in filenames:
            if count >= limit:
                return
            p = os.path.join(dirpath, fn)
            try:
                yield p, os.path.getsize(p)
            except OSError:
                continue
            count += 1


def _candidate_to_key(blob_or_text, target_key_id):
    """把一段字节（DPAPI 密文或明文）变成 atRestSecretKey 并校验 keyId。"""
    text = None
    try:
        text = dpapi_unprotect(blob_or_text).decode("utf-8", "replace").strip()
    except Exception:
        try:
            text = blob_or_text.decode("utf-8", "replace").strip()
        except Exception:
            text = None
    if not text:
        raise ValueError("无法解析候选密钥")
    text = text.strip().strip('"').strip("'")
    if not key_candidate_matches(text, target_key_id):
        raise ValueError("不是 44 字符规范 base64，或派生出的 keyId 不匹配")
    return text


def discover_key(target_key_id):
    """定位 atRestSecretKey（44 字符规范 base64），要求派生出的 keyId == target_key_id。

    顺序：环境变量 → 密钥文件 → DPAPI blob 扫描 → 客户端进程内存扫描。
    找不到抛 RuntimeError（带可操作提示）。密钥只在内存中使用，绝不写盘/打印。
    """
    # 1) 直接给密钥
    env_key = os.environ.get("WORKBUDDY_ATREST_KEY")
    if env_key:
        derive_at_rest_key(env_key.strip())      # 仅校验格式/长度
        return env_key.strip()
    # 2) 密钥文件（明文或 DPAPI 密文）
    env_file = os.environ.get("WORKBUDDY_ATREST_KEY_FILE")
    if env_file and os.path.isfile(env_file):
        try:
            with open(env_file, "rb") as f:
                return _candidate_to_key(f.read(), target_key_id)
        except Exception:
            pass
    # 3) DPAPI blob 扫描（兼容历史上曾落盘的设备）
    dpapi_tried = 0
    for root in _scan_roots():
        if not os.path.isdir(root):
            continue
        try:
            for path, size in _iter_candidate_files(root):
                if size > 256 * 1024:
                    continue
                try:
                    with open(path, "rb") as f:
                        content = f.read()
                except OSError:
                    continue
                idx = content.find(DPAPI_MAGIC)
                if idx < 0:
                    continue
                dpapi_tried += 1
                try:
                    return _candidate_to_key(content[idx:], target_key_id)
                except Exception:
                    continue
        except OSError:
            continue
    # 4) 运行中客户端进程内存（5.6.2 的密钥不落盘，这是唯一可靠途径）
    mem_key = discover_key_from_memory(target_key_id)
    if mem_key:
        return mem_key
    raise RuntimeError(
        "无法在本机定位 WorkBuddy 5.6.2+ 的 atRestSecretKey"
        "（已尝试 %d 个 DPAPI blob 与运行中客户端进程内存扫描）。\n"
        "可选项：\n"
        "  (a) 确认 WorkBuddy 客户端已启动并登录——密钥只驻留客户端进程内存，"
        "客户端未运行则无法解密；且本脚本需与客户端在同一 Windows 用户下运行；\n"
        "  (b) 设置环境变量 WORKBUDDY_ATREST_KEY=<44 字符规范 base64>（自行承担密钥落盘风险）；\n"
        "  (c) 设置环境变量 WORKBUDDY_ATREST_KEY_FILE=<密钥文件绝对路径>（明文或 DPAPI 密文）。\n"
        "注：客户端以管理员权限运行而本脚本未提权（或相反）时，进程内存扫描会被系统拒绝。"
        % dpapi_tried)


def is_encrypted_field(raw_value):
    """是否为 5.6.2+ 加密信封（{"$wbEncrypted": 1, "envelope": "..."}）。"""
    return isinstance(raw_value, dict) and raw_value.get("$wbEncrypted") == 1


def decrypt_field(raw_value):
    """复刻 ProtectedFieldCodec.decodeString：明文直接返回；信封解 AES-256-GCM。"""
    if isinstance(raw_value, str):
        return raw_value
    if is_encrypted_field(raw_value):
        envelope_b64 = raw_value.get("envelope")
        if not isinstance(envelope_b64, str):
            raise ValueError("加密信封缺少 envelope 字段")
        envelope_bytes = base64.b64decode(envelope_b64)
        if base64.b64encode(envelope_bytes).decode("ascii") != envelope_b64:
            raise ValueError("envelope 不是规范 base64")
        key_id, nonce, ciphertext, auth_tag = parse_suite1_envelope(envelope_bytes)
        secret = discover_key(key_id)
        key, _ = derive_at_rest_key(secret)
        return aes_gcm_decrypt(key, nonce, ciphertext, build_field_aad(key_id),
                               auth_tag).decode("utf-8")
    raise ValueError("字段既不是明文也不是加密信封")



# --------------------------------------------------------------------------- #
# 登录态读取
# --------------------------------------------------------------------------- #
def read_auth_json(auth_path, attempts=5, delay=1.0):
    """读取并解析登录态 JSON。

    Windows 上客户端刷新 token 时会短暂独占该文件（open 抛 PermissionError），
    这里做有限次重试（最多约 4 秒），其余异常照原样抛出。
    """
    last_err = None
    for i in range(attempts):
        try:
            with open(auth_path, "r", encoding="utf-8-sig") as f:
                return json.load(f)
        except PermissionError as e:
            last_err = e
            if i < attempts - 1:
                time.sleep(delay)
    raise last_err


def check_expiry(auth):
    """登录态过期时给出友好提示（只读 expiresAt，绝不打印 token）。"""
    raw = auth.get("expiresAt")
    if not raw:
        return
    try:
        exp = int(raw)
    except (TypeError, ValueError):
        return
    if exp > 10 ** 11:                     # 兼容 epoch 毫秒 / 秒
        exp = exp / 1000.0
    if exp <= time.time():
        raise RuntimeError("登录态已过期（过期时间 %s），请重新登录 WorkBuddy 客户端后再试"
                           % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp)))


def load_token(auth_path, meta=None):
    """从指定登录态文件读出 (token, domain)；加密信封自动解密。"""
    data = read_auth_json(auth_path)
    auth = data.get("auth") if isinstance(data.get("auth"), dict) else {}
    raw = auth.get("accessToken")
    if raw is None:
        raise RuntimeError("登录态文件中未找到 accessToken（可能未登录或登录态已失效）")
    if is_encrypted_field(raw):
        if meta is not None:
            meta["encrypted"] = True
        try:
            token = decrypt_field(raw)
        except Exception as e:
            raise RuntimeError(
                "解密 accessToken 失败（5.6.2+ 加密登录态）：%s" % e)
    else:
        token = raw if isinstance(raw, str) else None
        if not token:
            raise RuntimeError("accessToken 字段形态无法识别：%s" % type(raw).__name__)
    domain = auth.get("domain") or "www.codebuddy.cn"
    check_expiry(auth)
    return token, domain


def load_token_best(meta=None):
    """依次尝试所有候选登录态文件，返回 (token, domain, auth_path)。

    明文 JWT 直接用；加密信封则尝试本地解密（密钥可定位才成功）。某个候选失败
    （如加密态且定位不到 atRestSecretKey）就跳过、继续下一个，全部失败才汇总报错。
    这样「桌面客户端登录态被加密、但存在其它明文兜底登录态」的场景仍能签到。
    """
    errors = []
    for p in auth_candidates():
        if not os.path.isfile(p):
            continue
        try:
            token, domain = load_token(p, meta=meta)
            return token, domain, p
        except Exception as e:
            errors.append((p, str(e)))
    if not errors:
        raise RuntimeError("未找到本机登录态文件，请确认 WorkBuddy 已登录")
    raise RuntimeError(
        "所有候选登录态文件均无法读取/解密 accessToken（共 %d 个）：\n" % len(errors)
        + "\n".join("  - %s: %s" % (pp, ee) for pp, ee in errors)
        + "\n建议：若均为 5.6.2+ 加密登录态且无法自动定位密钥，请确保 WorkBuddy 客户端"
          "已启动并登录、且与脚本在同一 Windows 用户下运行；"
          "或设置 WORKBUDDY_ATREST_KEY（/ WORKBUDDY_ATREST_KEY_FILE）后重试。")


# --------------------------------------------------------------------------- #
# 自测：不联网、不读登录态，验证解密算法（含跨后端对拍与 AAD 绑定）
# --------------------------------------------------------------------------- #
def self_test(verbose=True):
    def say(msg):
        if verbose:
            print(msg)

    say("== AtRestEncryption 解密自测 ==")
    at_rest_secret_key = base64.b64encode(bytes(range(32))).decode("ascii")
    assert len(at_rest_secret_key) == 44
    key, key_id = derive_at_rest_key(at_rest_secret_key)
    assert derive_at_rest_key(at_rest_secret_key)[1] == key_id
    say("  [ok] 密钥派生 keyId=%s" % key_id)

    sample_jwt = ("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0."
                  "fakesignaturepaddingpaddingpaddingpaddingpadding")
    nonce = os.urandom(12)
    aad = build_field_aad(key_id)
    ciphertext, auth_tag = aes_gcm_encrypt(key, nonce, sample_jwt.encode("utf-8"), aad)
    envelope_bytes = json.dumps({
        "suite": 1,
        "keyId": key_id,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "authTag": base64.b64encode(auth_tag).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }).encode("utf-8")
    say("  [ok] 构造 suite=1 信封（AES-256-GCM 加密样本）")

    p_key_id, p_nonce, p_ct, p_tag = parse_suite1_envelope(envelope_bytes)
    assert p_key_id == key_id
    p_aad = build_field_aad(p_key_id)
    assert aes_gcm_decrypt(key, p_nonce, p_ct, p_aad, p_tag).decode("utf-8") == sample_jwt
    say("  [ok] 读端解密往返一致（后端：%s）" % (aes_backend_name() or "未知"))

    # 跨后端对拍：同一 key/nonce 下三个后端的密文/tag 必须逐字节一致。
    # 这是纯 Python 兜底敢上线的前提——消除「多套实现结果不一致」的风险。
    payload = sample_jwt.encode("utf-8")
    checked = []
    mismatched = []
    for name in BACKEND_ORDER:
        if name == aes_backend_name():
            continue
        try:
            enc = _load_backend(name)
        except Exception as e:                     # 缺库 / 坏库：跳过，不算失败
            say("  [--] 后端 %-13s 不可用，跳过对拍（%s: %s）"
                % (name, type(e).__name__, e))
            continue
        try:
            other_ct, other_tag = enc(False, key, nonce, payload, aad, None)
        except Exception as e:
            say("  [--] 后端 %-13s 加密失败，跳过对拍（%s: %s）"
                % (name, type(e).__name__, e))
            continue
        if other_ct == ciphertext and other_tag == auth_tag:
            checked.append(name)
            say("  [ok] 后端 %-13s 与本实现逐字节一致" % name)
        else:
            mismatched.append(name)
    if mismatched:
        say("  [FAIL] 以下后端加解密结果不一致，禁止降级使用：%s"
            % ", ".join(mismatched))
        return False
    say("  [ok] 跨后端对拍通过（已比对：%s）"
        % (", ".join(checked) if checked else "无其它可用后端，跳过"))

    try:
        bad = bytearray(p_ct)
        bad[0] ^= 0x01
        aes_gcm_decrypt(key, p_nonce, bytes(bad), p_aad, p_tag)
        say("  [FAIL] 篡改密文未触发校验失败")
        return False
    except Exception:
        say("  [ok] 篡改密文被正确拒绝（GCM 完整性校验生效）")

    try:
        bad_tag = bytearray(p_tag)
        bad_tag[0] ^= 0x01
        aes_gcm_decrypt(key, p_nonce, p_ct, p_aad, bytes(bad_tag))
        say("  [FAIL] 篡改 authTag 未触发校验失败")
        return False
    except Exception:
        say("  [ok] 篡改 authTag 被正确拒绝（GCM 完整性校验生效）")

    try:
        bad_aad = bytearray(p_aad)
        bad_aad[0] ^= 0x01
        aes_gcm_decrypt(key, p_nonce, p_ct, bytes(bad_aad), p_tag)
        say("  [FAIL] AAD 错误未触发校验失败")
        return False
    except Exception:
        say("  [ok] AAD 错误被正确拒绝（证明 AAD 构造被 GCM 严格绑定）")

    say("== 自测全部通过：5.6.2 信封解密算法正确 ==")
    say("   AES-GCM 后端可用性：")
    for name, state in aes_backend_report().items():
        say("     %-13s %s" % (name, state))
    return True


if __name__ == "__main__":
    raise SystemExit(0 if self_test() else 1)
