#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WorkBuddy「Buddy 加油站」云端自动签到 + 派猫猫旅行（GitHub Actions 版）

流程（一次跑完）：
  1. 从 secret WORKBUDDY_AUTH_JSON 读登录态（本机刷新脚本导出，云端无本机依赖）
  2. 签到：查今日状态 → 未签则领取（幂等：已签自动跳过）
  3. 派猫猫旅行：先领已到家(arrived)的旅行积分 → 再看能否派新的一趟
     （服务端 daily_limit_reached 为真 / 旅行中 / 非 idle 一律不派，天然幂等）
  4. 推送飞书：签到与猫猫两段分开写清楚
  5. 退出码只看签到：猫猫任何失败都不影响「签到成功 = 任务成功」

安全约束：
  - token 只从环境变量读，绝不打印明文（输出统一过 _mask 掩码）
  - 只请求官方域名：{auth.domain}（签到）与 www.workbuddy.cn（猫猫）
  - 纯标准库，云端零 pip 依赖

退出码：0=签到成功；1=签到失败；2=登录态缺失/无效
"""

import base64
import hashlib
import hmac
import json
import os
import random
import re
import smtplib
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr, formatdate

MAX_RETRY = 2
HTTP_TIMEOUT = 30
TZ_CN = timezone(timedelta(hours=8))

# ---- 接口路径（以实际请求为准，勿改）----
STATUS_PATH = "/billing/meter/checkin-activity-status"        # POST 查今日签到状态
CHECKIN_PATH = "/billing/meter/daily-checkin"                 # POST 领取签到
CREDITS_PATH = "/billing/meter/get-user-resource-summary"     # POST 账户余额（不带 /v2）

TRAVEL_BASE = "https://www.workbuddy.cn"
TRAVEL_STATUS_PATH = "/activity/growth/buddy/travel/status"   # GET  旅行状态
TRAVEL_CONFIG_PATH = "/activity/growth/buddy/travel/config"   # GET  可选地点
TRAVEL_CLAIM_PATH = "/activity/growth/buddy/travel/claim"     # POST 领取旅行积分
TRAVEL_DEPART_PATH = "/activity/growth/buddy/travel/depart"   # POST 派出

TRAVEL_STATE_TEXT = {"idle": "空闲", "traveling": "旅行中", "arrived": "已到家"}


class AuthError(Exception):
    pass


# ---------------- 基础 ----------------

def api_call(base, path, token, payload=None, method="POST"):
    """统一 API 调用。返回 (http_status, body_dict_or_{'raw': str})。"""
    url = base + path
    if method == "GET" and payload is None:
        data = None
    else:
        data = json.dumps(payload if payload is not None else {}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer %s" % token)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "wb-buddy-auto/1.0")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return _parse_body(resp.status, resp.read())
    except urllib.error.HTTPError as e:
        # 非 2xx 也读响应体（如重复签到的 HTTP 400 / code=10001）
        try:
            return _parse_body(e.code, e.read())
        except Exception:
            return e.code, {"raw": ""}
    except urllib.error.URLError as e:
        return 0, {"error": "网络错误: %s" % getattr(e, "reason", e)}


def _parse_body(status, raw_bytes):
    body = raw_bytes.decode("utf-8", "replace") if raw_bytes else ""
    try:
        return status, json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return status, {"raw": body[:500]}


_TOKEN_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")


def mask_text(text):
    """输出兜底掩码：任何疑似 JWT 的串都打码，防止明文进日志。"""
    return _TOKEN_RE.sub("<JWT已掩码>", str(text))


def mask_token(t):
    if not isinstance(t, str) or not t:
        return "<empty>"
    return "%s...%s（长度 %d）" % (t[:6], t[-4:], len(t))


def load_auth():
    """从环境变量解析登录态。兼容：完整 JSON / {"auth":{...}} / 裸 accessToken。"""
    raw = (os.environ.get("WORKBUDDY_AUTH_JSON") or "").strip()
    if not raw:
        raise AuthError("环境变量 WORKBUDDY_AUTH_JSON 未设置（请先在本机运行 tools/refresh_token.py 注入）")
    token, domain = None, None
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        obj = raw  # 裸 token
    if isinstance(obj, dict):
        auth = obj.get("auth") if isinstance(obj.get("auth"), dict) else obj
        token = auth.get("accessToken")
        domain = auth.get("domain")
    elif isinstance(obj, str):
        token = obj
    if not isinstance(token, str) or token.count(".") < 2:
        raise AuthError("WORKBUDDY_AUTH_JSON 中未找到有效 accessToken（形态不符）")
    return token, (domain or "www.codebuddy.cn").strip()


def jwt_exp(token):
    """解 JWT exp 得剩余天数；解析失败返回 None（不编造）。"""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = claims.get("exp")
        if isinstance(exp, (int, float)):
            return (exp - time.time()) / 86400.0
    except Exception:
        pass
    return None


# ---------------- 签到 ----------------

def do_checkin(base, token):
    """签到主流程。返回结构化结果；重试 MAX_RETRY 次。"""
    result = {"ok": False, "action": None, "points": None, "streak_days": None,
              "activity_credits": None, "msg": "", "detail": {}}
    last_err = None
    for attempt in range(1, MAX_RETRY + 2):
        try:
            st, st_body = api_call(base, STATUS_PATH, token)
            result["detail"]["status_http"] = st
            result["detail"]["status_resp"] = st_body
            if isinstance(st_body, dict):
                st_data = st_body.get("data") if isinstance(st_body.get("data"), dict) else {}
                result["activity_credits"] = _num(st_data.get("total_credits"))
            if st == 401:
                result["msg"] = "登录态失效（HTTP 401），请在本机重新运行 tools/refresh_token.py"
                return result

            signed = False
            if isinstance(st_body, dict):
                data = st_body.get("data") if isinstance(st_body.get("data"), dict) else st_body
                signed = (data.get("today_checked_in") is True) or (str(st_body.get("code")) == "10001")

            if signed:
                result.update(ok=True, action="skip_already_signed",
                              msg="今日已签到（服务端确认），无需重复领取")
                return result

            st_code, ck_body = api_call(base, CHECKIN_PATH, token)
            result["detail"]["checkin_http"] = st_code
            result["detail"]["checkin_resp"] = ck_body
            if st_code == 401:
                result["msg"] = "登录态失效（HTTP 401），请在本机重新运行 tools/refresh_token.py"
                return result

            if isinstance(ck_body, dict):
                code = str(ck_body.get("code", ""))
                msg = ck_body.get("msg") or ck_body.get("message") or ""
                data = ck_body.get("data") if isinstance(ck_body.get("data"), dict) else {}
                if code == "10001" or "已签到" in str(msg):
                    result.update(ok=True, action="skip_already_signed",
                                  msg="今日已签到（接口幂等返回 code=10001）")
                    return result
                if 200 <= st_code < 300 and code in ("", "0", "200"):
                    credit = (ck_body.get("credit") or data.get("credit")
                              or data.get("daily_credit") or data.get("today_credit"))
                    streak = ck_body.get("streak_days") or data.get("streak_days")
                    act = _num(data.get("total_credits") if isinstance(data, dict) else None) \
                        or _num(ck_body.get("total_credits"))
                    result.update(ok=True, action="claimed", points=_num(credit),
                                  streak_days=_num(streak), activity_credits=act,
                                  msg="签到成功%s%s" % (
                                      ("，+%s 积分" % _num(credit)) if _num(credit) is not None else "",
                                      ("，连续第 %s 天" % _num(streak)) if _num(streak) else ""))
                    return result
                result["msg"] = mask_text(msg or ("HTTP %s（业务码 %s）" % (st_code, code)))
                return result
            result["msg"] = "领取接口返回非 JSON"
            return result
        except Exception as e:
            last_err = "%s: %s" % (type(e).__name__, e)
            time.sleep(2)
    result["msg"] = "重试 %d 次后仍失败：%s" % (MAX_RETRY, last_err)
    return result


def _num(value):
    try:
        return int(value) if float(value) == int(float(value)) else round(float(value), 2)
    except (TypeError, ValueError):
        return None


def query_balance(base, token):
    """账户积分余额（积分包汇总，不带 /v2）。失败返回 None，不影响主流程。"""
    try:
        st, body = api_call(base, CREDITS_PATH, token, payload={})
        if st == 200 and isinstance(body, dict) and str(body.get("code")) in ("0", "200", ""):
            data = body.get("data") if isinstance(body.get("data"), dict) else {}
            for key in ("TotalCredits", "total_credits", "total_credit", "balance"):
                if key in data:
                    return _num(data.get(key))
            # 兜底：积分包列表汇总（Packages[].CycleRemainCapacity）
            items = data.get("Packages") or data.get("packages") or data.get("items")
            if isinstance(items, list):
                total = sum(float(i.get("CycleRemainCapacity") or i.get("remaining_credit")
                                  or i.get("credit") or 0)
                            for i in items if isinstance(i, dict))
                return round(total, 2)
    except Exception:
        pass
    return None


# ---------------- 派猫猫旅行 ----------------

def travel_get(token, path):
    """只读 GET；任何失败返回 None（静默降级，绝不影响签到）。"""
    try:
        st, body = api_call(TRAVEL_BASE, path, token, method="GET")
        if st == 200 and isinstance(body, dict) and body.get("code") == 0:
            data = body.get("data")
            return data if isinstance(data, dict) else None
    except Exception:
        pass
    return None


def fmt_duration(seconds):
    if seconds is None:
        return None
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m = rem // 60
    if h > 0:
        return "%d小时%d分" % (h, m)
    if m > 0:
        return "%d分钟" % m
    return "%d秒" % seconds


def travel_flow(token):
    """猫猫闭环：先领已到家的 → 再判断能否派新的一趟。

    独立返回 {ok, parts[], final_state}，任何异常都被吞掉，绝不抛出。
    """
    parts = []
    try:
        status = travel_get(token, TRAVEL_STATUS_PATH)
        if not isinstance(status, dict):
            return {"ok": False, "parts": ["查询旅行状态失败，猫猫环节跳过（不影响签到）"],
                    "final_state": None}

        # 1) 先领已到家的旅行积分
        if status.get("state") == "arrived":
            st, body = api_call(TRAVEL_BASE, TRAVEL_CLAIM_PATH, token, payload={})
            if st == 200 and isinstance(body, dict) and body.get("code") == 0:
                credit = (body.get("data") or {}).get("reward_credit") \
                    if isinstance(body.get("data"), dict) else None
                parts.append("领奖成功 +%s 积分（上一趟已到家）" % (_num(credit) if _num(credit) is not None else "?"))
                fresh = travel_get(token, TRAVEL_STATUS_PATH)
                if isinstance(fresh, dict):
                    status = fresh
            else:
                msg = body.get("msg") if isinstance(body, dict) else ("HTTP %s" % st)
                parts.append("领奖未成功：%s（奖励保留，下次运行补领）" % mask_text(msg))

        # 2) 再判断能否派新的一趟
        state = status.get("state")
        if status.get("daily_limit_reached"):
            parts.append("今日已派过（达每日上限），不再派新的一趟")
        elif state in (None, "", "idle"):
            config = travel_get(token, TRAVEL_CONFIG_PATH)
            locs = [loc for loc in (config.get("locations") if isinstance(config, dict) else None) or []
                    if isinstance(loc, dict) and loc.get("id") is not None]
            chosen = random.choice(locs)["id"] if locs else 1
            st, body = api_call(TRAVEL_BASE, TRAVEL_DEPART_PATH, token,
                                payload={"location_id": chosen})
            if st == 200 and isinstance(body, dict) and body.get("code") == 0:
                data = body.get("data") if isinstance(body.get("data"), dict) else {}
                loc = data.get("location") if isinstance(data.get("location"), dict) else {}
                arrive = data.get("arrive_at")
                eta = fmt_duration(arrive - time.time()) if isinstance(arrive, (int, float)) else None
                parts.append("已出发 → %s%s" % (loc.get("name") or ("地点 %s" % chosen),
                                               ("，预计 %s 后到家" % eta) if eta else ""))
            else:
                msg = body.get("msg") if isinstance(body, dict) else ("HTTP %s" % st)
                parts.append("派遣未成功：%s" % mask_text(msg))
        elif state == "traveling":
            arrive, now = status.get("arrive_at"), status.get("server_now")
            eta = fmt_duration(arrive - now) if isinstance(arrive, int) and isinstance(now, int) else None
            loc = status.get("location")
            parts.append("旅行中（%s）%s，到家后再领积分"
                         % ((loc or {}).get("name") or "路上", ("，还剩 %s" % eta) if eta else ""))
        else:
            parts.append("状态异常（state=%s），保守起见不派" % state)

        final = travel_get(token, TRAVEL_STATUS_PATH) or status
        state_text = TRAVEL_STATE_TEXT.get(final.get("state"), final.get("state"))
        return {"ok": True, "parts": parts,
                "final_state": state_text,
                "daily_limit_reached": bool(final.get("daily_limit_reached"))}
    except Exception as e:
        return {"ok": False, "parts": ["猫猫环节异常已隔离：%s: %s" % (type(e).__name__, e)],
                "final_state": None}


# ---------------- 通知推送（邮件 / 飞书，可选） ----------------

def build_notice(summary):
    """把结果渲染成 (subject, text, html)：签到与猫猫两段分开写，邮件/飞书共用。"""
    c, t = summary["checkin"], summary["travel"]
    icon_c = "✅" if c["ok"] else "❌"
    icon_t = "🐱" if t["ok"] else "⚠️"
    head = "Buddy加油站日报 %s" % summary["date"]

    lines = ["【签到】%s" % icon_c, c["msg"] or "（无信息）"]
    if c["activity_credits"] is not None:
        lines.append("签到活动累计：%s 积分" % c["activity_credits"])
    if summary["balance"] is not None:
        lines.append("账户余额：%s 积分" % summary["balance"])
    lines += ["", "【猫猫旅行】%s" % icon_t]
    lines += t["parts"] or ["（无信息）"]
    if t["final_state"]:
        lines.append("当前状态：%s" % t["final_state"])
    if not t["ok"]:
        lines.append("（猫猫环节失败，不影响今日签到结论）")
    lines += ["", "由 GitHub Actions 自动执行 · 签到结论：%s" % ("成功" if c["ok"] else "失败")]
    text = head + "\n\n" + "\n".join(lines)

    # 邮件标题：一眼看清今天的结果（过长截断加省略号）
    brief = "签到成功" if c["ok"] else "签到失败"
    if c["ok"] and c["points"]:
        brief += " +%s" % c["points"]
    tail = (t["parts"][0] if t["parts"] else "无信息")
    tail = tail if len(tail) <= 16 else tail[:16] + "…"
    subject = "%s Buddy加油站 %s｜%s｜猫猫：%s" % (
        "✅" if c["ok"] else "❌", summary["date"][:10], brief, tail)

    rows = [("签到", c["msg"] or "-"),
            ("签到活动累计", ("%s 积分" % c["activity_credits"]) if c["activity_credits"] is not None else "-"),
            ("账户余额", ("%s 积分" % summary["balance"]) if summary["balance"] is not None else "-"),
            ("猫猫旅行", "；<br>".join(t["parts"]) if t["parts"] else "-"),
            ("猫猫状态", t["final_state"] or "-")]
    tr = "".join(
        "<tr><td style=\"padding:7px 12px;color:#666;white-space:nowrap;"
        "border-bottom:1px solid #f0f0f0\">%s</td>"
        "<td style=\"padding:7px 12px;border-bottom:1px solid #f0f0f0\">%s</td></tr>" % kv
        for kv in rows)
    html = (
        "<div style=\"font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;"
        "font-size:14px;color:#222;max-width:560px\">"
        "<h3 style=\"margin:0 0 12px;font-size:16px\">%s %s</h3>"
        "<table style=\"border-collapse:collapse;border:1px solid #eee;background:#fafafa\">%s</table>"
        "<p style=\"color:#999;font-size:12px;margin-top:14px\">由 GitHub Actions 自动执行"
        "　签到结论：%s</p></div>"
        % ("🔥", head, tr, "成功" if c["ok"] else "失败"))
    return subject, text, html


def send_mail(subject, text, html=None):
    """SMTP 发信（纯标准库，适配 QQ/163/Gmail/Outlook）。

    需配置 SMTP_HOST / SMTP_USER / SMTP_PASS（授权码，不是登录密码）/ MAIL_TO，
    可选 SMTP_PORT（默认 465）、MAIL_FROM（默认同 SMTP_USER）。
    未配置或失败都只打印提示，绝不抛异常、不影响签到结论。
    """
    host = (os.environ.get("SMTP_HOST") or "").strip()
    user = (os.environ.get("SMTP_USER") or "").strip()
    pwd = (os.environ.get("SMTP_PASS") or "").strip()
    to = (os.environ.get("MAIL_TO") or "").strip()
    if not (host and user and pwd and to):
        print("[邮件] 未配置 SMTP_HOST/SMTP_USER/SMTP_PASS/MAIL_TO，跳过发信")
        return False
    try:
        port = int((os.environ.get("SMTP_PORT") or "465").strip())
    except ValueError:
        port = 465
    sender = (os.environ.get("MAIL_FROM") or "").strip() or user
    recipients = [a.strip() for a in to.split(",") if a.strip()]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr(("Buddy加油站", sender))
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=True)
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")

    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=25,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(host, port, timeout=25)
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        with server:
            server.login(user, pwd)
            server.send_message(msg, from_addr=sender, to_addrs=recipients)
        print("[邮件] 已发送 → %s（%s:%s）" % (", ".join(recipients), host, port))
        return True
    except Exception as e:
        name, detail = type(e).__name__, str(e)
        hint = ""
        if "SMTPServerDisconnected" in name or "535" in detail:
            hint = ("（多为认证失败：确认用的是「客户端密码/授权码」而不是登录密码，"
                    "且邮箱设置里 IMAP/SMTP 服务已开启）")
        elif "550" in detail or "553" in detail:
            hint = "（多为发件人与登录账号不一致：MAIL_FROM 保持默认，等于 SMTP_USER）"
        elif "timed out" in detail.lower() or "refused" in detail.lower():
            hint = "（连不上服务器：确认 SMTP_HOST/SMTP_PORT，139/QQ/163 用 465，Gmail 用 587）"
        print("[邮件] 发送失败（不影响签到结论）：%s: %s%s"
              % (name, mask_text(detail), hint))
        return False


def feishu_push(text):
    """推送飞书自定义机器人。webhook 未配置/失败返回 False（不抛异常）。"""
    webhook = (os.environ.get("FEISHU_WEBHOOK") or "").strip()
    if not webhook:
        print("[飞书] 未配置 FEISHU_WEBHOOK secret，跳过推送（结果见上方 JSON）")
        return False
    payload = {"msg_type": "text", "content": {"text": text}}
    secret = (os.environ.get("FEISHU_SECRET") or "").strip()
    if secret:
        timestamp = str(int(time.time()))
        string_to_sign = "%s\n%s" % (timestamp, secret)
        sign = base64.b64encode(hmac.new(string_to_sign.encode("utf-8"),
                                         b"", digestmod=hashlib.sha256).digest()).decode()
        payload["timestamp"] = timestamp
        payload["sign"] = sign
    try:
        req = urllib.request.Request(webhook,
                                     data=json.dumps(payload).encode("utf-8"),
                                     method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=15) as resp:
            out = json.loads(resp.read().decode("utf-8", "replace") or "{}")
            ok = out.get("code") == 0 or out.get("StatusCode") == 0
            print("[飞书] 推送%s：%s" % ("成功" if ok else "失败", mask_text(out)))
            return ok
    except Exception as e:
        print("[飞书] 推送异常（不影响签到结论）：%s: %s" % (type(e).__name__, e))
        return False


def notify(subject, text, html):
    """多通道分发：配了就发，都没配就只留日志。返回已成功的通道名。"""
    sent = []
    if send_mail(subject, text, html):
        sent.append("邮件")
    if feishu_push(text):
        sent.append("飞书")
    if not sent:
        print("[通知] 未配置任何通道（邮件 SMTP_* / 飞书 FEISHU_WEBHOOK），结果见上方 JSON")
    return sent


# ---------------- 主流程 ----------------

def main():
    argv = sys.argv[1:]
    no_push = "--no-push" in argv

    # 0. 只测邮件通道（不跑业务，方便配 secret 前先验证凭据）
    if "--test-mail" in argv:
        subject = "Buddy加油站 · 邮件通道测试"
        text = ("这是一封来自 wb-buddy-auto 的测试邮件。\n\n"
                "收到即表示 SMTP 配置正确，之后每天的签到/猫猫结果会用同样格式发到这个邮箱。")
        ok = send_mail(subject, text, "<p>%s</p>" % text.replace("\n", "<br>"))
        print("[test-mail] %s" % ("成功" if ok else "失败，按上面提示排查"))
        return 0 if ok else 1

    # 1. 登录态
    try:
        token, domain = load_auth()
    except AuthError as e:
        print(json.dumps({"ok": False, "fatal": str(e)}, ensure_ascii=False))
        return 2
    base = "https://%s" % domain
    days_left = jwt_exp(token)
    print("[登录态] token=%s domain=%s 剩余有效期=%s"
          % (mask_token(token), domain,
             ("%.1f 天" % days_left) if days_left is not None else "未知（无法解析 exp）"))
    if days_left is not None and days_left < 7:
        print("::warning::登录态剩余不足 7 天，请在本机运行 tools/refresh_token.py 换新！")

    # 2. 签到（主结论）
    checkin = do_checkin(base, token)
    balance = query_balance(base, token)

    # 3. 猫猫（先领后派；与签到结论隔离）
    travel = travel_flow(token)

    # 4. 汇总输出（脱敏原始返回）
    summary = {
        "date": datetime.now(TZ_CN).strftime("%Y-%m-%d %H:%M:%S"),
        "checkin": {k: checkin[k] for k in ("ok", "action", "points", "streak_days",
                                            "activity_credits", "msg")},
        "balance": balance,
        "travel": {"ok": travel["ok"], "parts": travel["parts"],
                   "final_state": travel["final_state"]},
        "detail_raw": checkin["detail"],  # 原始接口返回（已无凭据字段，输出前统一掩码兜底）
    }
    print("\n===== 结果摘要 =====")
    print(mask_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str)))

    # 5. 通知：邮件 / 飞书（配哪个走哪个；签到、猫猫两段分开写）
    c = summary["checkin"]
    subject, notice_text, notice_html = build_notice(summary)
    if "--mail-preview" in argv:
        print("\n===== 通知预览（未发送） =====")
        print("Subject: %s" % subject)
        print("-" * 40)
        print(notice_text)
    elif not no_push:
        notify(subject, notice_text, notice_html)

    # 6. 退出码只看签到
    if not c["ok"]:
        print("\n[结论] 签到失败 → 退出码 1")
        return 1
    print("\n[结论] 签到成功%s → 退出码 0"
          % ("（猫猫环节另有提示，见上）" if not travel["ok"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
