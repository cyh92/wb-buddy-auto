#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本机刷新脚本：读 WorkBuddy 本机登录态 → 导出 token → 注入 GitHub 仓库 secret。

用法（在本机、WorkBuddy 客户端运行且已登录时执行）：
  python tools/refresh_token.py --repo <owner>/<repo>          # gh CLI 可用时直接注入 secret
  python tools/refresh_token.py                                # 无 gh：复制到剪贴板，手动粘贴到
                                                               # GitHub 仓库 Settings → Secrets → Actions
  python tools/refresh_token.py --out min_auth.json            # 写入本地文件（用完即删，勿提交）

安全约束：
  - 明文 token 绝不打印到控制台/日志；默认走剪贴板或 gh secret set
  - 解密 5.6.2+ 加密登录态需要客户端正在运行（密钥只在进程内存），Windows + 同一用户
  - GitHub secret 名固定为 WORKBUDDY_AUTH_JSON，与 .github/workflows/buddy.yml 对应
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import wb_atrest  # noqa: E402

SECRET_NAME = "WORKBUDDY_AUTH_JSON"


def jwt_exp_days(token):
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        claims = json.loads(base64.urlsafe_b64decode(part))
        exp = claims.get("exp")
        if isinstance(exp, (int, float)):
            return (exp - time.time()) / 86400.0
    except Exception:
        pass
    return None


def to_clipboard(text):
    """跨平台写剪贴板（不落控制台）。"""
    try:
        if os.name == "nt":
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE)
            p.communicate(text.encode("utf-16-le"))  # clip.exe 期望 UTF-16LE 或本地编码
            return True
        for cmd in (["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"],
                    ["xsel", "--clipboard", "--input"]):
            if shutil.which(cmd[0]):
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                p.communicate(text.encode("utf-8"))
                return True
    except Exception:
        pass
    return False


def main():
    ap = argparse.ArgumentParser(description="WorkBuddy 登录态 → GitHub secret 刷新工具")
    ap.add_argument("--repo", help="目标仓库 <owner>/<repo>（gh 可用时用于 gh secret set）")
    ap.add_argument("--out", help="可选：把最小登录态 JSON 写到该文件（明文，用完即删）")
    args = ap.parse_args()

    # 1. 读本机登录态（自动处理 5.5.x 明文与 5.6.2+ 加密信封）
    try:
        token, domain, auth_path = wb_atrest.load_token_best()
    except Exception as e:
        sys.stderr.write("读取本机登录态失败：\n%s\n" % e)
        return 1

    days = jwt_exp_days(token)
    print("[登录态] 来源文件: %s" % auth_path)
    print("[登录态] domain: %s" % domain)
    print("[登录态] token: %s...%s（长度 %d，已掩码）" % (token[:6], token[-4:], len(token)))
    print("[登录态] 剩余有效期: %s" % (("%.1f 天" % days) if days is not None else "未知"))
    if days is not None and days < 7:
        print("!! 剩余不足 7 天：建议先在客户端退出重登，再运行本脚本，拿到的 token 更耐用")

    # 2. 组最小登录态 JSON（与 workflow secret 对应）
    payload = json.dumps({"auth": {"accessToken": token, "domain": domain}},
                         ensure_ascii=True, separators=(",", ":"))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(payload)
        print("\n已写入：%s（⚠️ 明文凭据，注入 secret 后请立即删除，切勿提交/截图）" % args.out)
        return 0

    # 3a. gh CLI：直接注入仓库 secret（token 不落控制台）
    gh = shutil.which("gh")
    if gh and args.repo:
        print("\n使用 gh CLI 注入 secret %s → %s ..." % (SECRET_NAME, args.repo))
        p = subprocess.run([gh, "secret", "set", SECRET_NAME, "--repo", args.repo,
                            "--body", payload], capture_output=True, text=True)
        if p.returncode == 0:
            print("✅ 已注入（gh secret set 成功）。云端 Actions 下次运行即用新 token。")
            return 0
        sys.stderr.write("gh secret set 失败（%s）：%s\n可改用剪贴板方式重试。\n"
                         % (p.returncode, p.stderr.strip()))
        return 1

    # 3b. 无 gh：复制到剪贴板，手动粘贴到 GitHub 网页
    if to_clipboard(payload):
        print("\n✅ 最小登录态 JSON 已复制到剪贴板（控制台不留明文）。")
    else:
        sys.stderr.write("剪贴板不可用，请改用 --out 参数输出到临时文件。\n")
        return 1
    print("下一步（手动，约 1 分钟）：")
    print("  1. 打开 GitHub 仓库 → Settings → Secrets and variables → Actions")
    print("  2. New repository secret，Name 填：%s" % SECRET_NAME)
    print("  3. Secret 粘贴剪贴板内容 → Add secret（更新已存在的同名 secret 即可）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
