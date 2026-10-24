#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本机自测入口：读本机登录态 → 内存注入环境变量 → 直接跑云端主脚本。

用途：推送代码前先在本机验证一遍，不用手工 export WORKBUDDY_AUTH_JSON。
  python tools/local_run.py            # 真实跑（会签到/领奖/派遣）
  python tools/local_run.py --no-push  # 不推飞书

注：token 只在进程内存中传递，不落盘、不打印。
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))

import wb_atrest  # noqa: E402
import wb_checkin  # noqa: E402


def main():
    try:
        token, domain, path = wb_atrest.load_token_best()
    except Exception as e:
        sys.stderr.write("读取本机登录态失败（确认客户端在运行且已登录）：\n%s\n" % e)
        return 2
    print("[local] 登录态: domain=%s 来源=%s token=%s...%s"
          % (domain, path, token[:6], token[-4:]))
    os.environ["WORKBUDDY_AUTH_JSON"] = json.dumps(
        {"auth": {"accessToken": token, "domain": domain}})
    sys.argv = ["wb_checkin.py"] + sys.argv[1:]
    return wb_checkin.main()


if __name__ == "__main__":
    sys.exit(main())
