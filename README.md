# Buddy 加油站 · 云端自动签到 + 派猫猫

把 WorkBuddy「Buddy 加油站」的**每日签到**和**派猫猫旅行**交给 GitHub Actions 免费定时任务，
云端 runner 执行，**不需要任何常开设备**，结果推送到飞书。

- 每天北京时间 **06:10** 跑一次（UTC 22:10），签到 + 猫猫一趟做完
- 猫猫：**先领**已到家（arrived）的旅行积分，**再判断**能不能派新的一趟；服务端
  `daily_limit_reached` 为真 / 旅行中 / 非 idle 一律不派 → 天然幂等，当天重复跑不重复派
- 签到：先查 `today_checked_in`，已签直接跳过；接口本身也幂等（code=10001）
- 猫猫环节任何失败都被隔离，**签到成功即任务成功**（退出码 0）
- 飞书消息里「签到」和「猫猫旅行」分两段写清

## 目录

```
.github/workflows/buddy.yml     定时任务（cron + 手动触发）
scripts/wb_checkin.py           云端主脚本（纯标准库，签到+领奖+派遣+飞书推送）
scripts/wb_atrest.py            登录态读取/解密模块（本机刷新用，Actions 不依赖）
tools/refresh_token.py          本机刷新脚本：读本机登录态 → 注入 GitHub secret
```

## 一、首次部署（3 步）

### ① 建一个 Private 仓库，推代码

```bash
# 建议 Private：仓库本身没有凭据，但签到类脚本没必要公开
git init -b main && git add . && git commit -m "feat: buddy daily checkin + cat travel"
git remote add origin https://github.com/<owner>/<repo>.git
git push -u origin main
```

### ② 在本机导出登录态 → 注入 secret（唯一需要手动做的一步）

前提：**WorkBuddy 客户端正在运行且已登录**（5.6.2+ 登录态是加密的，密钥只在进程内存里）。

```bash
# 有 gh CLI：直接写入仓库 secret，token 不落控制台
python tools/refresh_token.py --repo <owner>/<repo>

# 没有 gh CLI：复制到剪贴板，去网页粘贴
python tools/refresh_token.py
#  → GitHub 仓库 Settings → Secrets and variables → Actions → New repository secret
#    Name: WORKBUDDY_AUTH_JSON   Value: 粘贴剪贴板内容
```

> 明文 token 不进仓库、不进日志：脚本只打印掩码，`.gitignore` 已排除 `secrets*.yml|json`、`min_auth*.json`。

### ③ 配飞书机器人（可选但推荐）

1. 飞书群 → 设置 → 群机器人 → 添加机器人 → **自定义机器人**
2. 复制 webhook 地址（`https://open.feishu.cn/open-apis/bot/v2/hook/xxx`）
3. 仓库 Settings → Secrets → Actions 新增：
   - `FEISHU_WEBHOOK` = 上面那个地址
   - `FEISHU_SECRET` = 仅在机器人开启「签名校验」时填，否则不建
4. Actions 页 → **Buddy 加油站 签到+派猫猫** → Run workflow，跑一次验收

## 二、约 55 天一次：换 Token

JWT 实测有效期约 **55 天**，流水线每天打印剩余天数，**不足 7 天**会输出 `::warning::`。
到期前重新执行第 ② 步即可（客户端保持登录运行）。退出重登再导出，拿到的 token 更耐用。

## 三、本机自测

```bash
# 只读：查状态不领取（不会产生任何写操作）
# 实际跑一轮（签到 + 猫猫闭环，会真实领取/派遣）
python scripts/wb_checkin.py          # 需先 export WORKBUDDY_AUTH_JSON=...
python scripts/wb_checkin.py --no-push
```

退出码：`0` 签到成功｜`1` 签到失败｜`2` 登录态缺失/无效。

## 四、接口清单（以实际请求为准）

| 用途 | 方法 | 路径 | 域名 |
|---|---|---|---|
| 查今日签到状态 | POST | `/billing/meter/checkin-activity-status` | token 里的 `auth.domain` |
| 领取签到积分 | POST | `/billing/meter/daily-checkin` | 同上 |
| 账户积分余额 | POST | `/billing/meter/get-user-resource-summary`（**不带 /v2**） | 同上 |
| 旅行状态 | GET | `/activity/growth/buddy/travel/status` | `www.workbuddy.cn` |
| 可选地点 | GET | `/activity/growth/buddy/travel/config` | `www.workbuddy.cn` |
| 领取旅行积分 | POST | `/activity/growth/buddy/travel/claim` | `www.workbuddy.cn` |
| 派出 Buddy | POST | `/activity/growth/buddy/travel/depart` | `www.workbuddy.cn` |

鉴权：`Authorization: Bearer <JWT>`。签到域名以 token 内 `auth.domain` 为准（可能为
`www.workbuddy.cn` 或 `www.codebuddy.cn`），猫猫固定在 `www.workbuddy.cn`。

> 网上流传的 `/billing/meter/checkin-status` 是旧名，实际为 `checkin-activity-status`。
