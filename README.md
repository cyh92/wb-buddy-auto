# Buddy 加油站 · 云端自动签到 + 派猫猫

把 WorkBuddy「Buddy 加油站」的**每日签到**和**派猫猫旅行**交给 GitHub Actions 免费定时任务，
云端 runner 执行，**不需要任何常开设备**，结果推送邮件（或飞书）。

- 每天北京时间 **06:10** 跑一次（UTC 22:10），签到 + 猫猫一趟做完
- 猫猫：**先领**已到家（arrived）的旅行积分，**再判断**能不能派新的一趟；服务端
  `daily_limit_reached` 为真 / 旅行中 / 非 idle 一律不派 → 天然幂等，当天重复跑不重复派
- 签到：先查 `today_checked_in`，已签直接跳过；接口本身也幂等（code=10001）
- 猫猫环节任何失败都被隔离，**签到成功即任务成功**（退出码 0）
- 通知里「签到」和「猫猫旅行」分两段写清；邮件用 SMTP 直发（零第三方依赖），飞书可选

> **阅读顺序**：第一次搭 → 一（准备）→ 二（部署）→ 四（本机先跑通）；已上线日常 → 三（换 Token）；
> 出问题 → 五（常见坑）。接口细节在六。

## 文件结构

```
.github/workflows/buddy.yml     定时任务（cron + 手动触发）
scripts/wb_checkin.py           云端主脚本（纯标准库：签到+领奖+派遣+邮件/飞书推送）
scripts/wb_atrest.py            登录态读取/解密模块（本机刷新用，Actions 不依赖）
tools/refresh_token.py          本机刷新脚本：读本机登录态 → 注入 GitHub secret
tools/local_run.py              本机自测入口：直接复用本机登录态跑一轮
```

## 一、运行前准备

跑之前先确认下面 5 项。这不是形式主义——缺任何一项都**不会报出人话**：要么脚本报「解密失败」让人以为是密码问题，要么 GitHub 的 job 悄悄变红而你根本不会去看。

### 1. Python 3.8+

```bash
python --version
```

脚本纯标准库，**不需要 `pip install` 任何东西**。只在两个本机动作里用到：导出 token、跑自测。云端由 GitHub runner 自带 Python，不依赖你本机版本。

### 2. WorkBuddy 客户端：运行中 + 已登录

`tools/refresh_token.py` 要解密本机 `workbuddy-desktop.info` 里的登录态。5.6.2 之后它是 AES-GCM 信封，**密钥只存在于正在运行的客户端进程内存里**，磁盘上摸不到。由此产生三条硬要求：

| 要求 | 不满足的后果 |
|---|---|
| 客户端**开着**且已登录 | 报「解密失败」，看起来像密码错了，其实是没进程可扫 |
| 用**同一个 Windows 用户**运行脚本 | 客户端以管理员启动、你用普通终端跑 → 读不到对方内存 |
| 建议先**退出重登**一次再导出 | 当前 token 可能已用掉一半寿命，重登能拿到足额 ~55 天 |

### 3. 邮箱：开 SMTP + 生成客户端密码

只支持「SMTP + 密码类凭据」的邮箱，各服务商开法见下文「二、③ 配通知」。以 139 为例：

网页登录 `mail.10086.cn` → 设置 → 账户与安全 → 邮箱协议设置 → 开启 **IMAP/SMTP** → 同页设置**客户端密码**。

> 这一步卡住的人最多：**139 的 IMAP/SMTP 默认关闭**，密码填得再对也连不上，报错还是直接断连（不是 535），很容易误判。

### 4. GitHub 仓库：Private + 默认分支

- 建仓时**不要**勾 "Add a README file"——会与本地提交冲突，且默认分支被改成 `main`
- 推完去 Settings → General 确认 **Default branch 就是你要跑的那个分支**（本仓库是 `master`）

定时任务只在默认分支上生效，这点漏了会变成「手动 Run workflow 一切正常，cron 却从来没跑过」。

### 5. 准备清单（逐项打勾再往下走）

| # | 检查项 | 达标标准 |
|---|---|---|
| 1 | Python | `python --version` ≥ 3.8 |
| 2 | 客户端 | 已登录、正在运行、与终端同一 Windows 用户 |
| 3 | 邮箱 | IMAP/SMTP 已开启，已生成客户端密码（非登录密码） |
| 4 | 仓库 | Private，默认分支 = 推送分支 |
| 5 | 冒烟测试 | `--test-mail` 输出 `[邮件] 已发送 → 你的邮箱` |

## 二、首次部署（3 步）

### ① 建一个 Private 仓库，推代码

仓库已经在本地初始化过（分支 `master`，Gitee 作备份），所以只需再加一个 GitHub 远端双推：

```bash
git remote add github https://github.com/<owner>/<repo>.git
git push github master
```

从零开始的话（还没 `git init`）：

```bash
git init -b master && git add . && git commit -m "feat: buddy daily checkin + cat travel"
git remote add origin https://github.com/<owner>/<repo>.git
git push -u origin master
```

> 分支名用 `master` 还是 `main` 都行，**只要 workflow 文件在默认分支上**。推完去 Settings → General 核对一次。

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

### ③ 配通知：邮件（推荐）或飞书，二选一或都配

**邮件**（通用 SMTP，不需要注册任何服务，用的是「客户端密码/授权码」而不是登录密码）。
只要你的邮箱支持 SMTP + 密码类凭据就能用，不限于下表：

| 邮箱 | `MAIL_PROVIDER` 预设 | host:port | 凭据 |
|---|---|---|---|
| **139 邮箱**（移动） | `139` | `smtp.139.com:465` | 邮箱协议设置开启 IMAP/SMTP → 客户端密码 |
| QQ 邮箱 | `qq` / `foxmail` | `smtp.qq.com:465` | 设置 → 账号 → 开启 IMAP/SMTP → 授权码 |
| 163 / 126 / yeah | `163` `126` `yeah` | `smtp.163.com:465` 等 | 设置 → POP3/SMTP/IMAP → 授权码 |
| 新浪邮箱 | `sina` | `smtp.sina.com:465` | 设置 → 客户端 POP3/SMTP → 授权码 |
| 189 邮箱（电信） | `189` | `smtp.189.cn:465` | 设置 → 客户端授权码 |
| 阿里企业邮 | `aliyun` | `smtp.mxhichina.com:465` | 管理员开 SMTP → 客户端密码 |
| 网易企业邮 | `qiye163` | `smtp.qiye.163.com:465` | 同上 |
| Gmail | `gmail` | `smtp.gmail.com:587` | 两步验证 → 应用专用密码 |
| 其它 / 自建 | 不用预设 | 填 `SMTP_HOST`+`SMTP_PORT` | 465 走 SSL，其它端口走 STARTTLS |
| ~~live.cn / outlook.com~~ | — | — | 个人号已停用基础认证（2024-09 起），只能 OAuth2 |

> 规则：`SMTP_HOST` 优先；没填就按 `MAIL_PROVIDER` 取预设；`SMTP_PORT` 没填则用预设端口（默认 465）。
> 端口 465 用 SSL 直连，其它端口（如 587）自动 STARTTLS。发件人默认等于 `SMTP_USER`。

**139 邮箱具体步骤**：

1. 网页登录 `mail.10086.cn` → 右上「设置」→「账户与安全」→「邮箱协议设置」
2. 把 **IMAP/SMTP** 服务设为开启（默认是关的，不开必失败）
3. 同页「客户端密码」→ 自定义一个 8 位以上强密码（**不要和登录密码相同**）
4. GitHub 仓库 Settings → Secrets → Actions 新增：

| Secret | 值 |
|---|---|
| `MAIL_PROVIDER` | `139` |
| `SMTP_USER` | `cyh92@139.com`（完整邮箱地址） |
| `SMTP_PASS` | 上一步设置的客户端密码 |
| `MAIL_TO` | `cyh92@139.com`（多个用英文逗号分隔） |

> 用预设就**不必**再建 `SMTP_HOST` / `SMTP_PORT`；换服务商只改 `MAIL_PROVIDER` 一个值。

> 先在本机验证凭据，再配到仓库里（不需要跑签到）：
> ```bash
> export MAIL_PROVIDER=139 SMTP_USER=cyh92@139.com
> export SMTP_PASS='你的客户端密码' MAIL_TO=cyh92@139.com
> python scripts/wb_checkin.py --test-mail
> ```
> 输出 `[邮件] 已发送 → cyh92@139.com` 即通道打通；`535`/连接被断多为客户端密码错或
> 服务没开，`550` 多为发件人与登录账号不一致（`MAIL_FROM` 保持默认即可）。

> 邮件标题样例：`✅ Buddy加油站 2026-10-24｜签到成功 +100｜猫猫：已出发 → 商场店铺…`
> 正文分《签到》《猫猫旅行》两段，HTML + 纯文本双版本。发信失败只打印提示，不影响签到结论。

**飞书**（可选，与邮件可共存）：

1. 飞书群 → 设置 → 群机器人 → 添加机器人 → **自定义机器人**
2. 复制 webhook 地址（`https://open.feishu.cn/open-apis/bot/v2/hook/xxx`）
3. Secrets 新增：`FEISHU_WEBHOOK` = 该地址；`FEISHU_SECRET` = 仅当机器人开了「签名校验」才需要

配好后：Actions 页 → **Buddy 加油站 签到+派猫猫** → Run workflow，跑一次验收。
两个通道都不配也能跑，只是结果只能在 Actions 日志里看。

> ⚠️ **仓库必须在 GitHub 上**：Gitee 不会执行 `.github/workflows/buddy.yml`（它用自家的 Gitee Go，
> 语法完全不同），所以 `gitee.com/cyh92/wb-buddy-auto` 只能当代码备份，定时任务必须活在 GitHub 仓里。

## 三、约 55 天一次：换 Token

JWT 实测有效期约 **55 天**，流水线每天打印剩余天数，**不足 7 天**会输出 `::warning::`。
到期前重新执行「二、② 导出登录态」这一步即可（客户端保持登录运行）。退出重登再导出，拿到的 token 更耐用。

## 四、本机自测

推荐顺序：**先验发信，再跑业务**。这样出问题时能立刻分清是邮箱的事还是签到的事。

```bash
cd F:/androiddemo/wb-buddy-auto

# 第 1 步：只验邮箱凭据，不调任何业务接口（几秒钟）
export MAIL_PROVIDER=139 SMTP_USER=cyh92@139.com
export SMTP_PASS='你的客户端密码' MAIL_TO=cyh92@139.com
python scripts/wb_checkin.py --test-mail
# 期望：[邮件] 已发送 → cyh92@139.com

# 第 2 步：真实跑一轮（自动读本机登录态 → 签到 → 猫猫 → 发信）
python tools/local_run.py
# 期望：签到成功/已签到 + 猫猫状态 + [邮件] 已发送
```

跑完邮箱里应该收到一封 `✅ Buddy加油站 2026-10-24｜签到成功 +100｜…`，那正是以后每天 06:10 会到的东西。

其它入口：

```bash
python tools/local_run.py --mail-preview  # 只渲染通知内容，不发信、不推飞书
python tools/local_run.py --no-push       # 真实跑但跳过所有通知
python scripts/wb_checkin.py --test-mail  # 只测邮箱，不碰登录态
```

退出码：`0` 签到成功｜`1` 签到失败｜`2` 登录态缺失/无效。

## 五、常见坑

| 现象 | 真实原因 | 处理 |
|---|---|---|
| 「解密失败 / 读不到登录态」 | 客户端没开，或不是同一 Windows 用户 | 开客户端并确认已登录，用同一用户重跑；不是密码问题 |
| 手动 Run workflow 正常，定时从不触发 | 默认分支不是 workflow 所在分支 | Settings → General 改默认分支；cron 只认默认分支 |
| 每天跑但收不到邮件 | secret 名字拼错或值带空格 | 用 `--test-mail` 在本机先复现，再看 Actions 日志有没有「未配置，跳过发信」 |
| `535` / 直接断连 | 用了登录密码而非客户端密码，或 IMAP/SMTP 没开 | 回邮箱设置开服务、重设客户端密码 |
| `550` | 发件人与登录账号不一致 | 别填 `MAIL_FROM`，保持默认（= `SMTP_USER`） |
| 某天彻底没跑 | GitHub 免费 runner 排队延迟 5~15 分钟，高峰期可能跳过单次 | 签到接口幂等，手动 Run workflow 补一次即可 |
| 连续 60 天没有任何提交 | GitHub 自动停用 cron | 随便提一次 commit 后去 Actions 页重新启用 |
| token 到期后天天失败 | 约 55 天有效期，到期返回 401 | 重跑第 ② 步换 token；日志里会提前 7 天出 `::warning::` |

## 六、接口清单（以实际请求为准）

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
