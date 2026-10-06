# 安全中心 · Master

Go 主控通过 `55555/udp` 接收 Anqu Agent 的巡检摘要、文件/进程告警及每次 SSH 登录，通过 `10110/tcp` 提供经过登录鉴权的管理 API。配套 Vue 前端 `anquan-server-web` 使用 `10111/tcp`。

SQLite 数据文件为 `/data/anquan/anquan.db`。第一次启动自动创建目录、表和 `admin` 账号，默认密码 **`admin1818.`**（含末尾英文句点）。再次启动保留原密码、会话及全部数据。密码使用 bcrypt，浏览器使用 HttpOnly / SameSite=Strict Cookie，会话有效期 24 小时。

## 服务器独立部署脚本（推荐）

原生部署，不使用 Docker。支持 Ubuntu 22.04+/Debian 12+、systemd、x86_64 或 arm64。脚本自动安装基础依赖及独立的 Go 工具链，编译后注册 `anquan-master` systemd 服务；前端可以部署到另一台服务器。需要能访问软件源、go.dev 和 Go 模块代理。

```sh
sudo mkdir -p /opt/anquan
sudo apt-get update
sudo apt-get install -y git
cd /opt/anquan
sudo git clone https://github.com/userreksai/anquan-server-master.git
cd anquan-server-master
sudo sh deploy/deploy.sh
```

脚本编译、启动服务并等待健康检查通过，监听 `10110/TCP` 和 `55555/UDP`，首次自动初始化 `/data/anquan`。对 Agent 开通 UDP 55555，对前端服务器开通 TCP 10110。服务器重启后服务自动启动。Go 安装在 `/opt/anquan-tools/go1.27.1`，不覆盖系统现有工具链，下载后验证[官方 SHA256](https://go.dev/dl/?mode=json&include=all)。

更新、查看日志、重置管理员密码：

```sh
cd /opt/anquan/anquan-server-master
sudo git pull --ff-only
sudo sh deploy/deploy.sh
sudo systemctl status anquan-master --no-pager
sudo journalctl -u anquan-master -f
sudo anquan-reset-password
```

更新保留 `/data/anquan` 的数据库、密码和通知配置。已有 `anquan-master` systemd 服务会直接更新；如有其他方式运行的旧主控，应先停止旧实例。配置可写入 `/etc/anquan-master.env`，与下方参数表一致；脚本健康检查使用默认的本地 HTTP 10110。失败时返回非零退出码，可通过日志命令排查。

## 源码运行

需要 Go 1.27.1 或更新版本；SQLite 为纯 Go 驱动，无需系统 sqlite 或 C 编译器。

```sh
go test ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -o dist/anquan-master ./cmd/anquan-master
./dist/anquan-master
```

开发环境可指定数据目录和监听地址：

```sh
./dist/anquan-master --data-dir ./data --http 127.0.0.1:10110 --udp 127.0.0.1:55555
```

| 参数 | 环境变量 | 默认值 |
|---|---|---|
| `--data-dir` | `ANQUAN_DATA_DIR` | `/data/anquan` |
| `--http` | `ANQUAN_HTTP_ADDR` | `:10110` |
| `--udp` | `ANQUAN_UDP_ADDR` | `:55555` |
| `--secure-cookie` | `ANQUAN_SECURE_COOKIE` | `false`；HTTPS 部署可设为 `true` |

也支持显式 `serve` 子命令。`GET /healthz` 检查服务和数据库。程序收到 SIGTERM / Ctrl+C 后停止接收、关闭后台通知和 HTTP 服务。

## Docker Compose

前后端目录需相邻：

```text
anquan-server-master/
anquan-server-web/
```

在本目录执行：

```sh
docker compose up -d --build
docker compose logs -f master
```

打开 `http://主控IP:10111`。容器启动脚本准备宿主机绑定目录 `/data/anquan` 的权限，随后以 `anquan` 非 root 账号运行主控。前端 Nginx 代理 `/api/`，浏览器无需跨域。只应启动一个主控实例使用该 SQLite 数据库。

## systemd

```sh
sudo sh deploy/install.sh ./dist/anquan-master
sudo systemctl status anquan-master
journalctl -u anquan-master -f
```

安装脚本创建系统账号、目录、服务和 `/usr/local/bin/anquan-reset-password`。可在 `/etc/anquan-master.env` 设置监听地址等环境变量。数据目录固定可写为 `/data/anquan`；如改变数据路径，也需调整 unit 中的 `WorkingDirectory` 和 `ReadWritePaths`。

## 忘记密码

systemd 安装：

```sh
sudo anquan-reset-password
```

Docker 安装：

```sh
docker compose exec master /app/reset-admin-password.sh
```

脚本隐藏输入并二次确认，新密码通过标准输入传给后端 CLI，不进入进程命令行。手工安装可用 `ANQUAN_BIN=/实际路径/anquan-master ANQUAN_DATA_DIR=/data/anquan sh deploy/reset-admin-password.sh`。自动化场景支持 `--stdin` 从标准输入读取密码；底层命令为 `anquan-master reset-admin --data-dir /data/anquan --password-stdin`。

重置只操作已经存在的数据库，密码长度 8–72 字节，全部旧登录会话立即失效，无需重启。正常登录时也可通过页面修改密码。

## Agent 与记录

将 Agent 私有配置的 `server` 设为主控地址，重新构建内置配置程序后部署：

```yaml
server:
  - 172.22.0.100:55555
agent_ip: 172.22.0.101
```

机器以 IP 为主键，单独保存 hostname、UDP 来源 IP、上报 IP、别名、备注、首次/最近接收时间和最新巡检摘要。`agent_ip` 可省略，Agent 默认使用本地出口 IP；旧版本没有 `ip` 字段时主控使用 UDP 来源地址。多台机器经同一 NAT 上报时，应配置各自唯一 IP。

事件保存 `event_id`、机器 IP、类型、发生时间、接收时间、原始 data、处理状态和备注。文件路径及 MD5 前后值完整保留。SSH 来源 IP 与被监控机器 IP 分开，筛选以实际 `login_time` 为准。机器自动由上报建立，页面可查询、修改别名/备注及删除；事件由 UDP 创建，页面可查询、更新处理状态/备注和删除。删除机器级联删除其事件与待发通知，Agent 后续上报会重新建立该机器。

新版 Agent 启动后立即发送 `heartbeat`，主控自动建立机器并显示在线；常驻模式每 30 秒独立发送心跳，不等待文件巡检结束。超过 `max(心跳周期×3, 30秒)` 未收到上报则显示“异常离线”，默认 90 秒，恢复接收自动上线。心跳只更新机器状态，不占用历史事件列表。页面每 15 秒自动刷新。

兼容旧 Agent 的每轮 `scan_summary` 上报，未收到新版心跳时仍用 `max(巡检周期×3, 120秒)` 判断，缺省周期 300 秒。新事件按 `(机器IP,event_id)` 去重，SSH 额外按来源记录 ID 去重；乱序旧巡检不会覆盖新的状态。升级数据库自动补充心跳字段，保留已有账号、密码和记录。

按内网场景部署，打通 Agent 到主控的 `55555/UDP`，不需要 UDP 认证、加密或手工注册。UDP 为尽力投递，没有 ACK 或持久重传；丢包时主控记录可能不完整，可回查 Agent 本地报告。完整格式见 [Agent 协议](docs/agent-protocol.md)。

## Webhook

页面支持多条通知 URL，逐条增删改、启停和测试。新增/编辑弹窗可以直接测试当前填写的 URL，不必先保存；测试结果展示实际发送正文、HTTP 状态、业务确认码和耗时。新告警与待发通知在同一事务提交后，由后台最多 4 个并行请求投递；失败从 5 秒开始指数退避，最多 1 小时，持续重试且重启后保留。暂停的地址停止自动投递，重新启用后继续待发项；测试按钮仍可主动向暂停地址发送一条测试消息。

默认 `feishu` 同时支持飞书和 Lark，使用 `msg_type: text` / `content.text`，与 Python 示例一致。官方 `open.larksuite.com` / `open.feishu.cn` 的 `/open-apis/bot/v2/hook/…` 地址会自动使用此格式，旧配置误选 `generic` 也会纠正，无需重建配置。API 也接受 `lark` 别名并归一为 `feishu`。`wecom` 使用企业微信文本格式；`generic` 为 JSON，包含 `event_id`、`kind`、`machine_ip`、`host`、`created_at`、`text`、`data`。

告警正文包含机器 IP、主机名、UTC 时间、模块/类型、目标、描述、变更前后值（有值时）和事件 ID，文件告警的前后值为对应 MD5，进程告警则保留原始实例数量等证据。仅 `alert` 自动发送；普通 SSH 登录、心跳和巡检摘要不会发送通知。

飞书/Lark 必须同时满足 HTTP 2xx 和 `code` / `StatusCode` 为数值 0；企业微信校验 `errcode=0`。通用格式也会识别这些确认码，非零值不再误报成功；没有确认码时仅说明 HTTP 已接受，仍需在接收端核实。拒绝重定向，单次超时 10 秒。失败在页面保留安全的状态码及排查提示，自动投递失败同时记录主控日志；不回显 URL 密钥或原始响应体。业务码成功表示机器人接口确认接收，不能证明群成员已看到消息。

Lark 配置必须使用目标群的自定义机器人 Webhook URL。正文固定包含“安全中心”，机器人配置了关键词时可使用该关键词；若启用了签名校验，本示例格式不包含 `timestamp/sign`，只有 URL 无法满足签名校验，需另行提供签名配置支持。机器人 IP 白名单应允许主控服务器的出口 IP。测试和自动告警均由主控发起。

发送语义为至少一次：若远端收到后、本地记录成功前进程中断，恢复后可能再发。请求携带 `Idempotency-Key: 机器IP:事件ID`，通用接收端可据此去重。仅配置创建后新收到的告警进入队列，历史记录不补发；重放相同 UDP 事件不会再次入队。修改 URL 后，尚未投递的项使用新地址；删除地址会删除对应队列。

通知格式与应答校验参考现有 `SEO权重监控/title-monitor/internal/master/webhook.go`。API 详见 [API 文档](docs/api.md)。数据库包含通知 URL，备份时请一并保护；推荐停止服务后备份整个数据目录，运行中不要只复制主 `.db` 而遗漏 WAL。
