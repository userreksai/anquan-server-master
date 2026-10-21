# 安全中心 · Master

## Agent age 配置加密

新增已登录管理员接口 `GET/POST /api/settings/agent-encryption`，沿用会话鉴权和同源校验。POST 请求只包含 `{"yaml":"配置原文"}`；响应包含 `ciphertext` 和 `filename: config.age`，GET 仅返回文件名。支持最大 4 MiB 单份 YAML 映射，检查语法与重复字段；Agent 启动时继续校验完整配置字段。

加密接口使用代码内置的 age X25519 公钥和 ASCII armor，不保存或记录本次加密的配置明文、密文，不提供解密接口。页面不传入也不显示任何密钥。无需公钥环境变量，传入自定义 recipient 会被拒绝。管理页面生产部署请使用 HTTPS，代理不要记录请求正文。

模板通过独立的 `GET/POST /api/settings/agent-config-template` 接口保存，原有 PUT 方法继续兼容。沿用登录鉴权、同源校验和 `Cache-Control: no-store`，POST/PUT 请求均为 `{"yaml":"配置原文"}`，校验最大 4 MiB 的单份 YAML 映射后，原样覆盖 SQLite 中唯一一份共享模板；返回 `{"yaml":"已保存原文"}`。GET 读取最近保存的内容，尚未保存时返回 `{"yaml":null}`，由前端提供内置示例。注释、缩进和换行会保留，跨浏览器、跨设备和重启均可恢复。只有显式存储模板会持久化 YAML 明文，加密不会更改模板。数据库启动时自动升级到 schema v11，保留共享模板、机器配置分配并增加安全组件事件、快照与 sudo 会话表；需配套更新前端与 Agent。

通用 Agent 代码内置配套固定私钥，不内嵌 YAML。将页面生成的 `config.age` 与配套新版 Agent 放在同一目录；配置变更只需重新加密替换，单次运行下次启动生效，常驻服务重启生效。首次迁移须更新 Agent 和 Master 并重新加密旧配置。源码持有者和节点 root 可恢复配置，固定密钥不提供对此类人员的保密保证。

Go 主控通过 `55555/udp` 接收 Anqu Agent 的巡检摘要、文件/进程告警及每次 SSH 登录，通过 `10110/tcp` 提供经过登录鉴权的管理 API，并监听 `55556/tcp`，供 Agent 主动连接后接收配置。配套 Vue 前端 `anquan-server-web` 使用 `10111/tcp`。

在页面“管理设置 → Age 配置加密”编辑 YAML，点击“下发配置”选择机器。主控将配置加密后按机器保存在 SQLite，并通过现有 TCP 长连接发送；离线机器重连时自动收到最近版本，主控重启后也会继续发送。Agent 校验、原子保存 `config.master.age` 并切换后确认，页面区分待下发、已应用和失败。未分配配置时使用可选本地 config.age，没有本地配置则保持等待。Agent 通过 ANQUAN_MASTER 独立连接配置主控，握手自动上报本机出口 IP；下发 YAML 的 server 列表控制全部 UDP 数据目标，裸 IP 使用 55555，不影响 TCP 配置连接。配置通道只允许可信 Agent 网络访问，Agent 不监听入站端口。接口与协议见 [API](docs/api.md) 和 [Agent 协议](docs/agent-protocol.md)。

SQLite 数据文件为 `/data/anquan/anquan.db`。第一次启动自动创建目录、表和 `admin` 账号，默认密码 **`admin1818.`**（含末尾英文句点）。再次启动保留原密码、会话及全部数据。密码使用 bcrypt，浏览器使用 HttpOnly / SameSite=Strict Cookie，会话有效期 24 小时。

## 主控软件下载管理

新版 Agent 的软件源、依赖包和 Tetragon 发布包可通过主控下载，复用现有 TCP 55556，无需新开 55557。页面“管理设置 → 软件下载管理”默认关闭；安装前临时开启，默认 15 分钟、最多 60 分钟，到期自动关闭，主控重启仍保持关闭。关闭立即终止活跃下载，Agent 安装完成主动释放会话。下载源及窗口时长保存在新增的 schema v10 设置表，升级前备份数据库。主控需有外网出口；该中继不缓存包。凭证、域名白名单、公网地址验证、并发和流量限制详见 [API](docs/api.md#主控软件下载管理) 与 [Agent 协议](docs/agent-protocol.md#软件包下载中继复用-tcp-55556)。

## Agent 远程更新

“管理设置 → Agent 程序更新”从主控默认 `/usr/local/anquan-agent/dist` 读取 `anquan` 和 `anquan.update.json`，点击“读取并打包”后自动生成只包含 `anquan` 的 tar.gz 快照，再选择在线机器下发。需要使用新版 Agent 仓库的 `anqu-build` 重新编译，构建器会同时输出版本、Linux 架构、SHA-256 和大小清单；Master 不执行待发布的程序，也不使用旧 `anquan.tar.gz` 作为更新来源。可通过 `ANQUAN_AGENT_DIST_DIR` 设置其他目录。

```sh
cd /usr/local/anquan-agent
git pull --ff-only
go run ./cmd/anqu-build -output ./dist/anquan -goos linux -goarch "$(go env GOARCH)"
# 原生 deploy.sh 默认以 anquan 用户运行主控。root 编译后赋予该组读取权限。
sudo chgrp anquan ./dist/anquan ./dist/anquan.update.json
sudo chmod 0750 ./dist/anquan
sudo chmod 0640 ./dist/anquan.update.json
```

上级 `/usr/local/anquan-agent` 与 `dist` 目录还需允许 `anquan` 用户遍历；如果使用受限目录，可为该用户配置目录组执行权限。Docker 的容器 UID/GID 与宿主机账号独立，需按实际容器 UID/GID 设置读取权限。

每次只展示一个已准备版本，下发必须精确匹配页面确认的压缩包摘要；仅允许支持更新、在线、相同 Linux/amd64 或 Linux/arm64 平台、且当前正式版本低于目标版本的机器。批次全量校验，有一台不符合时不创建任何任务；同一台机器一次只允许一个更新任务。不支持降级、开发版本或跨架构安装。版本 0.7.2 和更早的 Agent 没有接收更新的代码，首次须手动安装支持此功能的新版，此后才可在页面选机更新。

Agent 主动通过原 TCP 55556 建立独立下载连接，控制连接继续传配置和心跳，无需新增端口。更新包是管理员已选定的主控本地文件，与“软件下载管理”的临时公网软件源代理开关独立。每个任务使用 10 分钟有效的随机下载凭证，绑定当前控制连接和来源地址；全局最多 8 个下载，每台最多 1 个，传输最多 2 分钟。仅下载并不表示更新成功，页面会显示等待、下载、重启、成功、失败或已回滚；必须由目标版本重新连接并报告匹配的任务、平台及二进制摘要后才确认成功。

Master 使用持久 Ed25519 密钥签名发布描述，Agent 首次连接按主控端点固定公钥；首次连接仍应通过可信内网完成。主控数据目录的 `agent-updates/` 保存发布快照，SQLite schema v11 保存签名密钥、当前版本和机器任务。重启使未完成的等待/下载任务失败，重启中的任务仍需新程序回执。再次准备版本时清理不再用于当前版本或有效任务的旧快照。升级前对 SQLite 做一致性备份并保留 `agent-updates/`；签名密钥丢失会导致已固定公钥的 Agent 拒绝更新，回退旧 Master 应恢复升级前备份，不要手动降低 `user_version`。

Docker Compose 已将 `/usr/local/anquan-agent/dist` 同路径只读挂入 Master，发布快照继续写 `/data/anquan/agent-updates`。容器以 `anquan` 用户运行，需要该目录可遍历，`anquan` 和 `anquan.update.json` 可读取；默认 root 编译产物若是 `0700`，需按容器实际 UID/GID 配置目录和文件的组读取权限（例如目录 `0750`、文件 `0640`），挂载只读不会自动赋予读取权限。原生服务同样检查运行用户权限。接口及帧格式见 [API](docs/api.md#agent-远程更新) 与 [Agent 协议](docs/agent-protocol.md#agent-远程更新复用-tcp-55556)。

## 安全组件配置与采集初版

页面“组件与主机策略 → 事件降噪与巡检保留”提供主控全局设置，保存后立即用于新上报，无需下发配置或升级 Agent。可按 Tetragon 类型屏蔽进程执行（`process_exec`）、进程退出（`process_exit`）等事件；被屏蔽的新事件不入库、不通知，仍正常确认接收并更新机器在线状态，其他来源的同名事件不受影响。默认不屏蔽任何类型；已有历史记录不会因勾选屏蔽而删除。

“安全运行事件最低级别”默认选择“警告及以上”，普通 auditd exec、sudo 等信息事件不再持续入库，可按需切到 `info` 或 `debug` 保存全量运行证据。旧 Agent 固定的 `Linux audit exec` 普通执行记录，在原始证据明确只有内建审计 `key=anquan_exec` 时，即使误标 warning 也按有效级别 info 判断，避免登录产生多条执行通知；自定义/多个 key、缺少 key 证据、自定义消息及 error/critical 保留原级别。通知投递前按当前策略复核，不再满足条件的积压任务取消，保留历史并且不记成 Webhook 成功。SSH 登录通知、传统告警、操作命令与显式 sudo 文件录制不受此运行事件阈值影响。

组件状态每次只更新机器最新快照，正常稳定状态不追加历史；首次异常、异常内容发生有意义变化、或恢复正常时分别记录一次。同一异常重复报告和应用时间/队列/库存变化不会重复入库，组件状态也不发送 Webhook。该主控规则兼容旧 Agent 的每 30 秒报告；新版 Agent 正常稳定时每 5 分钟补发快照，异常变化和恢复及时上报。

巡检记录（`scan_summary`）默认只保留最近 24 小时，也可选 12 小时。主控启动时和每分钟按事件发生时间分批删除过期巡检记录，每批最多 1000 条；新设置最迟在下一轮清理生效。安全告警、SSH 登录、操作命令、安全运行事件和组件状态不按这个期限删除，机器的最新巡检摘要和在线状态也保留。删除后的数据库页面可用于后续写入，不会自动执行阻塞式 `VACUUM` 来缩小数据库文件。

新增 `security_event`（原生文件监控、auditd、可选 Tetragon、sudo、主机策略）与 `component_status`（组件状态）数据，继续使用既有 UDP 55555 上报和事务提交后 ACK；配置继续通过既有 TCP 55556 下发，管理 API 继续使用 10110。Master 无需安装这些主机组件，也不新增服务端端口。

前端安全配置表单通过 `POST /api/settings/security-profile/compose` 将配置合并到共享 Agent YAML 的 `security` 节点，再复用原有模板保存、age 加密与按机器下发接口。该接口只合成配置，不保存、不下发。配置交付状态与各组件实际安装/应用状态分别查看，组件安装或 reload 失败会在状态中报告。

`security.native_fim.capture_created_content` 默认开启，配套新版 Agent 在监控基线建立后，对新建的非敏感文本文件留存已观察到的内容版本，并在修改和删除事件中附带可用的前后内容。显式设置为 `false` 可关闭此自动留存；`report_changes` 仍默认关闭，独立控制已有文件的文本差异。内容受 `max_diff_bytes` 与传输大小限制，二进制、敏感路径、截断及未捕获状态在事件明细中明确标注。此功能不扩大监控路径，也不能恢复 Agent 尚未读取即已消失的文件。

原生文件事件保持 `native_fim/file_change` 协议，通过 `details.change` 区分新增、修改、删除或缺失；正文和前后元数据保存在事件 `details` 中。聊天通知在同一条消息中显示具体操作、路径、内容留存摘要，以及变更前、变更后内容预览；每侧最多 512 个 UTF-8 字节，截断会明确标记，完整已留存版本在平台事件详情查看。空文件、不适用、敏感、二进制、关闭留存和未捕获状态分别显示，不把不应预览的文本带入通知；通用 Webhook 的 `data` 继续保留完整原始事件。Agent 聚合同一写入过程并排除编辑器临时文件后，一条变更上报只生成一个通知任务；Master 对相同事件 ID 的确认补传继续去重，不按时间窗口丢弃不同变更。

`GET /api/security/status` 返回每台机器最新组件快照；`GET /api/events?type=security_event` 查看通过主控筛选的审计事件。组件状态不触发 webhook；通过当前入库策略且有效级别为 `warning/error/critical` 的安全事件进入现有持久通知队列。快照按 Agent 事件时间更新，延迟上报不会覆盖较新状态。

`security.sudo.grants` 可以配置受管 sudo 授权，包含本机用户、目标身份、绝对路径命令及是否免密。Agent 仅更新自己的片段，不移除系统现有的广泛授权；因此配置少量 grants 不代表已撤销用户原有权限。具体字段、字符限制及示例见 API 文档。

按需开启 `security.sudo.upload_io` 后，sudo 会话分片存入独立表，不把 Base64 大字段重复写入普通事件表。`GET /api/security/sudo-sessions` 查看会话及文件完整性，`GET /api/security/sudo-sessions/{id}/files/{file}` 下载完整的原始会话文件，供 `sudoreplay` 使用；初版不提供网页播放器。单片最多 24 KiB，单文件最多 64 MiB，原始录制内容可能包含敏感输入输出，应按实际需求启用。当前文件随机器删除级联删除，尚未提供自动保留期限清理，需要监测数据库容量并制定备份/清理策略。

启动时自动升级到 schema v11，保留既有账号、会话、机器、事件、通知队列、共享模板与配置分配。升级前备份 SQLite 数据；旧 Master 无法打开升级后的数据库。Agent 上报源继续沿用现有网络信任边界，不增加新的身份认证通道。

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

脚本编译、启动服务并等待健康检查通过，监听 `10110/TCP`、`55555/UDP` 和 `55556/TCP`，首次自动初始化 `/data/anquan`。对 Agent 开通 UDP 55555 和 TCP 55556，对前端服务器开通 TCP 10110。服务器重启后服务自动启动。Go 安装在 `/opt/anquan-tools/go1.27.1`，不覆盖系统现有工具链，下载后验证[官方 SHA256](https://go.dev/dl/?mode=json&include=all)。

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
| `--tcp` | `ANQUAN_TCP_ADDR` | `:55556` |
| `--secure-cookie` | `ANQUAN_SECURE_COOKIE` | `false`；HTTPS 部署可设为 `true` |
| `--public-origin` | `ANQUAN_PUBLIC_ORIGIN` | 空；带 Origin 的写请求沿用 HTTP Host 校验 |

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

## 本机 Nginx 与模板保存 403 修复

主控与 Nginx 在同一台服务器时，浏览器仍使用网站同源 `/api/`；Nginx 将请求发送到本机 `127.0.0.1:10110`，主控直接更新自己的 SQLite。模板保存不调用 `sa.sa.ops.tw`，不连接 Agent，也不经过 Agent TCP/UDP 中转。浏览器 URL 显示 `https://prodsafety.ops.tw/api/...` 是管理入口地址，不能将前端地址改为浏览器的 `localhost`。

设置 `ANQUAN_PUBLIC_ORIGIN=https://prodsafety.ops.tw` 后，主控对带 Origin 的写请求严格校验该公开来源的协议、主机名和端口，即使代理将 HTTP Host 改为本机上游也可正常保存。只允许一个完整的 HTTP(S) Origin，不带末尾 `/`、路径、查询、片段、用户名或通配符。请使用浏览器实际发送的 Origin，HTTPS 默认端口应省略 `:443`，HTTP 默认端口应省略 `:80`；非默认端口必须填写。配置为空时保持原有 Host 校验。无效配置在打开数据库和监听端口前直接报错。

跨站请求拒绝、登录鉴权、JSON 内容类型校验和 Cookie 保护继续生效；主控不会信任 `X-Forwarded-Host` 或 `Forwarded` 来放宽来源。模板依旧保存在现有 `ANQUAN_DATA_DIR` 下的数据库，不移动或重建数据库。

对于既有 `anquan-master` systemd 服务，更新主控程序后复制专用配置：

```sh
sudo install -m 0644 deploy/local-api.env.example /etc/anquan-master-local-api.env
sudo install -d -m 0755 /etc/systemd/system/anquan-master.service.d
sudo install -m 0644 deploy/local-api.conf /etc/systemd/system/anquan-master.service.d/local-api.conf
sudo systemctl daemon-reload
sudo systemctl restart anquan-master
curl -fsS http://127.0.0.1:10110/healthz
```

`local-api.conf` 追加读取 `/etc/anquan-master-local-api.env`，只覆盖 HTTP 监听和公开 Origin；原 `/etc/anquan-master.env` 中的数据库目录、Agent TCP/UDP 监听等设置继续生效。上述示例仅用于原生 systemd 主控，Docker Compose 不应将容器 HTTP 监听改为 loopback。

在同机 Nginx 的现有 HTTPS 网站 `server` 块中，将 `/api/` 上游指向本机并保留浏览器 Host：

```nginx
location /api/ {
    proxy_pass http://127.0.0.1:10110;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 5m;
    proxy_read_timeout 30s;
}
```

已有 `/api/` 块时替换该块，不重复定义。检查配置后执行 `sudo nginx -t && sudo systemctl reload nginx`。若使用前端仓库的原生部署脚本，请显式传入 `127.0.0.1:10110` 覆盖曾保存的远程上游。后端返回 JSON `请求来源不受信任` 时检查公开 Origin；若响应是 HTML 403，则可能由 Nginx/WAF 拦截或入口改写了后端错误，应检查网站的 `limit_except`、访问控制、PUT 拦截及错误页配置，并结合主控日志确定请求是否到达。

### 无法修改中转入口时，直接在主控本机存储模板

管理页面默认使用 POST 保存模板，保留 PUT 兼容。两种方法调用相同保存逻辑且接受相同登录、来源和 JSON 校验。入口若只拦截 PUT，POST 可通过正常网站入口提交；若所有写请求都在中转层被拒绝，网页仍无法直接操作主控磁盘，此时可以在主控服务器使用本地命令：

```sh
# 将待保存 YAML 放到主控本地文件，如 /root/agent-template.yaml。
# 在 root shell 执行，重定向由 root 打开文件；数据库操作以服务账号运行。
sudo -u anquan /usr/local/bin/anquan-master save-agent-template \
  --data-dir /data/anquan --yaml-stdin < /root/agent-template.yaml
```

使用实际主控进程对应的数据库目录和服务账号。命令只读取 stdin 并更新既有 `anquan.db` 的共享模板，不发起 HTTP/Agent 连接、不解析中转域名、不启动监听端口，也不打印模板明文。支持最大 4 MiB 的单份 YAML 键值映射；原文注释、缩进和换行保留。无 `--yaml-stdin`、非法/过大/多文档输入或多余参数会失败，先前模板保持原样。

命令要求该目录已有正常初始化的主控 SQLite 数据库和模板表，不会创建数据库目录、空库、管理员账号或迁移数据库结构。请勿更换 `--data-dir` 来新建另一份库。以同一服务账号执行可保持数据库、WAL/SHM 的访问权限，运行中的主控能立即读到已提交的模板，无需停服务或重启。成功后网页通过现有 GET 接口刷新即可载入，不需要再次点击“存储模板”。现有密码、登录会话、机器、事件及配置下发记录保持不变。

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
```

机器以 IP 为主键，保存 hostname、来源 IP、别名、备注及最近活动。新版 Agent 自动获取连接配置主控时 TCP `LocalAddr` 的本机出口 IP，在 hello 的 `ip` 和 `reported_ip` 中报告同一地址，并用于全部 UDP 上报；无需手工 agent_ip，也不调用公网 IP 查询服务。主控以该地址区分机器和配置连接，独立保存实际 TCP/UDP 对端为 `source_ip`。例如两个 Agent 经 `172.22.240.6` 中转后，可分别登记为 `172.22.0.27`、`172.22.0.28`，中转地址只作为来源记录。多网卡机器使用操作系统到配置主控的路由出口，容器内 Agent 使用容器网络地址。

主控保留旧 `discover_ip` 握手的来源地址语义和旧显式 IP 协议。本次不改变数据库结构，不自动搬移或删除已经以中转 IP 聚合的历史记录；升级 Master 和 Agent 后，在页面选择新的本机 IP 重新下发配置。原聚合记录可能包含多台机器的历史，应确认后再处理。不同网络中重复的本机 IP 仍受 IP 主键约束，不能自动区分为独立机器；报告 IP 不构成节点认证，TCP/UDP 端口继续限可信 Agent 网络访问。

事件保存 `event_id`、机器 IP、类型、发生时间、接收时间、原始 data、处理状态和备注。文件路径及 MD5 前后值完整保留。SSH 来源 IP 与被监控机器 IP 分开，筛选以实际 `login_time` 为准。机器自动由上报建立，页面可查询、修改别名/备注及删除；事件由 UDP 上报或主控离线检测创建，页面可查询、更新处理状态/备注和删除。删除机器级联删除其事件、待发通知及离线状态，Agent 后续上报会重新建立该机器。

新版 Agent 启动后立即发送 `heartbeat`，主控自动建立机器并显示在线；常驻模式每 30 秒独立发送心跳，不等待文件巡检结束。超过 `max(心跳周期×3, 30秒)` 未收到上报则显示“异常离线”，默认 90 秒，恢复接收自动上线。心跳只更新机器状态，不占用历史事件列表。页面每 15 秒自动刷新。

主控启动时立即检查已登记机器，随后每秒独立检查异常离线，不依赖浏览器打开或 Agent 发告警。每台机器的每次持续离线只生成一条“机器异常离线”告警，并向所有已启用通知地址各入队一次；持续离线、Master 重启、修改或删除该告警都不会重新生成。收到任何有效上报后恢复在线并重新允许通知，下次离线再生成一条。升级时已经离线的机器同样会通知一次。

离线事件、持久去重状态及通知队列原子提交，检测产生的事件不会刷新机器最后上报时间。通知暂未配置或暂停时仍保存离线告警；持续离线期间新增或重新启用通知地址，会为尚未入队的该地址补一条。恢复后不补发给后来启用的地址，已入队的失败通知继续按原策略重试。

兼容旧 Agent 的每轮 `scan_summary` 上报，未收到新版心跳时仍用 `max(巡检周期×3, 120秒)` 判断，缺省周期 300 秒。新事件按 `(机器IP,event_id)` 去重，SSH 额外按来源记录 ID 去重；乱序旧巡检不会覆盖新的状态。升级数据库自动补充心跳字段，保留已有账号、密码和记录。

操作命令使用 `command_history` 事件，保留发生时间、用户、终端、完整命令、来源日志和字节位置；`/api/events?type=command_history` 支持现有筛选、分页和关键字搜索。正常命令不触发 webhook。发生时间取 `data.command_time`，接收时间另存。相同文本在同一秒执行多次仍分别保留，重传按机器与来源记录 ID 去重。

启动自动迁移 SQLite 到 schema v11，保留离线状态、共享模板、事件、备注、通知配置、队列、重试信息、机器配置分配和应用确认状态，并新增安全组件事件、快照及 sudo 会话数据。离线通知只需更新 Master，Web 更新用于中文标签及说明，Agent 无需修改。模板存储需同时更新 Master/Web。启用 Agent v0.7.0 的安全组件或 v0.6.0 的 `history` 时仍应先更新 Master/Web。旧二进制不支持 schema v11，回退需要使用升级前的数据库备份。

按内网场景部署，打通 Agent 到主控的 `55555/UDP` 及返回流量，不需要 UDP 认证、加密或手工注册。巡检、登录、摘要和心跳为尽力投递。命令采集请求 ACK，主控成功落库后回复，重复报文也确认；Agent 持久保留未确认批次并重试。完整格式见 [Agent 协议](docs/agent-protocol.md)。

## Webhook

页面支持多条通知 URL，逐条增删改、启停和测试。新增/编辑弹窗可以直接测试当前填写的 URL，不必先保存；测试结果展示实际发送正文、HTTP 状态、业务确认码和耗时。新告警、SSH 登录与各自待发通知在同一事务提交后，由后台最多 4 个并行请求投递；失败从 5 秒开始指数退避，最多 1 小时，持续重试且重启后保留。暂停的地址停止自动投递，重新启用后继续待发项；测试按钮仍可主动向暂停地址发送一条测试消息。

默认 `feishu` 同时支持飞书和 Lark，使用 `msg_type: text` / `content.text`，与 Python 示例一致。官方 `open.larksuite.com` / `open.feishu.cn` 的 `/open-apis/bot/v2/hook/…` 地址会自动使用此格式，旧配置误选 `generic` 也会纠正，无需重建配置。API 也接受 `lark` 别名并归一为 `feishu`。`wecom` 使用企业微信文本格式；`generic` 为 JSON，包含 `event_id`、`kind`、`machine_ip`、`host`、`created_at`、`text`、`data`。

告警正文包含机器 IP、主机名、北京时间（UTC+8）、模块/类型、目标、描述、变更前后值（有值时）和事件 ID，文件告警的前后值为对应 MD5，进程告警则保留原始实例数量等证据。安全组件告警的来源、类型、级别及已知事件描述显示中文，兼容旧 Agent 的英文消息；未知描述和原始命令保留原文。`ssh_login` 同样自动通知，标题为“安全中心 SSH 登录通知”，包含机器 IP、主机名、登录用户、来源 IP、终端、认证方式、真实登录时间（北京时间 UTC+8）和事件 ID，缺失字段显示 N/A。所有通知正文时间按 `YYYY-MM-DD HH:mm:ss` 显示，固定转换为 UTC+8，不依赖主控机器的系统时区；事件存储和通用 Webhook 的原始数据保持原有时间语义。心跳、巡检摘要和普通操作命令不发送通知。

机器离线通知使用中文标题“安全中心：机器异常离线”，正文显示机器 IP、主机名、可用的机器别名、状态、最后上报时间、离线判定时间、超时秒数和事件编号，时间明确标注北京时间 UTC+8，不显示 `machine / abnormal_offline` 等内部类型。支持现有 Lark/飞书、企业微信和通用 webhook。一次离线只创建一个通知任务，投递失败会重试；远端已接收但确认丢失等情况仍遵循下文的至少一次投递语义。

飞书/Lark 必须同时满足 HTTP 2xx 和 `code` / `StatusCode` 为数值 0；企业微信校验 `errcode=0`。通用格式也会识别这些确认码，非零值不再误报成功；没有确认码时仅说明 HTTP 已接受，仍需在接收端核实。拒绝重定向，单次超时 10 秒。失败在页面保留安全的状态码及排查提示，自动投递失败同时记录主控日志；不回显 URL 密钥或原始响应体。业务码成功表示机器人接口确认接收，不能证明群成员已看到消息。

Lark 配置必须使用目标群的自定义机器人 Webhook URL。正文固定包含“安全中心”，机器人配置了关键词时可使用该关键词；若启用了签名校验，本示例格式不包含 `timestamp/sign`，只有 URL 无法满足签名校验，需另行提供签名配置支持。机器人 IP 白名单应允许主控服务器的出口 IP。测试和自动告警均由主控发起。

发送语义为至少一次：若远端收到后、本地记录成功前进程中断，恢复后可能再发。请求携带 `Idempotency-Key: 机器IP:事件ID`，通用接收端可据此去重。Agent 上报告警和 SSH 登录仅在配置已启用且事件首次入库时进入队列，数据库中已有记录不补发；首次采集或延迟上报的登录只要首次入库也会通知，正文保留实际发生时间。主控生成的持续离线告警另按上述规则为后来启用的地址补充任务。重复事件或相同来源 ID 的登录不会再次入队，同一秒的不同登录分别通知。修改 URL 后，尚未投递的项使用新地址；删除地址会删除对应队列。

通知格式与应答校验参考现有 `SEO权重监控/title-monitor/internal/master/webhook.go`。API 详见 [API 文档](docs/api.md)。数据库包含通知 URL，备份时请一并保护；推荐停止服务后备份整个数据目录，运行中不要只复制主 `.db` 而遗漏 WAL。
