# HTTP API

基址：`http://主控IP:10110`。生产浏览器使用前端同源 `/api` 代理。除登录、健康检查外均须登录 Cookie；JSON 写请求使用 `Content-Type: application/json`。默认带 `Origin` 的写请求必须匹配 HTTP `Host`，反向代理需保留原始 Host（包括端口）。设置 `ANQUAN_PUBLIC_ORIGIN` 或 `--public-origin` 后，只接受该明确来源的协议、主机名和端口，不信任代理转发头；跨站请求仍拒绝。本机 Nginx 可将 `/api/` 直接转发到 `127.0.0.1:10110`，模板保存直接写主控本机 SQLite。

错误统一 `{ "message": "错误原因" }`，未登录为 401，非法参数 400，记录不存在 404。所有返回时间均为带时区 ISO8601。机器和事件列表返回 `{items: [], total: 0, page: 1, page_size: 20}`，页大小 1–100。webhook 列表返回数组。

| 方法 | 路径 | 用途 / 请求体 |
|---|---|---|
| GET | `/healthz` | 数据库健康检查 |
| POST | `/api/auth/login` | `{username,password}`；首次 admin/admin1818. |
| GET | `/api/auth/me` | `{username:"admin"}` |
| POST | `/api/auth/logout` | 注销当前会话 |
| PUT | `/api/auth/password` | `{current_password,new_password}`，使全部会话失效 |
| GET | `/api/settings/event-policy` | 读取主控全局 Tetragon 屏蔽与巡检保留设置 |
| PUT | `/api/settings/event-policy` | `{tetragon_ignored_kinds: string[],scan_summary_retention_hours: 12 或 24}`，完整替换设置 |
| GET | `/api/overview` | 机器/在线机器/事件/告警/待处理/登录/待投递数量 |
| GET | `/api/machines` | `q,page,page_size` 搜索 IP、主机名、别名、备注 |
| GET | `/api/machines/{ip}` | 单台机器 |
| PATCH | `/api/machines/{ip}` | `{alias?,notes?}` |
| DELETE | `/api/machines/{ip}` | 删除机器、其记录及通知队列 |
| GET | `/api/events` | `machine_ip,q,type,status,from,to,page,page_size` |
| GET | `/api/events/{id}` | 单条事件（整数数据库 ID） |
| PATCH | `/api/events/{id}` | `{status?,notes?}`，状态为 open/resolved |
| DELETE | `/api/events/{id}` | 删除记录与其通知队列 |
| GET | `/api/webhooks` | 通知配置数组 |
| POST | `/api/webhooks` | `{name,url,format?,enabled?}` |
| PUT | `/api/webhooks/{id}` | 同上，完整替换配置 |
| DELETE | `/api/webhooks/{id}` | 删除通知配置和队列 |
| POST | `/api/webhooks/{id}/test` | 测试已保存配置；空请求体或 `{message?}`；发送失败 502 |
| POST | `/api/webhooks/test` | 测试当前表单 `{url,name?,format?,enabled?,message?}`，不保存；发送失败 502 |

`type` 为 `alert`、`ssh_login`、`command_history`、`scan_summary`、`security_event`、`component_status`，为空表示全部；`q` 按字面文本搜索机器 IP、主机名、data 和备注，`%` / `_` 不当作通配符。`machine_ip` 为完整 IP；URL 路径里的 IPv6 应编码。`from` 和 `to` 为包含边界的 ISO8601（必须带时区），开始不得晚于结束。按事件发生时间倒序、整数 ID 倒序稳定分页；登录事件采用 `data.login_time`。发生新事件时使用偏移分页的不同页之间仍可能移动，刷新可查看最新记录。

机器字段：`ip,host,source_ip,reported_ip,alias,notes,first_seen,last_seen,last_event_at,last_summary,interval_seconds,heartbeat_interval_seconds,event_count,alert_count,open_alert_count,login_count,online,status,offline_after_seconds`。`status` 为 `online` / `abnormal_offline`，`offline_after_seconds` 给出当前机器的离线阈值。机器由首次心跳/事件自动建立，后续上报自动恢复在线；心跳不增加事件数量。

新版 Agent 自动报告连接配置主控的本机出口 IP，主控以规范化后的报告地址作为 `ip` 和配置下发机器标识，保存为 `reported_ip`。`source_ip` 独立记录主控看到的 TCP/UDP 对端，经中转时可为代理地址；`host` 只是 Agent 主机名，不用于推导 IP。不同报告 IP 经同一中转时分别建立机器记录，旧聚合记录不自动迁移。旧发现模式和缺少报告 IP 的旧 UDP 报文保持原有来源地址语义，详见 Agent 协议。

事件字段：`id,event_id,machine_ip,host,type,time,received_at,status,notes,data`。`data` 保留 Agent 上报或主控检测的证据，不接受经 HTTP 修改检测证据。

事件策略接口沿用管理员登录、同源与 JSON 校验，GET 和 PUT 成功返回相同对象，默认 `{"tetragon_ignored_kinds":[],"scan_summary_retention_hours":24}`。PUT 必须同时提供两个字段，不允许 null、重复类型、未知字段或其他保留时长；失败不覆盖原设置。设置持久保存在主控数据库，重启后保留。

可屏蔽的 Tetragon 类型为 `process_exec,process_exit,process_kprobe,process_tracepoint,process_loader,process_uprobe,process_lsm,process_usdt,runtime`。只过滤 `security_event` 中 `data.source=tetragon` 且 `data.kind` 匹配的未来上报，在入库前生效，不生成记录和通知任务；仍更新机器在线信息并在事务提交后 ACK，避免 Agent 重试积压。其他来源同名事件、解析错误等诊断及已有历史记录保留；清空数组可恢复记录新事件。

巡检保留仅针对 `scan_summary`，按事件 `time` 严格早于“当前时间减 12/24 小时”的记录清理，边界记录保留，不按 `received_at` 计算。主控启动立即清理，以后每分钟运行，每批至多 1000 条并分批处理积压；保存设置不阻塞等待全量清理。过期巡检的处理备注也随记录删除，机器 `last_summary` 和在线状态不受影响。其他事件类型及其通知队列不按此期限删除。

主控每秒检测机器离线，生成 `type: alert`、`data.module: machine`、`data.kind: abnormal_offline` 的事件。`data` 包含 `target`（机器 IP）、中文 `message`、可选 `alias`、`last_seen`、`offline_since`、`detected_at` 和 `offline_after_seconds`。外层 `time` 为离线阈值到达时间，`received_at` 为检测时间。每次持续离线仅生成一次，重启及删除事件不重置；有效上报恢复在线后，下次离线才创建新事件。所有启用地址各入队一次，失败持久重试；持续离线期间后来启用的地址会补充尚未存在的任务。

Webhook 字段：`id,name,url,format,enabled,created_at,updated_at,last_error,last_success_at,pending_count`。`format` 可选 `feishu`（默认）、`wecom`、`generic`，`enabled` 默认 true；名称最多 128 字节，URL 仅允许 HTTP(S)，禁止 URL 中的用户名密码与片段。可配置多个独立通知地址。

`feishu` 同时用于飞书和 Lark，请求格式为 `{"msg_type":"text","content":{"text":"告警正文"}}`；API 接受 `lark` 别名。官方 Lark/飞书 `/open-apis/bot/v2/hook/…` 地址自动归一为 `feishu`，读取旧配置和发送已有待发任务时同样生效。

两种测试接口实际调用同一发送器。`message` 最多 10000 字节，省略时发送安全中心默认测试文案；草稿的 `name` 可省略，`enabled` 不限制主动测试。测试不产生告警记录或重试队列，只有已保存配置测试会更新 `last_error/last_success_at`。成功 HTTP 200，发送失败 HTTP 502，均返回：

```json
{
  "success": true,
  "message": "Webhook 接收端已确认接收测试消息，请到对应群查看",
  "format": "feishu",
  "http_status": 200,
  "business_code": 0,
  "duration_ms": 120,
  "text": "【安全中心告警】\n机器 IP：127.0.0.1\n主机：安全中心主控（测试）\n..."
}
```

`text` 是本次发送器构造的正文（连接失败时为尝试发送的正文），与发送 JSON 中的文本相同。`http_status` 在收到 HTTP 响应后才存在；`business_code` 在解析到数值业务码后才存在，判断时不能把 0 当作缺失。`duration_ms` 总是返回。参数错误/未登录等请求未进入发送器的情况，仍返回原有 `{message}` 错误结构。

Lark/飞书即使 HTTP 200，业务码非零、缺失或无效仍返回 `success:false`、HTTP 502；企业微信要求 `errcode=0`。`generic` 检测到 `code/StatusCode/errcode` 时同样要求数值 0；没有业务码时 HTTP 2xx 表示请求已接受，`message` 会说明无法确认业务接收。前端应显示实际消息和响应信息，不应仅凭 HTTP 200 或缺少响应字段回退为“发送成功”。完整 URL 和原始接收端响应不包含在诊断中。

自动通知正文示例（`before/after` 有值时才追加，时间固定为北京时间 UTC+8）：

```text
【安全中心告警】
机器 IP：10.20.30.40
主机：node-a
类型：文件监控（files） / 修改（modified）
目标：/etc/app.conf
时间（北京时间 UTC+8）：2026-10-06 16:00:00
内容：监控文件已修改
变更前：900150983cd24fb0d6963f7d28e17f72
变更后：d41d8cd98f00b204e9800998ecf8427e
事件 ID：alert-example
```

组件告警的来源、类型和级别使用中文标签并保留协议标识，例如“系统策略（policies）”“策略合规检查（policy_check）”“警告（warning）”。已知 Agent 固定英文消息在通知正文中显示为中文，例如 `Host policy compliance checked` 显示为“已完成主机策略合规检查”；自定义消息和未知诊断原样保留。普通告警、组件告警、SSH 登录和机器离线通知的正文时间均固定转换为北京时间 UTC+8，不依赖主控系统时区；API 原始事件时间和 `data` 不受通知展示转换影响。

新入库的 `alert` 和 `ssh_login` 发往当时已启用的配置，事件与通知队列在同一事务提交。数据库已有记录不补发，重复上报不重复入队；延迟/补读登录首次入库时仍会通知，时间取真实 `login_time`。普通命令、巡检摘要和心跳不发送。测试成功不创建配置，草稿测试后仍需保存才能接收后续通知。

总览字段：`machines,online_machines,events,alerts,open_alerts,ssh_logins,pending_notifications`。待通知数量包括已暂停地址的未发送记录。

## 共享 Agent YAML 模板

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/settings/agent-config-template` | 返回 `{"yaml":"最近保存的原文"}`；尚未保存时为 `{"yaml":null}` |
| POST | `/api/settings/agent-config-template` | 默认保存方法，请求 `{"yaml":"配置原文"}` |
| PUT | `/api/settings/agent-config-template` | 兼容原保存方法，与 POST 相同处理 |

POST/PUT 均要求管理员登录、同源校验及 `application/json`。最大 4 MiB、单份 YAML 键值映射，拒绝重复字段、多文档和无效语法；保留原文注释、缩进和换行。成功 HTTP 200 返回已保存原文，只原子覆盖本机 SQLite 中唯一的共享模板，不连接 Agent，不影响配置下发任务。未登录为 401，来源拒绝为 403，非法输入为 400，失败不覆盖原模板。

如中转入口拒绝网页写请求且无法调整，可在主控本机通过 `anquan-master save-agent-template --data-dir /data/anquan --yaml-stdin` 输入 YAML。该命令使用同一校验和保存逻辑，限既有初始化数据库；不进行 HTTP 请求、不创建或迁移数据库、不输出模板内容。建议以主控服务账号执行，保存后 GET 读取立即生效。具体文件重定向流程见 README。

## 按机器下发 Agent 配置

`GET /api/settings/agent-config-deliveries` 返回 `{items:[...]}`，包含全部已登记机器。每项字段为 `machine_ip,host,alias,connected,revision,status,error,updated_at,applied_at`。`connected` 表示 TCP 配置连接，独立于 UDP 心跳在线状态；`status` 为 `unassigned`（未分配）、`pending`（等待连接或确认）、`applied`（Agent 已应用并确认）、`failed`（Agent 拒绝并返回错误）。GET 不返回配置正文。

`POST /api/settings/agent-config-deliveries` 请求：

```json
{"yaml":"output_dir: /usr/local/anqu\nlogin: {enabled: false}\n", "machine_ips":["192.0.2.10","192.0.2.11"]}
```

沿用管理员登录、JSON、同源校验。YAML 最大 4 MiB，必须是单份键值映射；机器列表必须非空且已登记。主控加密后在一个事务中覆盖所选机器的最新分配，返回 `{items:[所选机器的状态]}`。HTTP 200 表示主控已保存；是否在节点生效须查看后续 `applied` 确认。离线或旧版 Agent 保持待下发，新版 Agent 连接后自动投递。旧版本 ACK 不会覆盖更新版本状态。共享模板的存储与下发各自独立。

Agent 使用自己平台上的完整配置校验，校验或配置切换失败返回 `failed`，保留当前有效配置；修正 YAML 后再次下发。数据库自动迁移到 schema v8，保留已有机器、事件、账号、通知和模板；回退旧 Master 前使用升级前备份。

## 安全组件表单与状态

沿用管理员 Cookie、JSON、同源检查、`Cache-Control: no-store`；不改变管理端口和配置分发通道。

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/settings/security-profile/defaults` | `{security:{...}}`；表单基础范例，非已应用配置 |
| POST | `/api/settings/security-profile/compose` | `{yaml:string,security?:object}`，返回 `{yaml:string,security:object|null}` |
| GET | `/api/security/status` | `{items:[{machine_ip,host,time,received_at,data}]}`；可选 `machine_ip` 精确筛选 |
| GET | `/api/security/sudo-sessions` | `machine_ip,page,page_size`；分页返回 sudo 录制会话 |
| GET | `/api/security/sudo-sessions/{id}/files/{file}` | 下载完整原始会话文件；缺失 404，未收齐 409 |

compose 省略 `security` 时只解析并返回原文及当前安全配置；配置中没有该节点则 `security:null`。提供 `security` 时按对象深合并，数组及 `policies.sysctl` 整体替换，因此删除数组项或内核参数可生效。未涉及的节点、注释与自定义顶层字段保留；合成时规范化为两空格缩进。拒绝无效类型、新增/改写的未知安全字段、重复键、多文档、非字符串映射键，以及无法安全编辑的 YAML 锚点/别名；已存在的未知字段可以原样保留。最大 YAML 4 MiB；失败不改变任何模板或机器配置。compose 不执行保存、加密或下发，后续复用现有接口。

初版字段与基础范例：

```yaml
security:
  enabled: true
  install_missing: true
  poll_interval_seconds: 2
  status_interval_seconds: 30
  max_queue_events: 10000
  auditd:
    enabled: true
    audit_exec: true
    watch_paths: [/etc/passwd, /etc/group, /etc/shadow, /etc/ssh, /etc/sudoers, /etc/sudoers.d, /etc/crontab, /etc/cron.d]
    rules: []
  native_fim:
    enabled: true
    paths: [/etc/passwd, /etc/group, /etc/shadow, /etc/ssh, /etc/sudoers, /etc/sudoers.d, /etc/crontab, /etc/cron.d]
    poll_interval_seconds: 30
    report_changes: false
    max_diff_bytes: 8192
  ssh_auth:
    enabled: true
    poll_interval_seconds: 5
    initial_lookback_seconds: 300
    alert_threshold: 5
    window_seconds: 300
  sudo:
    enabled: true
    io_logging: true
    upload_io: false
    max_session_bytes: 20971520
    grants: []
  tetragon:
    enabled: false
    version: ""
    download_url: ""
    sha256: ""
    config: ""
    tracing_policy: ""
  policies:
    mode: audit
    ssh:
      enabled: false
      password_authentication: "no"
      permit_root_login: prohibit-password
      allow_users: []
      allow_sources: []
    sysctl: {}
    session_timeout_seconds: 0
    disable_ctrl_alt_del: false
    grub:
      enabled: false
      password_hash: ""
```

原有配置没有 `security` 时继续兼容，不隐式开启安装。表单范例主动开启基础审计和文件属性监控，Tetragon 和 I/O 上传按需启用；`policies.mode: audit` 默认只检查主机加固策略。Master 验证配置形状与字段名，Agent 完成对应平台、路径、范围和实际执行校验。

`security.sudo.grants` 为整体替换的授权数组，最多 128 项：`{user:string,run_as?:string,commands:string[],nopasswd?:boolean}`。user/run_as 是本机账户名称，run_as 留空或省略使用 root；commands 每项为绝对命令路径，可附字面参数，每条最多 1024 字节，每个授权 1–64 条命令，拒绝 sudoers 元字符、通配符和换行；nopasswd 默认 false。例：`{user: ops, run_as: root, commands: ["/usr/bin/systemctl restart nginx.service"], nopasswd: false}`。Agent 只管理自己的 sudoers 片段，不删除其他已有的 sudo、wheel 或云镜像广泛授权；新增授权不能证明用户已经实现最小权限。未指定命令参数时也应了解该二进制允许的参数及提权能力。授权变更的实际应用仍由 Agent 策略和校验结果决定。

`component_status.data.components` 每项包含 `name,enabled,installed,running,state`，可附 `message,error,version,config_hash,applied_at`；其他队列/采集进度字段原样保留。快照按 Agent `time` 更新，旧上报不会回滚新状态。配置交付 `applied` 只表示 Agent 已接受配置；安装、reload、内核能力等结果以组件状态为准。

`security_event.data` 含 `source,kind,severity,message`，可附 `path,user,uid,pid,ppid,command,session_id,details` 及来源证据。接受 `debug,info,notice,warning,error,critical`；只将后三种级别入 webhook 队列，重复事件不重复通知。普通命令和组件状态不自动通知。sudo `io_chunk` 单独处理，不进入事件表与 webhook 队列。

sudo 会话分页结构：`{items:[{id,machine_ip,host,session_id,generation,time,received_at,files:[{name,size,received_bytes,complete}]}],total,page,page_size}`。下载 `file` 仅允许 `log,log.json,timing,stdin,stdout,stderr,ttyin,ttyout`，`id` 为数据库整数 ID。下载为原始二进制 `application/octet-stream`，保存同一会话的全部完整文件后可在支持的环境使用 `sudoreplay`。初版不提供网页回放与自动保留期限清理；删除机器级联删除会话及分片。
