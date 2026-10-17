# Agent / Master UDP 协议

Agent 向主控 `55555/udp` 发送 UTF-8 JSON，每个数据报是一条完整事件，单条不超过 60000 字节。Agent 还主动连接主控 `55556/tcp` 接收配置。主控 HTTP API 与前端分别使用 `10110/tcp`、`10111/tcp`。当前扩展保留 `version: 1` 和原有字段。

## 机器身份与配置

```yaml
server:
  - 172.22.0.100:55555
setup:
  interval_seconds: 300
```

机器 IP 自动获取：新版 Agent 读取连接配置 TCP Master 时操作系统选择的 `LocalAddr`，报告本机出口地址并用于全部 UDP 上报。多网卡按到配置主控的路由选择地址，容器内运行时为容器网络地址；不从主机名推导 IP，不调用公网 IP 查询服务。无需配置 agent_ip，旧 YAML 的该字段以及 ANQUAN_AGENT_IP 被忽略。主控以报告地址区分机器和配置连接，另存实际 TCP/UDP 对端为 `source_ip`，经中转时来源可以是代理 IP。

例如 `172.22.0.27`、`172.22.0.28` 经同一 Nginx `172.22.240.6` 转发，机器标识仍为各自本机 IP，来源地址记录为 `172.22.240.6`。这不要求 Nginx 添加 PROXY protocol；当前主控仍不解析 PROXY protocol 帧。不同网络中重复的私网 IP 仍受现有 IP 主键约束，不能区分为不同机器。

主控以 `ip` 为机器主键，`host` 仅作为主机名展示。接收旧 Agent 的报文缺少 `ip` 时，使用 UDP 数据报来源 IP。UDP 来源端口是临时端口，不能当作机器标识。机器 IP 变化会形成新的机器记录。该协议用于内网传输，无需认证或加密；主控开通对应 Agent 机器访问 `55555/udp` 的网络即可。

## 公共信封

| 字段 | 类型 | 含义 |
|---|---|---|
| `version` | integer | 当前为 `1` |
| `event_id` | string | SHA-256 十六进制事件标识；持久化事件按 `(ip,event_id)` 唯一存储，心跳只更新机器状态 |
| `ip` | string | 被监控机器 IP；旧报文可回退 UDP 来源地址 |
| `host` | string | 被监控机器主机名 |
| `time` | RFC3339 string | 心跳为发送时间；告警/摘要为扫描开始时间；登录/操作命令为真实发生时间，带时区 |
| `type` | string | `heartbeat`、`scan_summary`、`alert`、`ssh_login`、`command_history` |
| `data` | object | 对应类型的数据 |
| `ack_requested` | boolean | 可选，默认 false；为 true 时 Master 成功提交后回复 ACK |

主控应另存 `received_at` 作为接收时间。按登录发生时间筛选时使用 `data.login_time`，避免首次补读、积压和延迟报文落入接收当天；机器在线状态应按接收时间更新。

## 自动上线、独立心跳与异常离线

配置 `server` 后，Agent 启动时在首轮采集前立即发送 `heartbeat`。`-service` 常驻模式随后每 30 秒发送一次，独立于默认 300 秒的扫描周期；文件、进程或登录采集耗时较长时仍继续发送心跳。心跳发送失败会写入日志，后续扫描和心跳继续运行。`server: []` 不发送网络数据。

```json
{
  "version": 1,
  "event_id": "f1ad30fd2b83903c056b17d0889cd58b02a6b465b26f9e32d680b4b8bc780009",
  "ip": "172.22.0.101",
  "host": "node-a",
  "time": "2026-10-03T10:00:00+08:00",
  "type": "heartbeat",
  "data": {
    "interval_seconds": 30,
    "state": "running",
    "version": "0.4.0"
  }
}
```

`data.interval_seconds` 是心跳周期，必须是 1–86400 的整数；当前 Agent 固定为 30。`state` 和 Agent 程序 `version` 是附加信息，程序版本可省略。它们与公共信封 `version: 1` 的协议版本分别表示不同含义。

Master 收到首条有效心跳或检测事件时，按机器 IP 自动创建记录；每条有效上报按主控接收时间更新 `last_seen`。支持心跳的机器离线阈值为 `max(心跳周期 × 3, 30)` 秒，因此当前 Agent 连续超过 90 秒没有任何有效上报时显示 `status: abnormal_offline`（异常离线）、`online: false`；再次收到有效上报立即恢复 `status: online`、`online: true`。列表、机器详情和概览使用同一规则，接口同时返回 `heartbeat_interval_seconds` 和 `offline_after_seconds`。

`heartbeat` 只更新机器状态，不写入 `events`，不增加告警/登录/事件数量，也不触发 webhook。乱序心跳不会把机器的心跳周期回退到旧值。单次运行（无参数）仅在采集前发送一次启动心跳，退出后不再周期上报；需要持续在线状态时使用 `-service`。外部 timer 两轮之间没有常驻 Agent 时，超过阈值会显示离线。

旧 Agent 仍可只发送 `scan_summary`：没有收到独立心跳的机器使用 `max(扫描周期 × 3, 120)` 秒作为离线阈值，默认扫描 300 秒对应 900 秒，避免正常巡检间隔被误判离线。收到新 Agent 的独立心跳后自动使用心跳阈值。

数据库初始化或打开旧库时，Master 自动迁移 SQLite schema 到 `PRAGMA user_version=9`。v2 增加机器心跳字段；v3 扩展事件类型及命令来源 ID 去重索引；v4 保存持续离线状态；v5 增加共享 YAML 模板；v6 增加按机器分配的加密配置、版本和应用确认状态；v7 增加安全组件事件、快照和 sudo 会话；v8 增加主控事件屏蔽与巡检保留设置；v9 增加安全运行事件最低保留级别，默认 warning。迁移保留机器信息、事件 ID、处理状态/备注、管理员密码、登录会话、webhook 配置及通知队列的重试记录和 ID 高水位，主控运行后按已配置的 12/24 小时策略自动删除过期巡检记录。数据库版本与协议 `version: 1` 相互独立。

主控事件策略可屏蔽指定 Tetragon 类型，并为所有来源的 `security_event` 设置最低保留级别（默认 `warning`）。匹配屏蔽或低于级别的新上报不写入事件表、不创建通知任务，但仍更新机器在线信息，并在事务提交后正常 ACK；Agent 可移除已确认的待发记录，不必升级 Agent 协议。Tetragon 类型屏蔽不影响其他来源的同名类型；显式 sudo `io_chunk` 文件录制上传、SSH 登录、普通告警和操作命令不受运行事件最低级别影响。

## TCP 配置下发（55556）

Master 监听 `55556/tcp`。Agent 的配置主控地址来自 -master、ANQUAN_MASTER 或自动保存的连接信息，完全独立于 YAML 的 server。裸配置主控 IP 默认使用 TCP 55556，可用 IP:TCP端口调整。YAML 的 server 仅向全部地址发送 UDP 数据，裸 IP 默认使用 UDP 55555；server: [] 只关闭 UDP，不影响接收配置。

v0.6.1 不要求本地 `config.age`：首次指定 Master 后自动保存 `agent.connection.json` 供后续无参数运行使用。无有效平台缓存或本地配置时，`-service` 只连接、注册并保持 TCP 心跳，等待下发，不开启巡检/登录/命令采集；Master 离线时持续重连。收到有效配置并完成运行环境检查和密文缓存后才启用采集并 ACK。主控明确取消分配时，无本地配置的 Agent 恢复等待，配置通道继续运行。

无参数仍执行一次：已有平台缓存时可以离线采集并上报 SSH 登录；可达 Master 时先限时同步配置，随后执行一次并退出。首次既没有地址也没有配置时提示指定 Master；限时同步后仍未获得配置时退出 1。SSH 登录按有效配置的 enabled/source/回看范围采集，沿用持久游标，不因重新执行而重复上报已读记录。

每帧是 UTF-8 JSON 加换行（NDJSON），最大 8 MiB，`version: 1`。JSON 字符串内的 age 密文换行使用 JSON 转义。第一帧：

```json
{"version":1,"type":"hello","ip":"172.22.0.27","reported_ip":"172.22.0.27","host":"ip-172-22-0-27","agent_version":"0.6.6"}
```

新 hello 不启用 `discover_ip`。主控优先规范化 `reported_ip` 并按其登记机器，TCP 实际来源另存 `source_ip`，先确认身份，再发送最新分配：

```json
{"version":1,"type":"identity","ip":"172.22.0.27"}
```

`reported_ip` 必须为可用单播地址，拒绝未指定、组播、广播、回环、链路本地或带 zone 的地址；IPv4 映射 IPv6 地址规范化为 IPv4。非空 `ip` 必须规范化后与 `reported_ip` 一致，同时启用 `discover_ip` 的新报告模式明确拒绝，不静默回退为中转来源。新版 Agent 在 hello 前已保存本机出口 IP，后续 TCP 确认和 UDP 载荷使用同一标识。

旧发现 hello（`discover_ip:true`、不带 `reported_ip`）仍按 TCP 实际来源登记并回复 identity，即使同时带旧 IP 也保留原行为。旧显式 IP hello（不带 `reported_ip`、不启用发现）仍按 `ip` 登记，不额外回复 identity；旧 hello 没有 `ip` 时使用实际来源。旧 Master 忽略新增字段时仍可按新 Agent 的显式 `ip` 登记和下发，因此新 Agent 不依赖 identity 回包完成本机 IP 获取。旧 UDP 缺少 `ip` 时继续使用数据报来源。

本次身份扩展保留协议 `version:1`，不改变数据库结构。升级后原中转 IP 的机器、历史和分配记录不会自动搬移或删除，因为其中可能聚合多节点数据；应在页面按新本机 IP 重新选择和下发，核对后再处理原记录。

没有分配时，revision 和 ciphertext 同时为空：

```json
{"version":1,"type":"config","revision":"<密文完整字节的SHA-256十六进制>","ciphertext":"-----BEGIN AGE ENCRYPTED FILE-----\n..."}
```

Agent 先验证 revision、age 完整性和节点平台的 YAML 配置，再原子保存程序旁的 `config.master.age`。常驻模式等待当前扫描结束，停止旧心跳/命令采集工作、切换到新配置并重启相应工作后才确认成功：

```json
{"version":1,"type":"ack","revision":"<当前版本>"}
```

失败返回同版本和非空 `error`，保留当前有效配置及缓存；Master 记录失败供页面显示。未知或旧版本 ACK 不改变新分配状态。主控保存每台机器最近分配的密文、版本、下发和确认状态，重启或连接恢复时自动重发。下发 HTTP 成功只表示保存成功，节点生效以 ACK 为准。

Agent 每 30 秒发送 `{"version":1,"type":"ping"}`，主控回复 `{"version":1,"type":"pong"}`。有效 hello 和 ping 更新机器活动时间；连接异常后 Agent 自动重连。页面 `connected` 单独表示配置 TCP 连接，机器 `online` 仍按最近活动时间及既有超时阈值计算。

主控配置优先于可选本地 config.age，启动先使用有效缓存，再限时同步；无缓存且无本地配置时常驻等待。无参数仍执行一次巡检及 SSH 登录上报。下发 server 列表立即生效并替换 UDP 目标，TCP 配置地址及自动 IP 不由 YAML 控制。连接文件 version 2 保存 master 列表和 observed_ip；version 1 自动迁移为 TCP 55556 并忽略旧手工 agent_ip。服务账号需要程序目录的缓存写入权限。升级顺序为 Master、Agent，再更新 Web 示例。

此通道沿用内网机器 IP 信任方式，没有单独的节点认证或 TLS；age 密文用于配置加密，不构成 Master 身份认证。仅允许可信 Agent 网络访问 55556/TCP。既有 UDP、HTTP 与 Webhook 的传输行为保持原有协议。


## 扫描摘要

即使没有告警，每轮完成采集仍发送 `scan_summary`，用于保存扫描结果及兼容旧 Agent 的在线判断。

```json
{
  "version": 1,
  "event_id": "d2bc9b09cf51d1b16eeedbe9b79094a90fdf1f42b4dc9ab891fb1b00d2a8a0c2",
  "ip": "172.22.0.101",
  "host": "node-a",
  "time": "2026-10-02T10:00:00+08:00",
  "type": "scan_summary",
  "data": {
    "collection_success": true,
    "alerts": 0,
    "errors": 0,
    "files": 12,
    "processes": 48,
    "logins": 1,
    "login_pending": false,
    "interval_seconds": 300,
    "finished_at": "2026-10-02T10:00:01+08:00"
  }
}
```

这里的 `interval_seconds` 是 Agent 常驻服务的扫描周期，默认 300 秒，与独立心跳的 30 秒分别保存。`collection_success` 仅表示采集完成，异常文件或缺失进程也可以是有效检测结果；应同时查看 `alerts` 与 `errors`。主控接纳乱序的心跳、告警、登录报文，旧扫描摘要不会覆盖新的摘要或心跳周期。

## 文件等通用告警

```json
{
  "version": 1,
  "event_id": "a3baf0fc452fe7c85a754e4364122415b4f79ed7f0e3a0deeb90ef4f27b1d642",
  "ip": "172.22.0.101",
  "host": "node-a",
  "time": "2026-10-02T10:00:00+08:00",
  "type": "alert",
  "data": {
    "module": "files",
    "kind": "modified",
    "target": "/etc/ssh/sshd_config",
    "message": "file content changed",
    "before": "900150983cd24fb0d6963f7d28e17f72",
    "after": "d41d8cd98f00b204e9800998ecf8427e"
  }
}
```

`target` 是异常文件路径、搜索规则或进程命令。文件常见类型为 `added`、`modified`、`deleted`、`missing`、`not_found`；检查失败可为 `inspection_error` 或 `collection_error`。从 Agent v0.5.1 起，fils/dir/search 命中任意配置 MD5 即正常，未知 MD5 初始化时记录为该路径的基线，之后变成另一个未知值产生 `modified`，不再仅因未命中配置值产生 `md5_mismatch`。主控仍可接收旧版 Agent 的 `md5_mismatch`。`before` / `after` 可省略：修改保存前后 MD5，删除只有旧 MD5，新增只有新 MD5；旧版允许列表不匹配保存允许值与当前值。主控应保存原始 `data`，不要把其他模块的这两个字段强制解释为 MD5。

## 每次 SSH 成功登录

```json
{
  "version": 1,
  "event_id": "54a826e65b3cb37f3d1079b1cdef4c89eed136944b4607235376d248fcb18281",
  "ip": "172.22.0.101",
  "host": "node-a",
  "time": "2026-10-02T09:55:00+08:00",
  "type": "ssh_login",
  "data": {
    "id": "journal-cursor-or-source-record-id",
    "source_ip": "192.0.2.10",
    "login_time": "2026-10-02T09:55:00+08:00",
    "user": "ops",
    "terminal": "N/A",
    "method": "publickey"
  }
}
```

`ip` 是被登录机器，`source_ip` 是登录来源，两者不可混用。来源没有终端时 `terminal` 为 `N/A`。生产默认读取 journal 成功认证记录，支持非交互 SSH；wtmp 只能覆盖操作系统写入的会话。

Master v0.6.0 将新入库的 `ssh_login` 与通知任务在同一事务提交，向全部已启用 webhook 发送登录通知。正文保留机器、主机名、用户、来源 IP、终端、认证方式、真实登录时间和事件 ID。重复事件及相同来源 ID 的登录不重复入队，数据库中已有历史记录不补发；补读/延迟上报的登录首次入库时仍通知。通知失败沿用持久重试，重启后继续发送。

## 操作命令及落库确认（v0.6.0）

```json
{
  "version": 1,
  "event_id": "c530bd810e792eec8fe41d4b307878d84691c9a6febea5c9864bd471f0115413",
  "ip": "172.22.0.101",
  "host": "node-a",
  "time": "2026-10-09T02:42:50+08:00",
  "type": "command_history",
  "ack_requested": true,
  "data": {
    "id": "stable-source-record-id",
    "command_time": "2026-10-09T02:42:50+08:00",
    "user": "root",
    "terminal": "/dev/pts/1",
    "command": "alias ll='ls -alF'",
    "path": "/var/log/history.log",
    "offset": 0
  }
}
```

来源文件从头补传，之后按字节位置读取追加记录。`id` 由持久化的日志代号和记录起始字节位置生成；相同文本、用户及时间的两次操作仍有不同 ID。Master 使用 `command_time` 作为事件发生时间，保存原始 `data`，并额外按 `(机器 IP, command id)` 去重，因此主机名改变后重试也不重复入库。机器 IP 改变会形成另一台机器。`GET /api/events?type=command_history` 支持现有机器、时间、关键字、状态及分页参数。正常命令事件不进入告警 webhook 队列。

当信封带 `ack_requested: true`，Master 在数据库事务成功提交后向报文来源地址回复：

```json
{"version":1,"type":"ack","event_id":"c530bd810e792eec8fe41d4b307878d84691c9a6febea5c9864bd471f0115413"}
```

重复事件也回复匹配原报文 `event_id` 的 ACK。格式/校验错误或落库失败不确认。Agent 每条最多等待 2 秒，未收到匹配确认则保留加密 `.commands` 中的待发批次，随后重试；重启仍使用相同 ID。每个配置的 Master 均确认后才清空该批次。此机制为至少一次传输、主控幂等入库；依赖保留 Agent 状态和 Master 数据库。网络须允许 UDP 请求及返回流量。

命令采集按单行日志解析；非法格式及无法容纳于 UDP 的记录以 `alert` 上报，`module: history`、`kind: parse_error`、`target: 来源日志`，描述包含字节位置，并同样请求 ACK。文件读取/状态错误写 Agent 本机 `history_error` 日志。Agent 不修改或清理源日志。

升级顺序为 Master、Web、Agent；旧 Master 不支持 `command_history` 或落库 ACK，新 Agent 会保留待发数据并持续等待，不会把发送成功当作落库成功。

## 重复、持久化与投递边界

同一报告构造相同的事件 ID，多个 UDP 副本按 `(ip,event_id)` 去重。登录使用机器 IP、主机名、事件类型与来源记录 `id` 生成标识，同一登录跨扫描重新读取保持相同标识；不同来源 ID 的两次登录即使用户/IP/时间完全相同也会分别保留。没有来源 ID 的兼容记录按其原始时间和内容生成标识。告警与摘要按扫描时间和内容生成标识，持续缺失在下轮仍产生新记录；文件变化因本地发布失败而跨轮重新检测，也可能形成新的告警观察记录。

常规巡检告警、登录、摘要和心跳的 Agent → Master 传输没有 ACK 或持久重传。成功发送只表示本地网络栈接受，不代表主控已存储；网络丢包、主控停机或超大数据报可能导致缺记录。命令采集通道采用上述落库确认及持久重试。Master → webhook 的告警及登录通知在入库后采用持久重试，重复事件不重复入队。

## 安全组件事件与状态

继续使用同一 v1 Envelope、UDP 55555 和 `ack_requested`，不增加端口；所有合法的请求确认都在事务提交后发送，包括重复报文。配置继续使用现有 TCP 55556 的 age YAML 分发。

`type: security_event` 的 `data` 必须包含非空 `source,kind,message` 和有效 `severity`（`debug/info/notice/warning/error/critical`），其余来源证据原样保存。通过主控屏蔽和最低级别筛选的普通事件按 `(machine_ip,event_id)` 幂等入库；仅有效级别为 `warning/error/critical` 创建 webhook 任务。兼容旧 Agent：仅 `source=auditd,kind=exec,severity=warning,message="Linux audit exec"`，且 `fields.key` 或原始 `records` 明确只有内建 `key=anquan_exec` 时，按 `info` 筛选且不通知；原始载荷不变，自定义/多个 key、缺少 key 证据、自定义消息和更高级别不降级，fields 最后覆盖也不能掩盖原始记录中的自定义 key。投递前重新按当前策略判断；不再满足条件的未投递运行事件任务会取消，不删除历史、不伪造投递成功。

`type: component_status` 的 `data.components` 是最多 32 个组件的数组，每项名称唯一、非空，包含 `name,enabled,installed,running,state`，可附 `message,error,version,config_hash,applied_at,checks`；`applied_at` 使用 RFC3339 时间。附加 `queue` 等字段保持原样。每次在同一事务维护每台机器最新快照，只有 Agent 时间不旧于现有快照才替换；正常稳定上报不进入事件历史。仅启用组件首次异常、异常状态/诊断/配置/检查证据有意义变化、及异常恢复时保留一次历史，重复异常、队列/库存变化、应用时间变化和组件/检查次序不增加历史。非空 `error` 或 `error/failed/install_failed/config_failed/degraded/unsupported/drift/stopped/missing/not_installed` 状态为异常，禁用组件与 `starting/installing/pending` 过渡状态不视为异常。旧报告不会回滚快照或制造过期历史，合法快照和重复报告仍在事务提交后正常 ACK；组件状态始终不触发 webhook。新 Agent 的正常快照可附 `status_reporting:"changes_only",snapshot_interval_seconds:300,snapshot_only:true`；这些字段仅为展示提示，主控独立判断异常，不信任 `snapshot_only` 来跳过真实异常。

sudo I/O 使用 `type: security_event`、`source: sudo`、`kind: io_chunk`、`severity: info`、非空 `message`，证据放在 `data.details`：

```json
{
  "session_id": "00/00/AB",
  "generation": "session-inode-start-identity",
  "file": "stdout",
  "offset": 0,
  "content_base64": "aGVsbG8K",
  "total_size": 6,
  "complete": true
}
```

`generation` 必须非空，只允许字母、数字、下划线、点、冒号、连字符，最多 128 字节；会话被重用或文件截断必须切换 generation，防止拼接不同记录。`session_id` 最多 128 字节，仅允许字母、数字、下划线、连字符及正常层级 `/`，禁止点和路径穿越。`file` 严格限定为 `log/log.json/timing/stdin/stdout/stderr/ttyin/ttyout`。

Base64 严格解码后每片最多 24 KiB，`offset` 和 `total_size` 为非负字节数，单文件最大 64 MiB，分片范围不能超出 total_size。同一会话、generation、文件、offset 的相同 bytes 幂等；同 offset 不同 bytes、分片重叠、冲突 event_id 拒绝且不确认。允许乱序到达，只有完整不重叠覆盖 `0..total_size` 且收到 `complete:true` 才可下载。空文件使用 offset=0、total_size=0、空 Base64、complete=true。

分片存入独立会话、文件及 chunk 表，不向普通事件表重复写 Base64，不创建 webhook；提交后沿用原 event_id ACK。原始文件内容包括 sudo 录制格式字节，Agent 不应在未标识时混合压缩和未压缩文件。HTTP 下载需管理员登录，详情见 API 文档。
