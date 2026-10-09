# Agent / Master UDP 协议

Agent 向主控 `55555/udp` 发送 UTF-8 JSON，每个数据报是一条完整事件，单条不超过 60000 字节。主控 HTTP API 与前端分别使用 `10110/tcp`、`10111/tcp`；Agent 只访问 UDP 端口。当前扩展保留 `version: 1` 和原有字段。

## 机器身份与配置

```yaml
server:
  - 172.22.0.100:55555
agent_ip: 172.22.0.101
setup:
  interval_seconds: 300
```

`agent_ip` 可省略：Agent 会使用连接该 Master 的 UDP socket 本地出口 IP。显式配置支持 IPv4、IPv6，拒绝未指定地址和组播地址。NAT 后不同机器可使用各自唯一的内网 IP；多个主控出口不同、多网卡或需要固定机器主键时应明确配置。此字段属于外置加密配置，修改后重新加密并替换程序旁的 `config.age`；单次运行下次启动读取，常驻服务重启生效，无需重新构建 Agent。

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

Master 启动时及此后每秒检测离线状态，独立于 webhook 网络发送。每台机器每次持续离线创建一次 `alert`，模块 `machine`、类型 `abnormal_offline`，事务内保存离线状态和通知队列；Master 重启或删除告警不重复创建。任何有效 UDP 上报恢复在线并重置离线通知资格，下次离线会再通知。心跳本身仍不产生事件；离线告警由 Master 创建，不刷新 `last_seen`，无需更新 Agent。中文通知保留机器、主机名、最后上报时间、离线判定时间及超时阈值。

数据库初始化或打开旧库时，Master 自动迁移 SQLite schema 到 `PRAGMA user_version=4`。v2 增加机器心跳字段；v3 扩展事件类型及命令来源 ID 去重索引；v4 增加 `machine_offline_state` 保存持续离线状态。迁移保留机器信息、事件 ID、处理状态/备注、管理员密码、登录会话、webhook 配置及通知队列的重试记录和 ID 高水位。数据库版本与 UDP 协议 `version: 1` 相互独立。

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
