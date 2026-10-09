# HTTP API

基址：`http://主控IP:10110`。生产浏览器使用前端同源 `/api` 代理。除登录、健康检查外均须登录 Cookie；JSON 写请求使用 `Content-Type: application/json`。带 `Origin` 的写请求必须匹配 HTTP `Host`，反向代理需保留原始 Host（包括端口）。

错误统一 `{ "message": "错误原因" }`，未登录为 401，非法参数 400，记录不存在 404。所有返回时间均为带时区 ISO8601。机器和事件列表返回 `{items: [], total: 0, page: 1, page_size: 20}`，页大小 1–100。webhook 列表返回数组。

| 方法 | 路径 | 用途 / 请求体 |
|---|---|---|
| GET | `/healthz` | 数据库健康检查 |
| POST | `/api/auth/login` | `{username,password}`；首次 admin/admin1818. |
| GET | `/api/auth/me` | `{username:"admin"}` |
| POST | `/api/auth/logout` | 注销当前会话 |
| PUT | `/api/auth/password` | `{current_password,new_password}`，使全部会话失效 |
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

`type` 为 `alert`、`ssh_login`、`command_history`、`scan_summary`，为空表示全部；`q` 按字面文本搜索机器 IP、主机名、data 和备注，`%` / `_` 不当作通配符。`machine_ip` 为完整 IP；URL 路径里的 IPv6 应编码。`from` 和 `to` 为包含边界的 ISO8601（必须带时区），开始不得晚于结束。按事件发生时间倒序、整数 ID 倒序稳定分页；登录事件采用 `data.login_time`。发生新事件时使用偏移分页的不同页之间仍可能移动，刷新可查看最新记录。

机器字段：`ip,host,source_ip,reported_ip,alias,notes,first_seen,last_seen,last_event_at,last_summary,interval_seconds,heartbeat_interval_seconds,event_count,alert_count,open_alert_count,login_count,online,status,offline_after_seconds`。`status` 为 `online` / `abnormal_offline`，`offline_after_seconds` 给出当前机器的离线阈值。机器由首次心跳/事件自动建立，后续上报自动恢复在线；心跳不增加事件数量。

事件字段：`id,event_id,machine_ip,host,type,time,received_at,status,notes,data`。`data` 保留 Agent 上报或主控检测的证据，不接受经 HTTP 修改检测证据。

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

自动通知正文示例（`before/after` 有值时才追加，时间为 UTC）：

```text
【安全中心告警】
机器 IP：10.20.30.40
主机：node-a
类型：files / modified
目标：/etc/app.conf
时间：2026-10-06T08:00:00Z
内容：monitored file modified
变更前：900150983cd24fb0d6963f7d28e17f72
变更后：d41d8cd98f00b204e9800998ecf8427e
事件 ID：alert-example
```

新入库的 `alert` 和 `ssh_login` 发往当时已启用的配置，事件与通知队列在同一事务提交。数据库已有记录不补发，重复上报不重复入队；延迟/补读登录首次入库时仍会通知，时间取真实 `login_time`。普通命令、巡检摘要和心跳不发送。测试成功不创建配置，草稿测试后仍需保存才能接收后续通知。

总览字段：`machines,online_machines,events,alerts,open_alerts,ssh_logins,pending_notifications`。待通知数量包括已暂停地址的未发送记录。
