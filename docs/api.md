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
| POST | `/api/webhooks/{id}/test` | 向该 URL 主动发送测试通知，失败 502 |

`type` 为 `alert`、`ssh_login`、`scan_summary`，为空表示全部；`q` 按字面文本搜索机器 IP、主机名、data 和备注，`%` / `_` 不当作通配符。`machine_ip` 为完整 IP；URL 路径里的 IPv6 应编码。`from` 和 `to` 为包含边界的 ISO8601（必须带时区），开始不得晚于结束。按事件发生时间倒序、整数 ID 倒序稳定分页；登录事件采用 `data.login_time`。发生新事件时使用偏移分页的不同页之间仍可能移动，刷新可查看最新记录。

机器字段：`ip,host,source_ip,reported_ip,alias,notes,first_seen,last_seen,last_event_at,last_summary,interval_seconds,heartbeat_interval_seconds,event_count,alert_count,open_alert_count,login_count,online,status,offline_after_seconds`。`status` 为 `online` / `abnormal_offline`，`offline_after_seconds` 给出当前机器的离线阈值。机器由首次心跳/事件自动建立，后续上报自动恢复在线；心跳不增加事件数量。

事件字段：`id,event_id,machine_ip,host,type,time,received_at,status,notes,data`。`data` 原样保留 Agent 对象，不接受经 HTTP 修改检测证据。

Webhook 字段：`id,name,url,format,enabled,created_at,updated_at,last_error,last_success_at,pending_count`。`format` 可选 `feishu`（默认）、`wecom`、`generic`，`enabled` 默认 true；名称最多 128 字节，URL 仅允许 HTTP(S)，禁止 URL 中的用户名密码与片段。可配置多个独立通知地址。

总览字段：`machines,online_machines,events,alerts,open_alerts,ssh_logins,pending_notifications`。待通知数量包括已暂停地址的未发送记录。
