package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityNotificationChineseTextAcrossWebhookFormats(t *testing.T) {
	at := time.Date(2026, 10, 17, 3, 33, 38, 0, time.UTC)
	data := mustJSON(t, map[string]any{"source": "policies", "kind": "policy_check", "severity": "warning", "message": "Host policy compliance checked", "path": "/etc/ssh/sshd_config", "user": "root", "command": "sshd -T"})
	event := Event{EventID: "47987534ef98bcc9c027af37ab73d3e866bd2c5568b68869720c2fef1097981a", MachineIP: "172.22.0.27", Host: "ip-172-22-0-27", Type: "security_event", Time: at, Data: data}
	for _, format := range []string{"feishu", "wecom", "generic"} {
		t.Run(format, func(t *testing.T) {
			var payload map[string]json.RawMessage
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Errorf("invalid webhook payload: %v", err)
				}
				_, _ = io.WriteString(w, `{"code":0,"errcode":0}`)
			}))
			defer endpoint.Close()
			result, err := SendEvent(context.Background(), WebhookClient(), Webhook{URL: endpoint.URL, Format: format}, event)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"【安全中心组件告警】", "机器 IP：172.22.0.27", "主机：ip-172-22-0-27", "来源：系统策略（policies）", "类型：策略合规检查（policy_check）", "级别：警告（warning）", "时间（北京时间 UTC+8）：2026-10-17 11:33:38", "内容：已完成主机策略合规检查", "路径：/etc/ssh/sshd_config", "用户：root", "命令：sshd -T", "事件 ID：" + event.EventID} {
				if !strings.Contains(result.Text, want) {
					t.Errorf("notification missing %q: %s", want, result.Text)
				}
			}
			var wireText string
			switch format {
			case "feishu":
				var content map[string]string
				_ = json.Unmarshal(payload["content"], &content)
				wireText = content["text"]
			case "wecom":
				var content map[string]string
				_ = json.Unmarshal(payload["text"], &content)
				wireText = content["content"]
			case "generic":
				_ = json.Unmarshal(payload["text"], &wireText)
				var createdAt time.Time
				if err := json.Unmarshal(payload["created_at"], &createdAt); err != nil || !createdAt.Equal(at) {
					t.Fatalf("raw event time changed: %s (%v)", payload["created_at"], err)
				}
				if !bytes.Equal(payload["data"], data) || !strings.Contains(string(payload["data"]), "Host policy compliance checked") {
					t.Fatal("generic payload lost original event evidence")
				}
			}
			if wireText != result.Text {
				t.Fatal("localized notification not sent in format-specific text field")
			}
			if event.Time != at || !bytes.Equal(event.Data, data) {
				t.Fatal("notification changed source event")
			}
		})
	}
}

func TestNotificationBeijingTimeUsesInstantAndIgnoresHostTimezone(t *testing.T) {
	originalLocal := time.Local
	time.Local = time.FixedZone("host", -7*60*60)
	t.Cleanup(func() { time.Local = originalLocal })
	for _, at := range []time.Time{
		time.Date(2026, 10, 17, 20, 33, 38, 0, time.UTC),
		time.Date(2026, 10, 18, 3, 33, 38, 0, time.FixedZone("Bangkok", 7*60*60)),
		time.Date(2026, 10, 18, 4, 33, 38, 0, beijingTimeZone),
	} {
		event := Event{Type: "security_event", Time: at, Data: mustJSON(t, securityData("warning"))}
		if text := NotificationText(event); !strings.Contains(text, "时间（北京时间 UTC+8）：2026-10-18 04:33:38") {
			t.Fatalf("incorrect Beijing time for %v: %s", at, text)
		}
	}
	alert := offlineAlert{LastSeen: time.Date(2026, 10, 17, 23, 59, 0, 0, time.UTC), OfflineSince: time.Date(2026, 10, 18, 0, 0, 30, 0, time.UTC)}
	text := offlineNotificationText(Event{}, alert)
	for _, want := range []string{"最后上报时间（北京时间 UTC+8）：2026-10-18 07:59:00", "离线判定时间（北京时间 UTC+8）：2026-10-18 08:00:30"} {
		if !strings.Contains(text, want) {
			t.Fatalf("incorrect offline notification time: %s", text)
		}
	}
}

func TestSecurityNotificationMessagesPreserveCustomDiagnostics(t *testing.T) {
	for _, tc := range []struct{ source, kind, message, want string }{
		{"policies", "policy_check", "Host policy compliance checked", "已完成主机策略合规检查"},
		{"tetragon", "parse_error", "Tetragon emitted invalid JSON", "Tetragon 输出的 JSON 格式无效"},
		{"tetragon", "process_exec", "Tetragon process_exec", "Tetragon 事件：进程执行（process_exec）"},
		{"tetragon", "process_usdt", "Tetragon process_usdt", "Tetragon 事件：用户态静态跟踪（process_usdt）"},
		{"auditd", "exec", "Linux audit exec", "Linux 审计：外部程序执行（exec）"},
		{"auditd", "oversize_event", "Event exceeds transport size; original records remain in the host source log", "事件超过传输大小限制，原始记录保留在主机源日志中"},
		{"sudo", "oversize_record", "Log record exceeds 128KiB; original remains in the host source log", "日志记录超过 128 KiB，原始记录保留在主机源日志中"},
		{"auditd", "collection_gap", "Rotated source disappeared before it could be drained", "轮转后的源日志在读取完成前已消失"},
		{"tetragon", "collection_gap", "Source was truncated; continuing from the beginning", "源日志已被截断，将从头继续读取"},
		{"sudo", "collection_gap", "Source contents changed before the saved cursor", "已保存读取位置之前的源日志内容发生变化"},
		{"sudo", "io_session", "sudo input/output session index", "sudo 输入输出会话索引"},
		{"sudo", "io_limit", "sudo I/O session exceeds max_session_bytes", "sudo 输入输出会话超过配置的最大字节数（max_session_bytes）"},
		{"sudo", "io_limit", "sudo I/O file exceeds 64MiB transport limit", "sudo 输入输出文件超过 64 MiB 传输限制"},
		{"sudo", "io_chunk", "sudo I/O file data", "sudo 输入输出文件数据"},
		{"ssh_auth", "ssh_auth_failure", "SSH authentication failed", "SSH 认证失败"},
		{"ssh_auth", "ssh_bruteforce", "repeated SSH authentication failures", "检测到重复 SSH 认证失败"},
		{"task", "task_started", "Scheduled task started", "计划任务开始执行"},
		{"task", "task_finished", "Scheduled task finished", "计划任务执行成功"},
		{"task", "task_failed", "Scheduled task failed", "计划任务执行失败"},
		{"native_fim", "file_activity", "kernel file notification", "内核文件活动通知"},
		{"native_fim", "file_change", "monitored file added", "新增监控文件"},
		{"native_fim", "file_change", "monitored file deleted", "监控文件已删除"},
		{"native_fim", "file_change", "monitored file modified", "监控文件内容已修改"},
		{"native_fim", "file_change", "monitored file missing", "监控文件不存在"},
		{"policies", "policy_check", "自定义策略说明", "自定义策略说明"},
		{"policies", "policy_check", "custom policy diagnostic", "custom policy diagnostic"},
		{"test", "webhook_test", "Host policy compliance checked", "Host policy compliance checked"},
		{"policies", "future_kind", "Host policy compliance checked", "Host policy compliance checked"},
		{"security", "collector_error", "open /var/log/audit/audit.log: permission denied", "open /var/log/audit/audit.log: permission denied"},
	} {
		t.Run(tc.source+"/"+tc.kind+"/"+tc.message, func(t *testing.T) {
			if got := securityNotificationMessage(tc.source, tc.kind, tc.message); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	data := mustJSON(t, map[string]any{"source": "future_source", "kind": "future_kind", "severity": "future_severity", "message": "custom diagnostic"})
	text := NotificationText(Event{Type: "security_event", Data: data})
	for _, want := range []string{"来源：future_source", "类型：future_kind", "级别：future_severity", "内容：custom diagnostic"} {
		if !strings.Contains(text, want) {
			t.Fatalf("unknown metadata lost: %s", text)
		}
	}
}
