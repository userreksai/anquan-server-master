package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSSHLoginNotificationFormatsAndMissingFields(t *testing.T) {
	at := time.Date(2026, 10, 9, 2, 42, 50, 0, time.UTC)
	data, _ := json.Marshal(map[string]any{"user": "root", "source_ip": "192.0.2.9", "terminal": "/dev/pts/1", "method": "publickey", "login_time": at})
	event := Event{EventID: "login-event", MachineIP: "10.0.0.1", Host: "boce", Type: "ssh_login", Time: at, Data: data}
	for _, format := range []string{"feishu", "wecom", "generic"} {
		t.Run(format, func(t *testing.T) {
			var payload map[string]json.RawMessage
			var key string
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				key = r.Header.Get("Idempotency-Key")
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Errorf("invalid payload: %v", err)
				}
				_, _ = io.WriteString(w, `{"code":0,"errcode":0}`)
			}))
			defer endpoint.Close()
			result, err := SendEvent(context.Background(), WebhookClient(), Webhook{URL: endpoint.URL, Format: format}, event)
			if err != nil || !result.Success || key != "10.0.0.1:login-event" {
				t.Fatalf("delivery failed: %+v %v", result, err)
			}
			for _, want := range []string{"【安全中心 SSH 登录通知】", "机器 IP：10.0.0.1", "主机：boce", "类型：ssh_login", "登录用户：root", "登录来源 IP：192.0.2.9", "终端：/dev/pts/1", "登录方式：publickey", "登录时间（北京时间 UTC+8）：2026-10-09 10:42:50", "事件 ID：login-event"} {
				if !strings.Contains(result.Text, want) {
					t.Errorf("missing login evidence %q: %s", want, result.Text)
				}
			}
			var wireText string
			switch format {
			case "feishu":
				var content map[string]string
				_ = json.Unmarshal(payload["content"], &content)
				wireText = content["text"]
			case "wecom":
				var text map[string]string
				_ = json.Unmarshal(payload["text"], &text)
				wireText = text["content"]
			case "generic":
				_ = json.Unmarshal(payload["text"], &wireText)
				if string(payload["kind"]) != `"ssh_login"` || !strings.Contains(string(payload["data"]), "192.0.2.9") {
					t.Fatal("generic payload lost login type or source")
				}
			}
			if wireText != result.Text {
				t.Fatal("login text not sent in format-specific field")
			}
		})
	}
	event.Data = json.RawMessage(`{"user":"ops"}`)
	text := NotificationText(event)
	if !strings.Contains(text, "登录来源 IP：N/A") || !strings.Contains(text, "终端：N/A") || !strings.Contains(text, "登录方式：N/A") {
		t.Fatal("missing fields not represented explicitly")
	}
}

func TestSSHLoginQueueOnlyForNewDistinctEventsAndEnabledHooks(t *testing.T) {
	s, _ := testStore(t)
	at := time.Now().UTC()
	login := map[string]any{"id": "history-login", "user": "root", "source_ip": "192.0.2.9", "login_time": at}
	old := testPacket(t, "old-login", "ssh_login", "10.0.0.1", at, login)
	requireIngest(t, s, old, "127.0.0.1", true)
	insertHook(t, s, "first", "http://127.0.0.1/unused", "feishu", true)
	insertHook(t, s, "second", "http://127.0.0.1/unused", "wecom", true)
	insertHook(t, s, "disabled", "http://127.0.0.1/unused", "generic", false)
	requireIngest(t, s, old, "127.0.0.1", false)
	if countRows(t, s, "outbox") != 0 {
		t.Fatal("existing history was retroactively notified")
	}
	login["id"] = "new-login-1"
	packet := testPacket(t, "new-login", "ssh_login", "10.0.0.1", at, login)
	requireIngest(t, s, packet, "127.0.0.1", true)
	requireIngest(t, s, packet, "127.0.0.1", false)
	requireIngest(t, s, testPacket(t, "different-envelope", "ssh_login", "10.0.0.1", at.Add(time.Hour), login), "127.0.0.1", false)
	if countRows(t, s, "outbox") != 2 {
		t.Fatal("duplicate login notified or enabled destinations missing")
	}
	login["id"] = "new-login-2"
	requireIngest(t, s, testPacket(t, "second-login", "ssh_login", "10.0.0.1", at, login), "127.0.0.1", true)
	if countRows(t, s, "outbox") != 4 {
		t.Fatal("distinct login at the same second was not notified")
	}
}
