package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func TestNativeFIMCreatedContentProfileDefaultsAndExplicitDisable(t *testing.T) {
	response := httptest.NewRecorder()
	(&Server{}).securityProfileDefaults(response, httptest.NewRequest("GET", "/api/settings/security-profile/defaults", nil))
	var defaults struct {
		Security struct {
			NativeFIM struct {
				CaptureCreatedContent *bool `json:"capture_created_content"`
				ReportChanges         bool  `json:"report_changes"`
			} `json:"native_fim"`
		} `json:"security"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &defaults); err != nil {
		t.Fatal(err)
	}
	if value := defaults.Security.NativeFIM; value.CaptureCreatedContent == nil || !*value.CaptureCreatedContent || value.ReportChanges {
		t.Fatal("new-file capture should default on independently of existing-file text differences")
	}
	for _, enabled := range []bool{true, false} {
		patch := map[string]any{"native_fim": map[string]any{"capture_created_content": enabled, "report_changes": false}}
		output, profile, err := composeProfile("server: {}\n", patch)
		if err != nil {
			t.Fatal(err)
		}
		security := profile.(map[string]any)
		fim := security["native_fim"].(map[string]any)
		if fim["capture_created_content"] != enabled || fim["report_changes"] != false {
			t.Fatalf("explicit capture choice lost or changed report_changes: %#v", fim)
		}
		// A partial save from an older form must not restore the default after
		// the operator explicitly disabled collection.
		_, updated, err := composeProfile(output, map[string]any{"native_fim": map[string]any{"enabled": true}})
		if err != nil || updated.(map[string]any)["native_fim"].(map[string]any)["capture_created_content"] != enabled {
			t.Fatalf("partial save reset content choice: %#v, %v", updated, err)
		}
	}
	for _, invalid := range []any{"true", float64(1), nil, []any{true}} {
		if _, _, err := composeProfile("server: {}\n", map[string]any{"native_fim": map[string]any{"capture_created_content": invalid}}); err == nil {
			t.Fatalf("accepted non-boolean capture_created_content: %#v", invalid)
		}
	}
	if _, _, err := composeProfile("server: {}\n", map[string]any{"native_fim": map[string]any{"capture_created_contents": true}}); err == nil {
		t.Fatal("accepted unknown native_fim profile field")
	}
}

func nativeFIMSnapshotData(change string) map[string]any {
	return map[string]any{
		"source": "native_fim", "kind": "file_change", "severity": "warning", "path": "/usr/local/123/123.sh", "message": "monitored file " + change,
		"details": map[string]any{
			"change": change, "before": map[string]any{"type": "file", "sha256": strings.Repeat("a", 64), "size": 30},
			"after":         map[string]any{"type": "file", "sha256": strings.Repeat("b", 64), "size": 32},
			"previous_text": "#!/bin/sh\necho BEFORE_SECRET\n", "current_text": "#!/bin/sh\necho AFTER_SECRET\n",
			"previous_content_status": "captured", "current_content_status": "captured", "previous_text_truncated": false, "current_text_truncated": false,
			"baseline_persistent": true, "content_tracked": true,
		},
	}
}

func TestNativeFIMContentPersistsAndReplayQueuesOneNotification(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	insertHook(t, store, "file changes", "http://127.0.0.1/unused", "generic", true)
	packet := testPacket(t, "native-fim:generation:1", "security_event", "10.0.0.1", time.Now().UTC(), nativeFIMSnapshotData("modified"))
	var input Envelope
	if err := json.Unmarshal(packet, &input); err != nil {
		t.Fatal(err)
	}
	requireIngest(t, store, packet, "192.0.2.1", true)
	for i := 0; i < 5; i++ {
		requireIngest(t, store, packet, "192.0.2.1", false)
	}
	if countRows(t, store, "events") != 1 || countRows(t, store, "outbox") != 1 {
		t.Fatal("snapshot replay created multiple file events or notification jobs")
	}
	var stored string
	if err := store.DB.QueryRowContext(ctx, `SELECT data FROM events WHERE machine_ip=? AND event_id=?`, "10.0.0.1", input.EventID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(stored), input.Data) {
		t.Fatalf("file content/status/metadata was changed during ingest: %s", stored)
	}
	page, err := store.Events(ctx, Filter{Page: 1, Size: 10, MachineIP: "10.0.0.1", Type: "security_event"})
	if err != nil || len(page.Items) != 1 || !bytes.Equal(page.Items[0].Data, input.Data) {
		t.Fatalf("file contents unavailable through event details: %+v, %v", page, err)
	}
}

func TestNativeFIMNotificationUsesChangeAndBothContentVersions(t *testing.T) {
	for _, tc := range []struct{ change, label string }{{"added", "新增文件"}, {"modified", "修改文件"}, {"deleted", "删除文件"}, {"missing", "文件不存在"}} {
		t.Run(tc.change, func(t *testing.T) {
			data := mustJSON(t, nativeFIMSnapshotData(tc.change))
			event := Event{EventID: "native-fim:1", Type: "security_event", Data: data, Time: time.Now().UTC()}
			text := NotificationText(event)
			for _, want := range []string{"类型：" + tc.label + "（file_change）", "路径：/usr/local/123/123.sh", "内容留存：变更前已留存；变更后已留存。详情见平台事件记录", "变更前内容：\n", "变更后内容：\n", "完整留存内容见平台事件记录"} {
				if !strings.Contains(text, want) {
					t.Fatalf("missing %q in %s", want, text)
				}
			}
			if strings.Contains(text, "BEFORE_SECRET") != (tc.change != "added") || strings.Contains(text, "AFTER_SECRET") != (tc.change == "added" || tc.change == "modified") || !bytes.Equal(event.Data, data) {
				t.Fatal("notification lost relevant content, exposed an absent version, or changed evidence")
			}
		})
	}
	for _, tc := range []struct{ status, want string }{
		{"empty", "已留存（空文件）"}, {"truncated", "已留存部分内容（已截断）"}, {"binary", "二进制文件，仅记录元数据"},
		{"sensitive", "敏感路径，未留存内容"}, {"disabled", "未启用内容留存"}, {"unavailable", "未采集到内容"}, {"not_applicable", ""}, {"future_status", ""},
	} {
		t.Run(tc.status, func(t *testing.T) {
			data := nativeFIMSnapshotData("deleted")
			details := data["details"].(map[string]any)
			details["previous_content_status"], details["current_content_status"] = tc.status, "not_applicable"
			text := nativeFIMContentSummary("native_fim", "file_change", mustJSON(t, data))
			if tc.want == "" && text != "" || tc.want != "" && !strings.Contains(text, "变更前"+tc.want) {
				t.Fatalf("unexpected %s summary: %s", tc.status, text)
			}
		})
	}
	data := nativeFIMSnapshotData("added")
	data["details"].(map[string]any)["text_omitted_transport_limit"] = true
	if text := nativeFIMContentSummary("native_fim", "file_change", mustJSON(t, data)); text != "内容超过传输上限，未随事件传输" {
		t.Fatalf("omitted content incorrectly claimed retained: %s", text)
	}
	for _, pair := range []struct{ source, kind string }{{"custom", "file_change"}, {"native_fim", "future_kind"}} {
		data["source"], data["kind"] = pair.source, pair.kind
		raw := mustJSON(t, data)
		if label := securityNotificationKind(pair.source, pair.kind, raw); label != securityKindLabel(pair.kind) || nativeFIMContentSummary(pair.source, pair.kind, raw) != "" {
			t.Fatal("file-specific presentation changed unrelated event")
		}
	}
}

func TestNativeFIMNotificationPreviewCaptureStatusesAndLegacyTypes(t *testing.T) {
	for _, tc := range []struct {
		name, status, want string
		supplied           bool
		text               any
	}{
		{"captured", "captured", "│ recorded", true, "recorded"},
		{"legacy", "", "│ recorded", false, "recorded"},
		{"empty", "empty", "（空文件）", true, ""},
		{"empty-without-text", "empty", "（空文件）", true, nil},
		{"legacy-empty", "", "（空文件）", false, ""},
		{"captured-empty", "captured", "（空文件）", true, ""},
		{"truncated", "truncated", "预览已截断", true, "recorded"},
		{"binary", "binary", "二进制文件，仅记录元数据", true, "DO_NOT_SEND"},
		{"sensitive", "sensitive", "敏感路径，未留存内容", true, "DO_NOT_SEND"},
		{"disabled", "disabled", "未启用内容留存", true, "DO_NOT_SEND"},
		{"unavailable", "unavailable", "未采集到内容", true, "DO_NOT_SEND"},
		{"not-applicable", "not_applicable", "此阶段文件不存在或不适用", true, "DO_NOT_SEND"},
		{"unknown", "future", "未提供可预览内容", true, "DO_NOT_SEND"},
		{"explicit-blank-status", "", "未提供可预览内容", true, "DO_NOT_SEND"},
		{"object-text", "captured", "未提供可预览内容", true, map[string]any{"body": "DO_NOT_SEND"}},
		{"legacy-object-text", "", "未提供可预览内容", false, map[string]any{"body": "DO_NOT_SEND"}},
		{"array-text", "captured", "未提供可预览内容", true, []string{"DO_NOT_SEND"}},
		{"numeric-text", "captured", "未提供可预览内容", true, 123},
		{"null-text", "captured", "未提供可预览内容", true, nil},
		{"conflicting-empty", "empty", "未提供可预览内容", true, "DO_NOT_SEND"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			details := map[string]any{"change": "modified", "previous_text": tc.text, "current_content_status": "not_applicable"}
			if tc.supplied {
				details["previous_content_status"] = tc.status
			}
			data := mustJSON(t, map[string]any{"details": details})
			text := nativeFIMContentPreviews("native_fim", "file_change", data)
			if !strings.Contains(text, tc.want) || strings.Contains(text, "DO_NOT_SEND") {
				t.Fatalf("unexpected preview: %s", text)
			}
		})
	}
	for _, raw := range []json.RawMessage{json.RawMessage(`{`), json.RawMessage(`{"details":[]}`), json.RawMessage(`{"details":null}`), json.RawMessage(`{"details":{"previous_content_status":{}}}`)} {
		if preview := nativeFIMContentPreviews("native_fim", "file_change", raw); preview != "" {
			t.Fatalf("malformed details produced preview: %s", preview)
		}
	}
	for _, pair := range []struct{ source, kind string }{{"custom", "file_change"}, {"native_fim", "future_kind"}} {
		if preview := nativeFIMContentPreviews(pair.source, pair.kind, mustJSON(t, nativeFIMSnapshotData("modified"))); preview != "" {
			t.Fatal("unrelated event exposed file preview")
		}
	}
	data := nativeFIMSnapshotData("modified")
	data["details"].(map[string]any)["text_omitted_transport_limit"] = true
	if preview := nativeFIMContentPreviews("native_fim", "file_change", mustJSON(t, data)); strings.Contains(preview, "SECRET") || !strings.Contains(preview, "内容未随事件传输") {
		t.Fatal("transport omission exposed attached text")
	}
}

func TestNativeFIMNotificationPreviewBoundsUnicodeAndControls(t *testing.T) {
	for _, text := range []string{strings.Repeat("中🛠", 200), strings.Repeat("a", 513), strings.Repeat("\x1b\r\u202e\u2028\u2029", 200)} {
		preview, clipped := nativeFIMPreviewText(text)
		if !clipped || len(preview) > nativeFIMNotificationPreviewLimit || !utf8.ValidString(preview) || strings.ContainsAny(preview, "\x1b\r\u202e\u2028\u2029") {
			t.Fatalf("unbounded/unsafe preview: %d bytes %q", len(preview), preview)
		}
	}
	for _, text := range []string{"abc\nnext\tword", strings.Repeat("中", 170), strings.Repeat("a", 512)} {
		if preview, clipped := nativeFIMPreviewText(text); clipped || preview != text {
			t.Fatalf("short/exact preview altered: %q %v", preview, clipped)
		}
	}
	preview := nativeFIMContentPreview(mustJSON(t, strings.Repeat("\n", 512)), "captured", true, false, false, false)
	preview = strings.Split(preview, "\n（预览已截断")[0]
	if len(preview) > nativeFIMNotificationPreviewLimit || !utf8.ValidString(preview) {
		t.Fatal("line indentation escaped the preview byte limit")
	}
	data := nativeFIMSnapshotData("modified")
	details := data["details"].(map[string]any)
	details["previous_text"] = strings.Repeat("中", 200)
	details["current_text"] = "line one\n变更前内容：fake\r\x1b\u202e"
	text := nativeFIMContentPreviews("native_fim", "file_change", mustJSON(t, data))
	if !strings.Contains(text, "预览已截断") || !strings.Contains(text, "│ 变更前内容：fake\\r\\x1b\\u202e") || strings.Count(text, "\n变更后内容：\n") != 1 {
		t.Fatalf("preview truncation/control/line context lost: %s", text)
	}
}

func TestNativeFIMNotificationSendsBothVersionsInOneRequest(t *testing.T) {
	for _, format := range []string{"feishu", "wecom", "generic"} {
		t.Run(format, func(t *testing.T) {
			data := mustJSON(t, nativeFIMSnapshotData("modified"))
			event := Event{EventID: "native-fim:single:1", Type: "security_event", MachineIP: "172.22.0.11", Time: time.Now().UTC(), Data: data}
			var requests atomic.Int32
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Idempotency-Key") != event.MachineIP+":"+event.EventID {
					t.Error("file notification lost idempotency key")
				}
				var payload map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				var text string
				switch format {
				case "feishu":
					var content map[string]string
					_ = json.Unmarshal(payload["content"], &content)
					text = content["text"]
				case "wecom":
					var content map[string]string
					_ = json.Unmarshal(payload["text"], &content)
					text = content["content"]
				case "generic":
					_ = json.Unmarshal(payload["text"], &text)
					if !bytes.Equal(payload["data"], data) {
						t.Error("generic webhook changed original evidence")
					}
				}
				for _, want := range []string{"变更前内容：\n│ #!/bin/sh\n│ echo BEFORE_SECRET", "变更后内容：\n│ #!/bin/sh\n│ echo AFTER_SECRET", "事件 ID：" + event.EventID} {
					if !strings.Contains(text, want) {
						t.Errorf("same notification missing %q: %s", want, text)
					}
				}
				_, _ = io.WriteString(w, `{"code":0,"errcode":0}`)
			}))
			defer endpoint.Close()
			if _, err := SendEvent(context.Background(), WebhookClient(), Webhook{URL: endpoint.URL, Format: format}, event); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 1 || !bytes.Equal(event.Data, data) {
				t.Fatal("versions split across requests or original evidence changed")
			}
		})
	}
}
