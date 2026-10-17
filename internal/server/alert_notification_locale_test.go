package server

import (
	"strings"
	"testing"
	"time"
)

func TestLegacyAlertNotificationKeepsEvidenceWithChineseText(t *testing.T) {
	for _, tc := range []struct {
		name, module, kind, message, before, after, want string
	}{
		{"file", "files", "modified", "monitored file modified", "900150983cd24fb0d6963f7d28e17f72", "d41d8cd98f00b204e9800998ecf8427e", "内容：监控文件已修改"},
		{"process", "processes", "deleted", "running instance count changed from 3 to 0", "3", "0", "内容：运行实例数量从 3 变为 0"},
		{"custom", "files", "modified", "custom diagnostic: permission denied", "old", "new", "内容：custom diagnostic: permission denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := mustJSON(t, map[string]any{"module": tc.module, "kind": tc.kind, "message": tc.message, "target": "/etc/app_100%.conf", "before": tc.before, "after": tc.after})
			originalData := string(data)
			event := Event{Type: "alert", EventID: "legacy-alert", MachineIP: "172.22.0.27", Host: "ip-172-22-0-27", Time: time.Date(2026, 10, 17, 20, 33, 38, 0, time.UTC), Data: data}
			text := NotificationText(event)
			for _, want := range []string{tc.want, "时间（北京时间 UTC+8）：2026-10-18 04:33:38", "目标：/etc/app_100%.conf", "变更前：" + tc.before, "变更后：" + tc.after, "事件 ID：legacy-alert"} {
				if !strings.Contains(text, want) {
					t.Fatalf("notification missing %q: %s", want, text)
				}
			}
			if event.Time.Hour() != 20 || string(event.Data) != originalData {
				t.Fatal("notification changed original event evidence")
			}
		})
	}
}
