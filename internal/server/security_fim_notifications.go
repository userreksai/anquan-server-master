package server

import (
	"encoding/json"
	"strings"
)

type nativeFIMNotificationDetails struct {
	Change                    string `json:"change"`
	PreviousContentStatus     string `json:"previous_content_status"`
	CurrentContentStatus      string `json:"current_content_status"`
	TextOmittedTransportLimit bool   `json:"text_omitted_transport_limit"`
}

func nativeFIMDetails(source, kind string, data json.RawMessage) (nativeFIMNotificationDetails, bool) {
	if source != "native_fim" || kind != "file_change" {
		return nativeFIMNotificationDetails{}, false
	}
	var event struct {
		Details nativeFIMNotificationDetails `json:"details"`
	}
	if json.Unmarshal(data, &event) != nil {
		return nativeFIMNotificationDetails{}, false
	}
	return event.Details, true
}

func securityNotificationKind(source, kind string, data json.RawMessage) string {
	if details, ok := nativeFIMDetails(source, kind, data); ok {
		labels := map[string]string{"added": "新增文件", "modified": "修改文件", "deleted": "删除文件", "missing": "文件不存在"}
		if label, exists := labels[details.Change]; exists {
			return label + "（" + kind + "）"
		}
	}
	return securityKindLabel(kind)
}

// Keep command/file contents in the authenticated event details. Chat alerts
// carry only collection status so a large script cannot inflate every send.
func nativeFIMContentSummary(source, kind string, data json.RawMessage) string {
	details, ok := nativeFIMDetails(source, kind, data)
	if !ok {
		return ""
	}
	if details.TextOmittedTransportLimit {
		return "内容超过传输上限，未随事件传输"
	}
	labels := map[string]string{
		"captured": "已留存", "empty": "已留存（空文件）", "truncated": "已留存部分内容（已截断）",
		"binary": "二进制文件，仅记录元数据", "sensitive": "敏感路径，未留存内容", "disabled": "未启用内容留存", "unavailable": "未采集到内容",
	}
	parts := []string{}
	for _, field := range []struct{ name, status string }{{"变更前", details.PreviousContentStatus}, {"变更后", details.CurrentContentStatus}} {
		if label, exists := labels[field.status]; exists {
			parts = append(parts, field.name+label)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "；") + "。详情见平台事件记录"
}
