package server

import (
	"encoding/json"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type nativeFIMNotificationDetails struct {
	Change                    string          `json:"change"`
	PreviousContentStatus     string          `json:"previous_content_status"`
	CurrentContentStatus      string          `json:"current_content_status"`
	TextOmittedTransportLimit bool            `json:"text_omitted_transport_limit"`
	PreviousText              json.RawMessage `json:"previous_text"`
	CurrentText               json.RawMessage `json:"current_text"`
	PreviousTextTruncated     bool            `json:"previous_text_truncated"`
	CurrentTextTruncated      bool            `json:"current_text_truncated"`
	previousStatusSupplied    bool
	currentStatusSupplied     bool
}

func nativeFIMDetails(source, kind string, data json.RawMessage) (nativeFIMNotificationDetails, bool) {
	if source != "native_fim" || kind != "file_change" {
		return nativeFIMNotificationDetails{}, false
	}
	if !utf8.Valid(data) {
		return nativeFIMNotificationDetails{}, false
	}
	var event struct {
		Details nativeFIMNotificationDetails `json:"details"`
	}
	if json.Unmarshal(data, &event) != nil {
		return nativeFIMNotificationDetails{}, false
	}
	var raw struct {
		Details map[string]json.RawMessage `json:"details"`
	}
	if json.Unmarshal(data, &raw) != nil || raw.Details == nil {
		return nativeFIMNotificationDetails{}, false
	}
	_, event.Details.previousStatusSupplied = raw.Details["previous_content_status"]
	_, event.Details.currentStatusSupplied = raw.Details["current_content_status"]
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

// The complete retained versions stay in event details; notification previews
// below are bounded separately and accompany this same event's status summary.
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

const nativeFIMNotificationPreviewLimit = 512

// Both versions belong to one message and one outbox job. Missing or explicitly
// suppressed capture statuses never fall back to accidentally attached text.
func nativeFIMContentPreviews(source, kind string, data json.RawMessage) string {
	details, ok := nativeFIMDetails(source, kind, data)
	if !ok {
		return ""
	}
	beforeAbsent := details.Change == "added"
	afterAbsent := details.Change == "deleted" || details.Change == "missing"
	before := nativeFIMContentPreview(details.PreviousText, details.PreviousContentStatus, details.previousStatusSupplied, details.PreviousTextTruncated, beforeAbsent, details.TextOmittedTransportLimit)
	after := nativeFIMContentPreview(details.CurrentText, details.CurrentContentStatus, details.currentStatusSupplied, details.CurrentTextTruncated, afterAbsent, details.TextOmittedTransportLimit)
	return "变更前内容：\n" + before + "\n变更后内容：\n" + after + "\n（每侧最多预览 512 字节；完整留存内容见平台事件记录。）"
}

func nativeFIMContentPreview(raw json.RawMessage, status string, supplied, truncated, absent, omitted bool) string {
	if absent || status == "not_applicable" {
		return "（此阶段文件不存在或不适用）"
	}
	if omitted {
		return "（内容未随事件传输）"
	}
	labels := map[string]string{
		"binary": "二进制文件，仅记录元数据", "sensitive": "敏感路径，未留存内容", "disabled": "未启用内容留存", "unavailable": "未采集到内容",
	}
	if label, exists := labels[status]; exists {
		return "（" + label + "）"
	}
	if supplied && status != "captured" && status != "empty" && status != "truncated" {
		return "（未提供可预览内容）"
	}
	var text *string
	if len(raw) > 0 && json.Unmarshal(raw, &text) != nil {
		return "（未提供可预览内容）"
	}
	if status == "empty" {
		if text == nil || *text == "" {
			return "（空文件）"
		}
		return "（未提供可预览内容）"
	}
	if text == nil {
		return "（未提供可预览内容）"
	}
	if *text == "" && status != "truncated" && !truncated {
		return "（空文件）"
	}
	preview, clipped := nativeFIMPreviewText(*text)
	// Indent every source line so a script cannot imitate the surrounding
	// notification headings. ESC, CR, bidi and other controls are visible escapes.
	preview, indentedClip := nativeFIMPreviewText("│ " + strings.ReplaceAll(preview, "\n", "\n│ "))
	if clipped || indentedClip || truncated || status == "truncated" {
		preview += "\n（预览已截断；已留存内容见平台事件记录）"
	}
	return preview
}

func nativeFIMPreviewText(text string) (string, bool) {
	var preview strings.Builder
	for _, r := range text {
		part := string(r)
		if r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029') {
			quoted := strconv.QuoteRuneToASCII(r)
			part = quoted[1 : len(quoted)-1]
		}
		if preview.Len()+len(part) > nativeFIMNotificationPreviewLimit {
			return preview.String(), true
		}
		preview.WriteString(part)
	}
	return preview.String(), false
}
