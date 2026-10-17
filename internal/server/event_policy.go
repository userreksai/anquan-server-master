package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

type EventPolicy struct {
	TetragonIgnoredKinds      []string `json:"tetragon_ignored_kinds"`
	ScanSummaryRetentionHours int      `json:"scan_summary_retention_hours"`
	SecurityEventMinSeverity  string   `json:"security_event_min_severity"`
}

var tetragonEventKinds = []string{"process_exec", "process_exit", "process_kprobe", "process_tracepoint", "process_loader", "process_uprobe", "process_lsm", "process_usdt", "runtime"}

func defaultEventPolicy() EventPolicy {
	return EventPolicy{TetragonIgnoredKinds: []string{}, ScanSummaryRetentionHours: 24, SecurityEventMinSeverity: "warning"}
}

func securitySeverityRank(severity string) int {
	return slices.Index([]string{"debug", "info", "notice", "warning", "error", "critical"}, severity)
}

// Legacy agents used syscall failure alone to label ordinary exec observations
// as warnings. Match only that exact built-in report; retain original evidence
// when the operator explicitly selects info or debug recording.
func effectiveSecuritySeverity(source, kind, severity, message string, data json.RawMessage) string {
	if source == "auditd" && kind == "exec" && severity == "warning" && message == "Linux audit exec" && builtinAuditExecEvidence(data) {
		return "info"
	}
	return severity
}

var auditRecordKeyPattern = regexp.MustCompile(`(?:^|[[:space:]])key=("[^"]*"|'[^']*'|[^[:space:]]+)`)

func builtinAuditExecEvidence(data json.RawMessage) bool {
	var evidence struct {
		Fields  map[string]string `json:"fields"`
		Records []string          `json:"records"`
	}
	if json.Unmarshal(data, &evidence) != nil {
		return false
	}
	found := false
	if key, ok := evidence.Fields["key"]; ok {
		if key != "anquan_exec" {
			return false
		}
		found = true
	}
	for _, record := range evidence.Records {
		for _, match := range auditRecordKeyPattern.FindAllStringSubmatch(record, -1) {
			// Any custom or multiple-key value preserves warning severity,
			// even if the flattened fields map later overwrote it.
			if strings.Trim(match[1], "\"'") != "anquan_exec" {
				return false
			}
			found = true
		}
	}
	return found
}

func (policy EventPolicy) retainSecurityEvent(source, kind, severity, message string, data json.RawMessage) bool {
	return !(source == "tetragon" && slices.Contains(policy.TetragonIgnoredKinds, kind)) &&
		securitySeverityRank(effectiveSecuritySeverity(source, kind, severity, message, data)) >= securitySeverityRank(policy.SecurityEventMinSeverity)
}

func validateEventPolicy(policy EventPolicy) error {
	if policy.ScanSummaryRetentionHours != 12 && policy.ScanSummaryRetentionHours != 24 {
		return errors.New("巡检记录保留时间只能为 12 或 24 小时")
	}
	if securitySeverityRank(policy.SecurityEventMinSeverity) < 0 {
		return errors.New("安全运行事件最低级别只能为 debug、info、notice、warning、error 或 critical")
	}
	seen := map[string]bool{}
	for _, kind := range policy.TetragonIgnoredKinds {
		if !slices.Contains(tetragonEventKinds, kind) {
			return fmt.Errorf("不支持屏蔽的 Tetragon 事件类型：%s", kind)
		}
		if seen[kind] {
			return fmt.Errorf("Tetragon 事件类型重复：%s", kind)
		}
		seen[kind] = true
	}
	return nil
}

// Use the caller's transaction during ingestion: the database has one writer
// connection, so querying the Store while holding a transaction would deadlock.
func readEventPolicy(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (EventPolicy, error) {
	policy := defaultEventPolicy()
	var raw string
	err := q.QueryRowContext(ctx, `SELECT tetragon_ignored_kinds,scan_summary_retention_hours,security_event_min_severity FROM event_policy WHERE id=1`).Scan(&raw, &policy.ScanSummaryRetentionHours, &policy.SecurityEventMinSeverity)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultEventPolicy(), nil
	}
	if err != nil {
		return policy, err
	}
	if err = json.Unmarshal([]byte(raw), &policy.TetragonIgnoredKinds); err != nil {
		return policy, err
	}
	if policy.TetragonIgnoredKinds == nil {
		policy.TetragonIgnoredKinds = []string{}
	}
	return policy, validateEventPolicy(policy)
}

func (s *Store) EventPolicy(ctx context.Context) (EventPolicy, error) {
	return readEventPolicy(ctx, s.DB)
}

func (s *Store) SaveEventPolicy(ctx context.Context, policy EventPolicy) error {
	_, err := s.saveEventPolicy(ctx, policy)
	return err
}

func (s *Store) saveEventPolicy(ctx context.Context, policy EventPolicy) (EventPolicy, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return policy, err
	}
	defer tx.Rollback()
	if policy.SecurityEventMinSeverity == "" {
		// Old clients only know the original two settings. Their saves must not
		// reset the operator's newer severity threshold.
		current, err := readEventPolicy(ctx, tx)
		if err != nil {
			return policy, err
		}
		policy.SecurityEventMinSeverity = current.SecurityEventMinSeverity
	}
	if err := validateEventPolicy(policy); err != nil {
		return policy, err
	}
	if policy.TetragonIgnoredKinds == nil {
		policy.TetragonIgnoredKinds = []string{}
	}
	raw, err := json.Marshal(policy.TetragonIgnoredKinds)
	if err != nil {
		return policy, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO event_policy(id,tetragon_ignored_kinds,scan_summary_retention_hours,security_event_min_severity) VALUES(1,?,?,?)
ON CONFLICT(id) DO UPDATE SET tetragon_ignored_kinds=excluded.tetragon_ignored_kinds,scan_summary_retention_hours=excluded.scan_summary_retention_hours,security_event_min_severity=excluded.security_event_min_severity`, string(raw), policy.ScanSummaryRetentionHours, policy.SecurityEventMinSeverity)
	if err != nil {
		return policy, err
	}
	return policy, tx.Commit()
}

func (s *Server) getEventPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := s.Store.EventPolicy(r.Context())
	s.respond(w, policy, err)
}

func (s *Server) saveEventPolicy(w http.ResponseWriter, r *http.Request) {
	var request struct {
		TetragonIgnoredKinds      *[]string `json:"tetragon_ignored_kinds"`
		ScanSummaryRetentionHours *int      `json:"scan_summary_retention_hours"`
		SecurityEventMinSeverity  *string   `json:"security_event_min_severity"`
	}
	if !decode(w, r, &request) {
		return
	}
	if request.TetragonIgnoredKinds == nil || request.ScanSummaryRetentionHours == nil {
		fail(w, 400, "请提供屏蔽事件类型列表和巡检记录保留时间")
		return
	}
	policy := EventPolicy{TetragonIgnoredKinds: *request.TetragonIgnoredKinds, ScanSummaryRetentionHours: *request.ScanSummaryRetentionHours}
	if request.SecurityEventMinSeverity != nil {
		policy.SecurityEventMinSeverity = *request.SecurityEventMinSeverity
	}
	validation := policy
	if request.SecurityEventMinSeverity == nil {
		validation.SecurityEventMinSeverity = defaultEventPolicy().SecurityEventMinSeverity
	}
	if err := validateEventPolicy(validation); err != nil {
		fail(w, 400, err.Error())
		return
	}
	policy, err := s.Store.saveEventPolicy(r.Context(), policy)
	s.respond(w, policy, err)
}
