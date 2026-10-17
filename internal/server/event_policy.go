package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
)

type EventPolicy struct {
	TetragonIgnoredKinds      []string `json:"tetragon_ignored_kinds"`
	ScanSummaryRetentionHours int      `json:"scan_summary_retention_hours"`
}

var tetragonEventKinds = []string{"process_exec", "process_exit", "process_kprobe", "process_tracepoint", "process_loader", "process_uprobe", "process_lsm", "process_usdt", "runtime"}

func defaultEventPolicy() EventPolicy {
	return EventPolicy{TetragonIgnoredKinds: []string{}, ScanSummaryRetentionHours: 24}
}

func validateEventPolicy(policy EventPolicy) error {
	if policy.ScanSummaryRetentionHours != 12 && policy.ScanSummaryRetentionHours != 24 {
		return errors.New("巡检记录保留时间只能为 12 或 24 小时")
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
	err := q.QueryRowContext(ctx, `SELECT tetragon_ignored_kinds,scan_summary_retention_hours FROM event_policy WHERE id=1`).Scan(&raw, &policy.ScanSummaryRetentionHours)
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
	if err := validateEventPolicy(policy); err != nil {
		return err
	}
	if policy.TetragonIgnoredKinds == nil {
		policy.TetragonIgnoredKinds = []string{}
	}
	raw, err := json.Marshal(policy.TetragonIgnoredKinds)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO event_policy(id,tetragon_ignored_kinds,scan_summary_retention_hours) VALUES(1,?,?)
ON CONFLICT(id) DO UPDATE SET tetragon_ignored_kinds=excluded.tetragon_ignored_kinds,scan_summary_retention_hours=excluded.scan_summary_retention_hours`, string(raw), policy.ScanSummaryRetentionHours)
	return err
}

func (s *Server) getEventPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := s.Store.EventPolicy(r.Context())
	s.respond(w, policy, err)
}

func (s *Server) saveEventPolicy(w http.ResponseWriter, r *http.Request) {
	var request struct {
		TetragonIgnoredKinds      *[]string `json:"tetragon_ignored_kinds"`
		ScanSummaryRetentionHours *int      `json:"scan_summary_retention_hours"`
	}
	if !decode(w, r, &request) {
		return
	}
	if request.TetragonIgnoredKinds == nil || request.ScanSummaryRetentionHours == nil {
		fail(w, 400, "请提供屏蔽事件类型列表和巡检记录保留时间")
		return
	}
	policy := EventPolicy{TetragonIgnoredKinds: *request.TetragonIgnoredKinds, ScanSummaryRetentionHours: *request.ScanSummaryRetentionHours}
	if err := validateEventPolicy(policy); err != nil {
		fail(w, 400, err.Error())
		return
	}
	s.respond(w, policy, s.Store.SaveEventPolicy(r.Context(), policy))
}
