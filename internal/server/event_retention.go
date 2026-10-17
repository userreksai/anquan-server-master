package server

import (
	"context"
	"fmt"
	"time"
)

const scanSummaryPruneBatchSize = 1000

// PruneScanSummaries removes one bounded batch using the event occurrence time.
// Current machine summaries and all other event types remain available.
func (s *Store) PruneScanSummaries(ctx context.Context, now time.Time) (int64, error) {
	policy, err := s.EventPolicy(ctx)
	if err != nil {
		return 0, fmt.Errorf("read event retention policy: %w", err)
	}
	cutoff := now.Add(-time.Duration(policy.ScanSummaryRetentionHours) * time.Hour)
	result, err := s.DB.ExecContext(ctx, `DELETE FROM events WHERE id IN (
 SELECT id FROM events WHERE type='scan_summary' AND time<?
 ORDER BY time,id LIMIT 1000
)`, stamp(cutoff))
	if err != nil {
		return 0, fmt.Errorf("prune scan summaries: %w", err)
	}
	return result.RowsAffected()
}

// RunEventRetention cleans up immediately and once per minute afterwards. A
// backlog is drained in small transactions with a pause between batches so the
// single SQLite connection remains available to incoming reports and requests.
func (s *Server) RunEventRetention(ctx context.Context) {
	s.runEventRetention(ctx, time.Minute)
}

func (s *Server) runEventRetention(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var nextErrorLog time.Time
	for ctx.Err() == nil {
		now := time.Now()
		for ctx.Err() == nil {
			removed, err := s.Store.PruneScanSummaries(ctx, now)
			if err != nil {
				if ctx.Err() == nil && !time.Now().Before(nextErrorLog) {
					s.Logger.Error("清理过期巡检记录失败", "error", err)
					nextErrorLog = time.Now().Add(time.Minute)
				}
				break
			}
			if removed < scanSummaryPruneBatchSize {
				break
			}
			pause := time.NewTimer(10 * time.Millisecond)
			select {
			case <-ctx.Done():
				pause.Stop()
				return
			case <-pause.C:
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
