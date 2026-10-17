package server

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func retentionMachine(t *testing.T, s *Store, now time.Time) {
	t.Helper()
	requireIngest(t, s, testPacket(t, "retention-register", "heartbeat", "10.0.0.1", now, map[string]int{"interval_seconds": 30}), "192.0.2.1", true)
	if _, err := s.DB.Exec(`UPDATE machines SET last_summary_at=?,last_summary='{"collection_success":true,"files":9}' WHERE ip='10.0.0.1'`, stamp(now)); err != nil {
		t.Fatal(err)
	}
}

func insertRetentionEvents(t *testing.T, s *Store, prefix, kind string, at, received time.Time, count int) {
	t.Helper()
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	statement, err := tx.Prepare(`INSERT INTO events(event_id,machine_ip,host,type,time,received_at,data) VALUES(?,'10.0.0.1','node-a',?,?,?,'{}')`)
	if err != nil {
		t.Fatal(err)
	}
	defer statement.Close()
	for i := 0; i < count; i++ {
		if _, err := statement.Exec(fmt.Sprintf("%s-%d", prefix, i), kind, stamp(at), stamp(received)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func retentionCount(t *testing.T, s *Store, prefix string) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM events WHERE event_id LIKE ?`, prefix+"-%").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPruneScanSummariesUsesConfiguredOccurrenceTimeBoundary(t *testing.T) {
	for _, hours := range []int{0, 12, 24} {
		t.Run(fmt.Sprintf("hours-%d", hours), func(t *testing.T) {
			s, _ := testStore(t)
			ctx := context.Background()
			now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.FixedZone("Beijing", 8*60*60))
			retentionMachine(t, s, now)
			keepHours := hours
			if hours == 0 {
				keepHours = 24
			} else if err := s.SaveEventPolicy(ctx, EventPolicy{ScanSummaryRetentionHours: hours}); err != nil {
				t.Fatal(err)
			}
			cutoff := now.Add(-time.Duration(keepHours) * time.Hour)
			insertRetentionEvents(t, s, "expired", "scan_summary", cutoff.Add(-time.Millisecond), now, 1)
			insertRetentionEvents(t, s, "boundary", "scan_summary", cutoff, now, 1)
			insertRetentionEvents(t, s, "recent", "scan_summary", cutoff.Add(time.Millisecond), now.Add(-72*time.Hour), 1)
			insertRetentionEvents(t, s, "thirteen-hours", "scan_summary", now.Add(-13*time.Hour), now, 1)
			insertRetentionEvents(t, s, "future", "scan_summary", now.Add(time.Hour), now, 1)
			for _, kind := range []string{"alert", "ssh_login", "command_history", "security_event", "component_status"} {
				insertRetentionEvents(t, s, kind, kind, now.Add(-72*time.Hour), now.Add(-72*time.Hour), 1)
			}
			hook := insertHook(t, s, "retention-alert", "http://127.0.0.1/unused", "generic", true)
			if _, err := s.DB.Exec(`INSERT INTO outbox(webhook_id,event_id,next_attempt_at) SELECT ?,id,0 FROM events WHERE event_id='alert-0'`, hook); err != nil {
				t.Fatal(err)
			}
			wantRemoved := int64(1)
			if keepHours == 12 {
				wantRemoved++
			}
			if removed, err := s.PruneScanSummaries(ctx, now); err != nil || removed != wantRemoved {
				t.Fatalf("removed=%d want=%d error=%v", removed, wantRemoved, err)
			}
			if retentionCount(t, s, "expired") != 0 {
				t.Fatal("expired summary survived")
			}
			for _, prefix := range []string{"boundary", "recent", "future", "alert", "ssh_login", "command_history", "security_event", "component_status"} {
				if retentionCount(t, s, prefix) != 1 {
					t.Fatalf("retention removed protected record %s", prefix)
				}
			}
			if countRows(t, s, "outbox") != 1 {
				t.Fatal("retention removed an alert notification")
			}
			var summary string
			var summaryAt, lastSeen int64
			if err := s.DB.QueryRow(`SELECT last_summary,last_summary_at,last_seen FROM machines WHERE ip='10.0.0.1'`).Scan(&summary, &summaryAt, &lastSeen); err != nil {
				t.Fatal(err)
			}
			if summary != `{"collection_success":true,"files":9}` || summaryAt != stamp(now) || lastSeen == 0 {
				t.Fatal("retention changed machine summary or presence")
			}
			if removed, err := s.PruneScanSummaries(ctx, now); err != nil || removed != 0 {
				t.Fatalf("second prune removed=%d error=%v", removed, err)
			}
		})
	}
}

func TestPruneScanSummariesLimitsEachBatchAndRespectsCancellation(t *testing.T) {
	s, _ := testStore(t)
	now := time.Now()
	retentionMachine(t, s, now)
	insertRetentionEvents(t, s, "backlog", "scan_summary", now.Add(-48*time.Hour), now, 2105)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if removed, err := s.PruneScanSummaries(ctx, now); removed != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled prune removed=%d error=%v", removed, err)
	}
	if retentionCount(t, s, "backlog") != 2105 {
		t.Fatal("cancelled cleanup mutated events")
	}
	for _, want := range []int64{1000, 1000, 105, 0} {
		if removed, err := s.PruneScanSummaries(context.Background(), now); removed != want || err != nil {
			t.Fatalf("batch removed=%d want=%d error=%v", removed, want, err)
		}
	}
}

func waitRetentionCount(t *testing.T, s *Store, prefix string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for retentionCount(t, s, prefix) != want {
		if time.Now().After(deadline) {
			t.Fatalf("background retention did not reach %d records for %s", want, prefix)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func stopRetention(t *testing.T, cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retention worker did not stop on cancellation")
	}
}

func TestEventRetentionStartupDrainsBacklogAndResumesAfterRestart(t *testing.T) {
	s, dir := testStore(t)
	now := time.Now()
	retentionMachine(t, s, now)
	if err := s.SaveEventPolicy(context.Background(), EventPolicy{ScanSummaryRetentionHours: 12}); err != nil {
		t.Fatal(err)
	}
	insertRetentionEvents(t, s, "startup", "scan_summary", now.Add(-13*time.Hour), now, 2105)
	insertRetentionEvents(t, s, "retained", "scan_summary", now, now, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); testServer(s).RunEventRetention(ctx) }()
	defer stopRetention(t, cancel, done)
	waitRetentionCount(t, s, "startup", 0)
	stopRetention(t, cancel, done)
	insertRetentionEvents(t, s, "after-stop", "scan_summary", now.Add(-13*time.Hour), now, 1)
	if retentionCount(t, s, "after-stop") != 1 {
		t.Fatal("stopped cleanup continued running")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { defer close(done); testServer(reopened).RunEventRetention(ctx) }()
	defer stopRetention(t, cancel, done)
	waitRetentionCount(t, reopened, "after-stop", 0)
	stopRetention(t, cancel, done)
	if retentionCount(t, reopened, "retained") != 1 {
		t.Fatal("restart removed retained records")
	}
}

func TestEventRetentionContinuesCheckingAfterStartup(t *testing.T) {
	s, _ := testStore(t)
	now := time.Now()
	retentionMachine(t, s, now)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); testServer(s).runEventRetention(ctx, 20*time.Millisecond) }()
	defer stopRetention(t, cancel, done)
	insertRetentionEvents(t, s, "first", "scan_summary", now.Add(-48*time.Hour), now, 1)
	waitRetentionCount(t, s, "first", 0)
	insertRetentionEvents(t, s, "later", "scan_summary", now.Add(-48*time.Hour), now, 1)
	waitRetentionCount(t, s, "later", 0)
}
