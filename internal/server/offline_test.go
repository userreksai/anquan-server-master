package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func offlineMachine(t *testing.T, s *Store, ip string, lastSeen time.Time, heartbeat int) {
	t.Helper()
	if heartbeat > 0 {
		requireIngest(t, s, testPacket(t, "register-"+ip, "heartbeat", ip, lastSeen, map[string]int{"interval_seconds": heartbeat}), "127.0.0.1", true)
	} else {
		requireIngest(t, s, testPacket(t, "register-"+ip, "scan_summary", ip, lastSeen, map[string]any{"collection_success": true, "interval_seconds": 300}), "127.0.0.1", true)
	}
	if _, err := s.DB.Exec(`UPDATE machines SET last_seen=? WHERE ip=?`, stamp(lastSeen), ip); err != nil {
		t.Fatal(err)
	}
}

func requireOffline(t *testing.T, s *Store, now time.Time, want int) {
	t.Helper()
	if n, err := s.DetectOffline(context.Background(), now); err != nil || n != want {
		t.Fatalf("offline incidents=%d want=%d error=%v", n, want, err)
	}
}

func TestOfflineThresholdsRestartRecoveryAndDeletedEvent(t *testing.T) {
	s, dir := testStore(t)
	ctx := context.Background()
	base := unstamp(stamp(time.Now().Add(-time.Hour)))
	insertHook(t, s, "enabled", "http://127.0.0.1/unused", "generic", true)
	insertHook(t, s, "disabled", "http://127.0.0.1/unused", "generic", false)
	offlineMachine(t, s, "10.0.0.1", base, 30)
	offlineMachine(t, s, "2001:db8::1", base, 0)
	requireOffline(t, s, base.Add(90*time.Second), 0)
	requireOffline(t, s, base.Add(90*time.Second+time.Millisecond), 1)
	requireOffline(t, s, base.Add(900*time.Second), 0)
	requireOffline(t, s, base.Add(900*time.Second+time.Millisecond), 1)
	page, err := s.Events(ctx, Filter{Page: 1, Size: 10, Type: "alert"})
	if err != nil || page.Total != 2 || countRows(t, s, "outbox") != 2 {
		t.Fatalf("not all machines notified exactly once: %+v %v", page, err)
	}
	m, err := s.Machine(ctx, "10.0.0.1")
	if err != nil || !m.LastSeen.Equal(base) || m.Online {
		t.Fatalf("offline alert refreshed presence: %+v %v", m, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	requireOffline(t, s, base.Add(2*time.Hour), 0)
	if countRows(t, s, "outbox") != 2 {
		t.Fatal("restart duplicated the ongoing outage")
	}
	// Deleting a visible event must not remove the ongoing incident marker.
	if _, err := s.DB.Exec(`DELETE FROM events WHERE id=?`, page.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	requireOffline(t, s, base.Add(2*time.Hour), 0)
	if ok, err := s.Ingest(ctx, []byte(`{"version":1}`), "127.0.0.1"); err == nil || ok || countRows(t, s, "machine_offline_state") != 2 {
		t.Fatal("invalid report rearmed offline notification")
	}
	requireIngest(t, s, testPacket(t, "recovered", "heartbeat", "10.0.0.1", base, map[string]int{"interval_seconds": 30}), "127.0.0.1", true)
	m, err = s.Machine(ctx, "10.0.0.1")
	if err != nil || !m.Online || countRows(t, s, "machine_offline_state") != 1 {
		t.Fatal("recovery did not rearm the machine", err)
	}
	requireOffline(t, s, m.LastSeen.Add(91*time.Second), 1)
	page, err = s.Events(ctx, Filter{Page: 1, Size: 10, Type: "alert", MachineIP: "10.0.0.1"})
	if err != nil || page.Total != 2 || page.Items[0].EventID == page.Items[1].EventID {
		t.Fatal("second outage was suppressed or reused its previous ID", err)
	}
	// A duplicate legacy summary still proves live contact and rearms detection.
	requireIngest(t, s, testPacket(t, "register-2001:db8::1", "scan_summary", "2001:db8::1", base, map[string]any{"collection_success": true, "interval_seconds": 300}), "127.0.0.1", false)
	m, err = s.Machine(ctx, "2001:db8::1")
	if err != nil || !m.Online || countRows(t, s, "machine_offline_state") != 1 {
		t.Fatal("duplicate valid report did not restore contact", err)
	}
}

func TestOfflineIncidentAndQueueCommitAtomically(t *testing.T) {
	s, _ := testStore(t)
	now := time.Now()
	offlineMachine(t, s, "10.0.0.1", now.Add(-time.Hour), 30)
	insertHook(t, s, "enabled", "http://127.0.0.1/unused", "generic", true)
	if _, err := s.DB.Exec(`CREATE TRIGGER reject_notification BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'test queue failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DetectOffline(context.Background(), now); err == nil {
		t.Fatal("queue failure ignored")
	}
	for _, table := range []string{"events", "outbox", "machine_offline_state"} {
		if countRows(t, s, table) != 0 {
			t.Fatalf("failed transaction left partial %s", table)
		}
	}
	if _, err := s.DB.Exec(`DROP TRIGGER reject_notification`); err != nil {
		t.Fatal(err)
	}
	requireOffline(t, s, now, 1)
}

func TestOfflineQueueCatchesNewlyEnabledDestinationWithoutDuplicates(t *testing.T) {
	s, _ := testStore(t)
	now := time.Now()
	offlineMachine(t, s, "10.0.0.1", now.Add(-time.Hour), 30)
	requireOffline(t, s, now, 1)
	if countRows(t, s, "outbox") != 0 {
		t.Fatal("queued without a destination")
	}
	hook := insertHook(t, s, "later", "http://127.0.0.1/unused", "generic", false)
	requireOffline(t, s, now, 0)
	if countRows(t, s, "outbox") != 0 {
		t.Fatal("queued to disabled destination")
	}
	if _, err := s.DB.Exec(`UPDATE webhooks SET enabled=1 WHERE id=?`, hook); err != nil {
		t.Fatal(err)
	}
	requireOffline(t, s, now, 0)
	requireOffline(t, s, now, 0)
	if countRows(t, s, "outbox") != 1 {
		t.Fatal("ongoing outage missed or duplicated after enabling notifications")
	}
	if _, err := s.DB.Exec(`DELETE FROM machines`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"events", "outbox", "machine_offline_state"} {
		if countRows(t, s, table) != 0 {
			t.Fatalf("deleted machine left %s", table)
		}
	}
}

func TestOfflineChineseNotificationsRetryAfterRestart(t *testing.T) {
	s, dir := testStore(t)
	ctx := context.Background()
	now := unstamp(stamp(time.Now()))
	var attempts atomic.Int32
	received := make(chan receivedWebhook, 8)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- captureWebhook(t, r)
		if r.URL.Path == "/feishu" && attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"code":0,"errcode":0}`)
	}))
	defer endpoint.Close()
	for _, format := range []string{"feishu", "wecom", "generic"} {
		insertHook(t, s, format, endpoint.URL+"/"+format, format, true)
	}
	offlineMachine(t, s, "10.0.0.1", now.Add(-91*time.Second), 30)
	if _, err := s.DB.Exec(`UPDATE machines SET alias='生产节点'`); err != nil {
		t.Fatal(err)
	}
	requireOffline(t, s, now, 1)
	srv := testServer(s)
	jobs, err := srv.due(ctx)
	if err != nil || len(jobs) != 3 {
		t.Fatal("missing delivery jobs", err)
	}
	for _, job := range jobs {
		if err := srv.deliver(ctx, job); err != nil {
			t.Fatal(err)
		}
		request := awaitCapturedWebhook(t, received)
		var text string
		switch request.Path {
		case "/feishu":
			var content map[string]string
			_ = json.Unmarshal(request.Body["content"], &content)
			text = content["text"]
		case "/wecom":
			var content map[string]string
			_ = json.Unmarshal(request.Body["text"], &content)
			text = content["content"]
		case "/generic":
			_ = json.Unmarshal(request.Body["text"], &text)
		}
		for _, want := range []string{"【安全中心：机器异常离线】", "机器 IP：10.0.0.1", "主机名：node-a", "机器别名：生产节点", "状态：异常离线", "最后上报时间（UTC）：", "离线判定时间（UTC）：", "超时阈值：90 秒", "本次持续离线仅通知一次", "事件编号："} {
			if !strings.Contains(text, want) {
				t.Errorf("missing Chinese notification field %q: %s", want, text)
			}
		}
		if strings.Contains(text, "abnormal_offline") || !strings.HasPrefix(request.Key, "10.0.0.1:master-offline-") {
			t.Fatal("notification leaked raw status or lost stable idempotency key")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	requireOffline(t, s, now.Add(time.Hour), 0)
	srv = testServer(s)
	if _, err := s.DB.Exec(`UPDATE outbox SET next_attempt_at=0 WHERE delivered_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	jobs, err = srv.due(ctx)
	if err != nil || len(jobs) != 1 {
		t.Fatal("restart lost failed notification or retried successful destinations", err)
	}
	if err := srv.deliver(ctx, jobs[0]); err != nil {
		t.Fatal(err)
	}
	_ = awaitCapturedWebhook(t, received)
	requireOffline(t, s, now.Add(2*time.Hour), 0)
	jobs, err = srv.due(ctx)
	if err != nil || len(jobs) != 0 || countRows(t, s, "events") != 1 || countRows(t, s, "outbox") != 3 || attempts.Load() != 2 {
		t.Fatal("successful offline notification was not final", err)
	}
}

func TestOfflineMonitorStartsImmediatelyAndKeepsScanning(t *testing.T) {
	s, _ := testStore(t)
	offlineMachine(t, s, "10.0.0.1", time.Now().Add(-time.Hour), 30)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); testServer(s).RunOfflineMonitor(ctx) }()
	defer func() { cancel(); <-done }()
	for want := 1; want <= 2; want++ {
		if want == 2 {
			offlineMachine(t, s, "10.0.0.2", time.Now().Add(-time.Hour), 30)
		}
		deadline := time.Now().Add(3 * time.Second)
		for countRows(t, s, "machine_offline_state") != want {
			if time.Now().After(deadline) {
				t.Fatal("background monitor did not detect all machines")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestV3MigrationPreservesDataAndDetectsExistingOfflineMachine(t *testing.T) {
	s, dir := testStore(t)
	now := time.Now()
	insertHook(t, s, "enabled", "http://127.0.0.1/unused", "generic", true)
	offlineMachine(t, s, "10.0.0.1", now.Add(-time.Hour), 30)
	if _, err := s.DB.Exec(`DROP TABLE machine_offline_state; PRAGMA user_version=3`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 4 {
		t.Fatal("v3 database not upgraded", err)
	}
	requireOffline(t, s, now, 1)
	if countRows(t, s, "machines") != 1 || countRows(t, s, "webhooks") != 1 || countRows(t, s, "outbox") != 1 {
		t.Fatal("migration lost original machine or notification settings")
	}
}
