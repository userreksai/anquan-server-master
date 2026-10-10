package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestFirstHeartbeatRegistersOnlineWithoutHistoryAndRecoversFromOffline(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	at := time.Now().UTC()
	insertHook(t, s, "notify", "http://127.0.0.1/unused", "generic", true)
	packet := testPacket(t, "heartbeat-first", "heartbeat", "10.0.0.1", at, map[string]any{"interval_seconds": 30, "state": "running", "version": "test"})
	requireIngest(t, s, packet, "192.0.2.1", true)
	assertPresence := func(online bool) {
		t.Helper()
		m, err := s.Machine(ctx, "10.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		wantStatus := "abnormal_offline"
		if online {
			wantStatus = "online"
		}
		if m.Online != online || m.Status != wantStatus || m.OfflineAfterSeconds != 90 || m.HeartbeatIntervalSeconds != 30 || m.IntervalSeconds != 300 {
			t.Fatalf("wrong presence: %+v", m)
		}
		list, err := s.Machines(ctx, Filter{Page: 1, Size: 10})
		if err != nil || len(list.Items) != 1 || list.Items[0].Status != wantStatus {
			t.Fatalf("list differs: %+v %v", list, err)
		}
		overview, err := s.Overview(ctx)
		if err != nil {
			t.Fatal(err)
		}
		wantOnline := 0
		if online {
			wantOnline = 1
		}
		if overview.Machines != 1 || overview.OnlineMachines != wantOnline || overview.Events != 0 || overview.PendingNotifications != 0 {
			t.Fatalf("overview differs: %+v", overview)
		}
	}
	assertPresence(true)
	if countRows(t, s, "events") != 0 || countRows(t, s, "outbox") != 0 {
		t.Fatal("heartbeat polluted event history/notifications")
	}
	if _, err := s.DB.Exec(`UPDATE machines SET last_seen=? WHERE ip='10.0.0.1'`, stamp(time.Now().Add(-91*time.Second))); err != nil {
		t.Fatal(err)
	}
	assertPresence(false)
	requireIngest(t, s, testPacket(t, "heartbeat-return", "heartbeat", "10.0.0.1", at.Add(time.Second), map[string]int{"interval_seconds": 30}), "192.0.2.1", true)
	assertPresence(true)
	if _, err := s.DB.Exec(`UPDATE machines SET last_seen=? WHERE ip='10.0.0.1'`, stamp(time.Now().Add(-89*time.Second))); err != nil {
		t.Fatal(err)
	}
	assertPresence(true)
}

func TestHeartbeatOrderingLegacyTimeoutAndMalformedPackets(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	at := time.Now().UTC()
	requireIngest(t, s, testPacket(t, "summary", "scan_summary", "10.0.0.1", at, map[string]any{"collection_success": true, "interval_seconds": 300}), "127.0.0.1", true)
	if _, err := s.DB.Exec(`UPDATE machines SET last_seen=?`, stamp(time.Now().Add(-899*time.Second))); err != nil {
		t.Fatal(err)
	}
	m, err := s.Machine(ctx, "10.0.0.1")
	if err != nil || !m.Online || m.OfflineAfterSeconds != 900 {
		t.Fatalf("legacy threshold changed: %+v %v", m, err)
	}
	if _, err := s.DB.Exec(`UPDATE machines SET last_seen=?`, stamp(time.Now().Add(-901*time.Second))); err != nil {
		t.Fatal(err)
	}
	m, err = s.Machine(ctx, "10.0.0.1")
	if err != nil || m.Status != "abnormal_offline" {
		t.Fatalf("legacy offline missing: %+v %v", m, err)
	}
	requireIngest(t, s, testPacket(t, "hb-new", "heartbeat", "10.0.0.1", at.Add(time.Minute), map[string]int{"interval_seconds": 30}), "127.0.0.1", true)
	var old Envelope
	if err := json.Unmarshal(testPacket(t, "hb-old", "heartbeat", "10.0.0.1", at, map[string]int{"interval_seconds": 300}), &old); err != nil {
		t.Fatal(err)
	}
	old.Host = "stale-host"
	b, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	requireIngest(t, s, b, "127.0.0.1", true)
	m, err = s.Machine(ctx, "10.0.0.1")
	if err != nil || m.HeartbeatIntervalSeconds != 30 || m.Host != "node-a" || m.OfflineAfterSeconds != 90 {
		t.Fatalf("late heartbeat rolled settings back: %+v %v", m, err)
	}
	for _, data := range []any{map[string]int{}, map[string]int{"interval_seconds": 0}, map[string]int{"interval_seconds": -1}, map[string]int{"interval_seconds": 86401}, map[string]any{"interval_seconds": nil}} {
		if ok, err := s.Ingest(ctx, testPacket(t, "bad", "heartbeat", "10.0.0.2", at, data), "127.0.0.1"); err == nil || ok {
			t.Fatalf("invalid heartbeat accepted: %+v %v", data, err)
		}
	}
	if countRows(t, s, "machines") != 1 || countRows(t, s, "events") != 1 {
		t.Fatal("invalid/valid heartbeats created history or partial machine rows")
	}
	for _, tc := range []struct{ scan, hb, want int }{{1, 0, 120}, {300, 0, 900}, {300, 1, 30}, {300, 30, 90}} {
		online, status, seconds := machinePresence(at, tc.scan, tc.hb, at.Add(time.Duration(tc.want)*time.Second))
		if !online || status != "online" || seconds != tc.want {
			t.Fatalf("threshold boundary mismatch: %+v %v %s %d", tc, online, status, seconds)
		}
		online, status, _ = machinePresence(at, tc.scan, tc.hb, at.Add(time.Duration(tc.want)*time.Second+time.Millisecond))
		if online || status != "abnormal_offline" {
			t.Fatalf("post-threshold state mismatch: %+v", tc)
		}
	}
}

func TestVersionOneMigrationPreservesHistoryCredentialsAndOutbox(t *testing.T) {
	s, dir := testStore(t)
	ctx := context.Background()
	if err := s.ResetAdmin(ctx, "migration-custom-password"); err != nil {
		t.Fatal(err)
	}
	insertHook(t, s, "retained", "http://127.0.0.1/unused", "generic", true)
	requireIngest(t, s, testPacket(t, "history", "alert", "10.0.0.1", time.Now(), testAlert()), "127.0.0.1", true)
	if _, err := s.DB.Exec(`UPDATE machines SET alias='retained alias',notes='retained notes'; INSERT INTO sessions(token_hash,username,expires_at) VALUES('retained-session','admin',9999999999999); ALTER TABLE machines DROP COLUMN heartbeat_interval_seconds; ALTER TABLE machines DROP COLUMN last_heartbeat_at; PRAGMA user_version=1;`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var version int
	var hash string
	if err := reopened.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 5 {
		t.Fatalf("migration version=%d error=%v", version, err)
	}
	if err := reopened.DB.QueryRow(`SELECT password_hash FROM users WHERE username='admin'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("migration-custom-password")); err != nil {
		t.Fatal("migration restored default password")
	}
	for _, table := range []string{"machines", "events", "webhooks", "outbox", "sessions"} {
		if countRows(t, reopened, table) != 1 {
			t.Fatalf("migration lost %s", table)
		}
	}
	m, err := reopened.Machine(ctx, "10.0.0.1")
	if err != nil || m.Alias != "retained alias" || m.Notes != "retained notes" || m.HeartbeatIntervalSeconds != 0 || m.OfflineAfterSeconds != 900 {
		t.Fatalf("legacy machine damaged: %+v %v", m, err)
	}
	requireIngest(t, reopened, testPacket(t, "first-v2-heartbeat", "heartbeat", "10.0.0.1", time.Now(), map[string]int{"interval_seconds": 30}), "127.0.0.1", true)
	m, err = reopened.Machine(ctx, "10.0.0.1")
	if err != nil || m.HeartbeatIntervalSeconds != 30 || m.OfflineAfterSeconds != 90 || countRows(t, reopened, "events") != 1 {
		t.Fatalf("migrated machine did not accept heartbeat: %+v %v", m, err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	m, err = again.Machine(ctx, "10.0.0.1")
	if err != nil || m.HeartbeatIntervalSeconds != 30 {
		t.Fatalf("v2 reopen lost settings: %+v %v", m, err)
	}
}
