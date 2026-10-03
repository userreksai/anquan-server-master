package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMalformedDatagramsCannotCreatePartialMachinesOrEvents(t *testing.T) {
	s, _ := testStore(t)
	valid := testPacket(t, "valid", "alert", "10.0.0.1", time.Now(), testAlert())
	cases := map[string][]byte{"empty": nil, "oversize": []byte(strings.Repeat("x", MaxDatagram+1)), "malformed": []byte(`{"version":`), "trailing": append(append([]byte{}, valid...), []byte(` {}`)...)}
	for name, mutate := range map[string]func(*Envelope){
		"version":            func(e *Envelope) { e.Version = 2 },
		"identity":           func(e *Envelope) { e.EventID = " " },
		"host":               func(e *Envelope) { e.Host = "" },
		"ip":                 func(e *Envelope) { e.IP = "0.0.0.0" },
		"unknown-type":       func(e *Envelope) { e.Type = "command" },
		"null-data":          func(e *Envelope) { e.Data = []byte(`null`) },
		"array-data":         func(e *Envelope) { e.Data = []byte(`[]`) },
		"missing-alert-kind": func(e *Envelope) { e.Data = []byte(`{"message":"bad"}`) },
		"invalid-summary":    func(e *Envelope) { e.Type = "scan_summary"; e.Data = []byte(`{"collection_success":true,"alerts":-1}`) },
		"invalid-login": func(e *Envelope) {
			e.Type = "ssh_login"
			e.Data = []byte(`{"user":"root","source_ip":"not-an-ip","login_time":"2026-10-02T08:00:00Z"}`)
		},
		"zero-time": func(e *Envelope) { e.Time = time.Time{} },
	} {
		var e Envelope
		if err := json.Unmarshal(valid, &e); err != nil {
			t.Fatal(err)
		}
		mutate(&e)
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		cases[name] = b
	}
	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			if inserted, err := s.Ingest(context.Background(), packet, "192.0.2.1"); err == nil || inserted {
				t.Fatalf("malformed packet accepted: %v %v", inserted, err)
			}
		})
	}
	if _, err := s.Ingest(context.Background(), valid, "invalid-source"); err == nil {
		t.Fatal("invalid transport source accepted")
	}
	for _, table := range []string{"machines", "events", "outbox"} {
		if n := countRows(t, s, table); n != 0 {
			t.Fatalf("%s has %d partial rows", table, n)
		}
	}
}

func TestUDPIdentityDedupLegacyLoginAndOutOfOrderPersistence(t *testing.T) {
	s, dir := testStore(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	insertHook(t, s, "notify", "http://127.0.0.1/unused", "generic", true)
	alert := testPacket(t, "same-id", "alert", "10.0.0.1", at, testAlert())
	requireIngest(t, s, alert, "192.0.2.1", true)
	requireIngest(t, s, alert, "192.0.2.1", false)
	requireIngest(t, s, testPacket(t, "same-id", "alert", "10.0.0.2", at, testAlert()), "192.0.2.1", true)
	if countRows(t, s, "outbox") != 2 {
		t.Fatal("duplicate event queued another notification or NAT merged nodes")
	}
	// Old v1 envelopes have no ip. Local/wtmp login records can legitimately
	// lack source_ip, and their occurrence time predates the scan.
	loginAt := at.Add(-24 * time.Hour)
	login := map[string]any{"id": "login-a", "user": "root", "source_ip": "", "terminal": "tty1", "login_time": loginAt}
	requireIngest(t, s, testPacket(t, "old-scan-1", "ssh_login", "", at, login), "192.0.2.9", true)
	requireIngest(t, s, testPacket(t, "old-scan-2", "ssh_login", "", at.Add(time.Minute), login), "192.0.2.9", false)
	login["id"] = "login-b"
	requireIngest(t, s, testPacket(t, "old-scan-3", "ssh_login", "", at, login), "192.0.2.9", true)
	page, err := s.Events(ctx, Filter{Page: 1, Size: 100, MachineIP: "192.0.2.9", Type: "ssh_login", From: &loginAt, To: &loginAt})
	if err != nil || page.Total != 2 || !page.Items[0].Time.Equal(loginAt) {
		t.Fatalf("legacy login time/identity: %+v %v", page, err)
	}
	legacy := testPacket(t, "old-summary", "scan_summary", "", at, map[string]any{"collection_success": true, "alerts": 0})
	requireIngest(t, s, legacy, "192.0.2.9", true)
	m, err := s.Machine(ctx, "192.0.2.9")
	if err != nil || m.IntervalSeconds != 300 || !m.Online {
		t.Fatalf("legacy interval/status: %+v %v", m, err)
	}
	requireIngest(t, s, testPacket(t, "new-summary", "scan_summary", "", at.Add(time.Hour), map[string]any{"collection_success": true, "interval_seconds": 900, "files": 9}), "192.0.2.9", true)
	requireIngest(t, s, testPacket(t, "missing-interval", "scan_summary", "", at.Add(2*time.Hour), map[string]any{"collection_success": true, "files": 10}), "192.0.2.9", true)
	before, err := s.Machine(ctx, "192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	if before.IntervalSeconds != 900 {
		t.Fatal("older client erased configured heartbeat interval")
	}
	var late Envelope
	if err := json.Unmarshal(legacy, &late); err != nil {
		t.Fatal(err)
	}
	late.Host = "old-host"
	late.EventID = "late-summary"
	b, err := json.Marshal(late)
	if err != nil {
		t.Fatal(err)
	}
	requireIngest(t, s, b, "192.0.2.9", true)
	after, err := s.Machine(ctx, "192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	if after.Host != before.Host || string(after.LastSummary) != string(before.LastSummary) || after.IntervalSeconds != 900 || after.LastEventAt.Before(before.LastEventAt) {
		t.Fatal("out-of-order event rolled machine state backward")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if countRows(t, reopened, "events") != 8 || countRows(t, reopened, "machines") != 3 || countRows(t, reopened, "outbox") != 2 {
		t.Fatal("reopening database lost durable events or outbox")
	}
	requireIngest(t, reopened, alert, "192.0.2.1", false)
}

func TestLegacyLoginFallbackCanonicalizesIPForDedup(t *testing.T) {
	s, _ := testStore(t)
	at := time.Now().UTC()
	login := map[string]any{"user": "ops", "terminal": "pts/1", "source_ip": "2001:0db8::1", "login_time": at}
	requireIngest(t, s, testPacket(t, "a", "ssh_login", "10.0.0.1", at, login), "192.0.2.1", true)
	login["source_ip"] = "2001:db8::1"
	requireIngest(t, s, testPacket(t, "b", "ssh_login", "10.0.0.1", at.Add(time.Second), login), "192.0.2.1", false)
}
