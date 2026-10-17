package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestEventPolicySettingsValidateAndSurviveRestart(t *testing.T) {
	store, dir := testStore(t)
	srv := testServer(store)
	const path = "/api/settings/event-policy"
	requireStatus(t, testRequest(t, srv, "GET", path, nil, nil, nil), 401)
	requireStatus(t, testRequest(t, srv, "PUT", path, defaultEventPolicy(), nil, nil), 401)
	cookie := testLogin(t, srv, DefaultPassword)
	response := testRequest(t, srv, "GET", path, nil, cookie, nil)
	requireStatus(t, response, 200)
	if got := jsonResult[EventPolicy](t, response); !reflect.DeepEqual(got, defaultEventPolicy()) {
		t.Fatalf("wrong defaults: %+v", got)
	}
	want := EventPolicy{TetragonIgnoredKinds: []string{"process_exec", "process_exit"}, ScanSummaryRetentionHours: 12}
	requireStatus(t, testRequest(t, srv, "PUT", path, want, cookie, map[string]string{"Origin": "https://untrusted.example"}), 403)
	requireStatus(t, testRequest(t, srv, "PUT", path, want, cookie, nil), 200)
	for _, invalid := range []any{
		map[string]any{},
		map[string]any{"tetragon_ignored_kinds": nil, "scan_summary_retention_hours": 12},
		map[string]any{"tetragon_ignored_kinds": []string{}, "scan_summary_retention_hours": 0},
		map[string]any{"tetragon_ignored_kinds": []string{}, "scan_summary_retention_hours": 48},
		map[string]any{"tetragon_ignored_kinds": []string{"collector_error"}, "scan_summary_retention_hours": 24},
		map[string]any{"tetragon_ignored_kinds": []string{"process_exec", "process_exec"}, "scan_summary_retention_hours": 24},
		map[string]any{"tetragon_ignored_kinds": []string{}, "scan_summary_retention_hours": 12, "unknown": true},
	} {
		requireStatus(t, testRequest(t, srv, "PUT", path, invalid, cookie, nil), 400)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.EventPolicy(context.Background())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("saved policy changed after invalid requests/restart: %+v %v", got, err)
	}
}

func tetragonPolicyData(source, kind string) map[string]any {
	return map[string]any{"source": source, "kind": kind, "severity": "warning", "message": "observed event"}
}

func TestTetragonFilterPreservesPresenceHistoryAndOtherSources(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()
	insertHook(t, store, "hook", "http://127.0.0.1/unused", "generic", true)
	at := time.Now().UTC()
	requireIngest(t, store, testPacket(t, "before-filter", "security_event", "10.0.0.1", at, tetragonPolicyData("tetragon", "process_exec")), "127.0.0.1", true)
	if err := store.SaveEventPolicy(ctx, EventPolicy{TetragonIgnoredKinds: []string{"process_exec", "process_exit"}, ScanSummaryRetentionHours: 24}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`UPDATE machines SET last_seen=0; INSERT INTO machine_offline_state(machine_ip,event_id) VALUES('10.0.0.1','old-incident')`); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"process_exec", "process_exit"} {
		requireIngest(t, store, testPacket(t, "filtered-"+kind, "security_event", "10.0.0.1", at.Add(time.Second), tetragonPolicyData("tetragon", kind)), "127.0.0.1", false)
	}
	if countRows(t, store, "events") != 1 || countRows(t, store, "outbox") != 1 || countRows(t, store, "machine_offline_state") != 0 {
		t.Fatal("filter inserted events/notifications, deleted history, or failed to rearm presence")
	}
	machine, err := store.Machine(ctx, "10.0.0.1")
	if err != nil || machine.LastSeen.Before(at) {
		t.Fatalf("filtered report did not refresh presence: %+v %v", machine, err)
	}
	requireIngest(t, store, testPacket(t, "other-source", "security_event", "10.0.0.1", at, tetragonPolicyData("auditd", "process_exec")), "127.0.0.1", true)
	requireIngest(t, store, testPacket(t, "other-kind", "security_event", "10.0.0.1", at, tetragonPolicyData("tetragon", "process_kprobe")), "127.0.0.1", true)
	if countRows(t, store, "events") != 3 || countRows(t, store, "outbox") != 3 {
		t.Fatal("filter affected other sources or unselected types")
	}
	if err := store.SaveEventPolicy(ctx, defaultEventPolicy()); err != nil {
		t.Fatal(err)
	}
	requireIngest(t, store, testPacket(t, "restored", "security_event", "10.0.0.1", at, tetragonPolicyData("tetragon", "process_exec")), "127.0.0.1", true)
}

func TestFilteredTetragonReportsAreAcknowledged(t *testing.T) {
	store, _ := testStore(t)
	if err := store.SaveEventPolicy(context.Background(), EventPolicy{TetragonIgnoredKinds: []string{"process_exec"}, ScanSummaryRetentionHours: 24}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- store.ServeUDP(ctx, listener, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	defer func() { cancel(); listener.Close(); <-done }()
	client, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var envelope Envelope
	if err = json.Unmarshal(testPacket(t, "filtered-ack", "security_event", "10.0.0.2", time.Now(), tetragonPolicyData("tetragon", "process_exec")), &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.AckRequested = true
	packet, _ := json.Marshal(envelope)
	for range 2 {
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = client.Write(packet); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1024)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		var ack struct {
			Type string `json:"type"`
			ID   string `json:"event_id"`
		}
		if err = json.Unmarshal(buf[:n], &ack); err != nil || ack.Type != "ack" || ack.ID != envelope.EventID {
			t.Fatalf("invalid filtered-event ACK: %s (%v)", buf[:n], err)
		}
	}
	if countRows(t, store, "events") != 0 || countRows(t, store, "machines") != 1 {
		t.Fatal("filtered ACK did not reflect committed presence without event insertion")
	}
}

func TestV7EventPolicyMigrationKeepsExistingData(t *testing.T) {
	store, dir := testStore(t)
	insertHook(t, store, "retained", "http://127.0.0.1/unused", "generic", true)
	requireIngest(t, store, testPacket(t, "retained", "alert", "10.0.0.1", time.Now(), testAlert()), "127.0.0.1", true)
	if _, err := store.DB.Exec(`DROP TABLE event_policy; DROP INDEX outbox_event_id; PRAGMA user_version=7;`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var version int
	if err := reopened.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 8 {
		t.Fatalf("wrong migration version: %d %v", version, err)
	}
	if countRows(t, reopened, "events") != 1 || countRows(t, reopened, "outbox") != 1 {
		t.Fatal("event policy migration lost existing data")
	}
	policy, err := reopened.EventPolicy(context.Background())
	if err != nil || !reflect.DeepEqual(policy, defaultEventPolicy()) {
		t.Fatalf("invalid migrated defaults: %+v %v", policy, err)
	}
}
