package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func securityData(severity string) map[string]any {
	return map[string]any{"source": "auditd", "kind": "exec", "severity": severity, "message": "execution observed", "command": "id", "details": map[string]any{"records": []string{"test audit record"}}}
}

func componentData(state string) map[string]any {
	return map[string]any{"components": []any{map[string]any{"name": "auditd", "enabled": true, "installed": true, "running": state == "running", "state": state, "message": "status detail"}}, "queue": map[string]any{"pending": 2}}
}

func TestSecurityEventsNotificationPolicyAndStatusOrdering(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	policy := defaultEventPolicy()
	policy.SecurityEventMinSeverity = "debug"
	if err := s.SaveEventPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	insertHook(t, s, "security", "http://127.0.0.1/unused", "generic", true)
	for _, severity := range []string{"debug", "info", "notice", "warning", "error", "critical"} {
		packet := testPacket(t, "security-"+severity, "security_event", "10.0.0.1", at, securityData(severity))
		requireIngest(t, s, packet, "127.0.0.1", true)
		requireIngest(t, s, packet, "127.0.0.1", false)
	}
	if countRows(t, s, "outbox") != 3 {
		t.Fatal("security notification severity filtering failed")
	}
	if overview, err := s.Overview(ctx); err != nil || overview.Alerts != 3 || overview.OpenAlerts != 3 {
		t.Fatalf("security alert totals missing: %+v %v", overview, err)
	}
	if machine, err := s.Machine(ctx, "10.0.0.1"); err != nil || machine.AlertCount != 3 || machine.OpenAlertCount != 3 {
		t.Fatalf("machine security alert totals missing: %+v %v", machine, err)
	}
	if _, err := s.DB.Exec(`UPDATE events SET status='resolved' WHERE event_id='security-warning'`); err != nil {
		t.Fatal(err)
	}
	if overview, err := s.Overview(ctx); err != nil || overview.OpenAlerts != 2 {
		t.Fatalf("resolved security event remained open: %+v %v", overview, err)
	}
	requireIngest(t, s, testPacket(t, "new-status", "component_status", "10.0.0.1", at, componentData("running")), "127.0.0.1", false)
	requireIngest(t, s, testPacket(t, "older-status", "component_status", "10.0.0.1", at.Add(-time.Minute), componentData("stopped")), "127.0.0.1", false)
	statuses, err := s.SecurityStatuses(ctx, "10.0.0.1")
	if err != nil || len(statuses) != 1 || !strings.Contains(string(statuses[0].Data), `"state":"running"`) {
		t.Fatalf("snapshot rolled back: %+v %v", statuses, err)
	}
	statuses, err = s.SecurityStatuses(ctx, "10.0.0.2")
	if err != nil || len(statuses) != 0 {
		t.Fatal("machine status filter failed", err)
	}
	requireIngest(t, s, testPacket(t, "abnormal-status", "component_status", "10.0.0.1", at.Add(time.Minute), componentData("stopped")), "127.0.0.1", true)
	for _, kind := range []string{"security_event", "component_status"} {
		f, err := ParseFilter(url.Values{"type": {kind}})
		if err != nil {
			t.Fatal(err)
		}
		page, err := s.Events(ctx, f)
		if err != nil || page.Total == 0 {
			t.Fatal("new events not queryable", err)
		}
	}
	if countRows(t, s, "outbox") != 3 {
		t.Fatal("status update triggered webhook")
	}
	text := NotificationText(Event{Type: "security_event", Data: mustJSON(t, securityData("warning"))})
	for _, part := range []string{"auditd", "exec", "warning", "execution observed", "id"} {
		if !strings.Contains(text, part) {
			t.Fatalf("notification dropped %q: %s", part, text)
		}
	}
	if _, err := s.DB.Exec(`DELETE FROM machines WHERE ip='10.0.0.1'`); err != nil {
		t.Fatal(err)
	}
	if countRows(t, s, "machine_security_status") != 0 {
		t.Fatal("machine deletion did not cascade status")
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSecurityIngestRejectsInvalidPayloadsBeforeMutation(t *testing.T) {
	s, _ := testStore(t)
	for _, data := range []any{map[string]any{"source": "auditd", "kind": "exec", "severity": "broken", "message": "test"}, map[string]any{"severity": "info"}} {
		if _, err := s.Ingest(context.Background(), testPacket(t, "invalid", "security_event", "10.0.0.1", time.Now(), data), "127.0.0.1"); err == nil {
			t.Fatal("accepted invalid security event")
		}
	}
	for _, data := range []any{map[string]any{}, map[string]any{"components": []any{map[string]any{"name": ""}}}, map[string]any{"components": []any{map[string]any{"name": "auditd", "running": "yes"}}}} {
		if _, err := s.Ingest(context.Background(), testPacket(t, "invalid", "component_status", "10.0.0.1", time.Now(), data), "127.0.0.1"); err == nil {
			t.Fatal("accepted invalid status")
		}
	}
	if countRows(t, s, "machines") != 0 {
		t.Fatal("invalid security payload registered machine")
	}
}

func TestComposeSecurityProfilePreservesAndMergesYAML(t *testing.T) {
	input := "# retained header\nserver:\n  addr: original.example:8123 # retained address\ncustom_extension:\n  foo: bar\nsecurity:\n  enabled: false\n  auditd:\n    enabled: true\n    rules: [\"-w /etc/passwd -p wa\"]\n  future_field: keep\n"
	output, profile, err := composeProfile(input, map[string]any{"enabled": true, "auditd": map[string]any{"audit_exec": true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"retained header", "original.example:8123 # retained address", "custom_extension:", "future_field: keep", "-w /etc/passwd -p wa", "audit_exec: true", "enabled: true"} {
		if !strings.Contains(output, part) {
			t.Fatalf("composition dropped %q:\n%s", part, output)
		}
	}
	if profile == nil {
		t.Fatal("missing merged profile")
	}
	if _, _, err := composeProfile(input, map[string]any{"future_field": "keep"}); err != nil {
		t.Fatal("unchanged existing future field rejected", err)
	}
	if _, _, err := composeProfile(input, map[string]any{"future_field": "changed"}); err == nil {
		t.Fatal("unknown existing field modification accepted")
	}
	sysctlInput := "security:\n  policies:\n    sysctl:\n      kernel.kptr_restrict: '2'\n"
	cleared, _, err := composeProfile(sysctlInput, map[string]any{"policies": map[string]any{"sysctl": map[string]any{}}})
	if err != nil || strings.Contains(cleared, "kptr_restrict") {
		t.Fatal("sysctl map deletion did not take effect", cleared, err)
	}
	readOnly, parsed, err := composeProfile(input, nil)
	if err != nil || readOnly != input || parsed == nil {
		t.Fatal("read-only parse changed YAML", err)
	}
	_, parsed, err = composeProfile("server: {}\n", nil)
	if err != nil || parsed != nil {
		t.Fatal("absent profile should be null", err)
	}
	for _, patch := range []map[string]any{{"install_missng": true}, {"auditd": map[string]any{"enabld": true}}, {"sudo": map[string]any{"enabled": "true"}}, {"policies": map[string]any{"mode": "unknown"}}} {
		if _, _, err := composeProfile(input, patch); err == nil {
			t.Fatal("accepted invalid profile patch", patch)
		}
	}
	for _, bad := range []string{"security: []\n", "x: 1\nx: 2\n", "x: 1\n---\nx: 2\n", "x: &a {foo: bar}\ny: *a\n"} {
		if _, _, err := composeProfile(bad, map[string]any{}); err == nil {
			t.Fatal("accepted ambiguous YAML", bad)
		}
	}
}

func TestSecurityAPIRequiresAuthAndSupportsComposeAndStatus(t *testing.T) {
	s, _ := testStore(t)
	server := testServer(s)
	for _, path := range []string{"/api/security/status", "/api/settings/security-profile/defaults", "/api/security/sudo-sessions"} {
		requireStatus(t, testRequest(t, server, "GET", path, nil, nil, nil), 401)
	}
	cookie := testLogin(t, server, DefaultPassword)
	response := testRequest(t, server, "GET", "/api/settings/security-profile/defaults", nil, cookie, nil)
	requireStatus(t, response, 200)
	defaults := jsonResult[map[string]any](t, response)
	if err := validateProfileValue(defaults["security"], securityProfileSchema, "security"); err != nil {
		t.Fatal("invalid defaults", err)
	}
	requireStatus(t, testRequest(t, server, "POST", "/api/settings/security-profile/compose", map[string]any{"yaml": "server: {}\n", "security": defaults["security"]}, cookie, nil), 200)
	requireStatus(t, testRequest(t, server, "POST", "/api/settings/security-profile/compose", map[string]any{"yaml": "server: {}\n", "security": nil}, cookie, nil), 400)
	requireStatus(t, testRequest(t, server, "POST", "/api/settings/security-profile/compose", map[string]any{"yaml": "server: {}\n"}, cookie, nil), 200)
	requireIngest(t, s, testPacket(t, "status", "component_status", "10.0.0.1", time.Now(), componentData("running")), "127.0.0.1", false)
	requireStatus(t, testRequest(t, server, "GET", "/api/security/status?machine_ip=bad", nil, cookie, nil), 400)
	response = testRequest(t, server, "GET", "/api/security/status?machine_ip=10.0.0.1", nil, cookie, nil)
	requireStatus(t, response, 200)
	result := jsonResult[struct {
		Items []SecurityStatus `json:"items"`
	}](t, response)
	if len(result.Items) != 1 {
		t.Fatal("status missing", response.Body.String())
	}
}

func TestSudoGrantProfileValidationAndArrayReplacement(t *testing.T) {
	valid := map[string]any{"user": "ops", "commands": []any{"/usr/bin/systemctl restart nginx.service"}, "nopasswd": false}
	input := "security:\n  sudo:\n    grants:\n      - user: old\n        commands: [/usr/bin/id]\n"
	output, _, err := composeProfile(input, map[string]any{"sudo": map[string]any{"grants": []any{valid}}})
	if err != nil || !strings.Contains(output, "user: ops") || strings.Contains(output, "user: old") {
		t.Fatal("grants were not replaced", output, err)
	}
	cleared, _, err := composeProfile(output, map[string]any{"sudo": map[string]any{"grants": []any{}}})
	if err != nil || strings.Contains(cleared, "user: ops") {
		t.Fatal("grant removal failed", cleared, err)
	}
	for _, grant := range []any{
		nil,
		map[string]any{"user": "ops", "command": []any{"/usr/bin/id"}},
		map[string]any{"user": "root ALL=(ALL)", "commands": []any{"/usr/bin/id"}},
		map[string]any{"user": "ops", "run_as": "ALL", "commands": []any{}},
		map[string]any{"user": "ALL", "commands": []any{"/usr/bin/id"}},
		map[string]any{"user": "ops", "run_as": "ALL", "commands": []any{"/usr/bin/id"}},
		map[string]any{"user": "ops", "run_as": "root,daemon", "commands": []any{"/usr/bin/id"}},
		map[string]any{"user": "ops", "commands": []any{"systemctl restart nginx"}},
		map[string]any{"user": "ops", "commands": []any{"/usr/bin/id\nALL ALL=(ALL) ALL"}},
		map[string]any{"user": "ops", "commands": []any{"/usr/bin/cat /etc/*"}},
		map[string]any{"user": "ops", "commands": []any{"/usr/bin/id"}, "nopasswd": "yes"},
	} {
		if _, _, err := composeProfile(input, map[string]any{"sudo": map[string]any{"grants": []any{grant}}}); err == nil {
			t.Fatal("invalid grant accepted", grant)
		}
	}
}

func sudoChunkData(generation, file string, offset, total int64, content []byte, complete bool) map[string]any {
	return map[string]any{"source": "sudo", "kind": "io_chunk", "severity": "info", "message": "sudo I/O upload", "details": map[string]any{"session_id": "00/00/AB", "generation": generation, "file": file, "offset": offset, "total_size": total, "content_base64": base64.StdEncoding.EncodeToString(content), "complete": complete}}
}

func TestSudoChunksDurabilityIdempotenceIsolationAndDownload(t *testing.T) {
	s, dir := testStore(t)
	server := testServer(s)
	cookie := testLogin(t, server, DefaultPassword)
	at := time.Now()
	ip := "10.0.0.1"
	last := testPacket(t, "chunk-last", "security_event", ip, at, sudoChunkData("first", "stdout", 3, 6, []byte{0, 1, 255}, true))
	requireIngest(t, s, last, "127.0.0.1", true)
	requireIngest(t, s, last, "127.0.0.1", false)
	page, err := s.SudoSessions(context.Background(), Filter{Page: 1, Size: 20, MachineIP: ip})
	if err != nil || page.Total != 1 {
		t.Fatal(page, err)
	}
	path := fmt.Sprintf("/api/security/sudo-sessions/%d/files/stdout", page.Items[0].ID)
	requireStatus(t, testRequest(t, server, "GET", path, nil, nil, nil), 401)
	requireStatus(t, testRequest(t, server, "GET", path, nil, cookie, nil), 409)
	first := testPacket(t, "chunk-first", "security_event", ip, at, sudoChunkData("first", "stdout", 0, 6, []byte("abc"), false))
	requireIngest(t, s, first, "127.0.0.1", true)
	requireIngest(t, s, testPacket(t, "new-envelope", "security_event", ip, at, sudoChunkData("first", "stdout", 0, 6, []byte("abc"), false)), "127.0.0.1", false)
	response := testRequest(t, server, "GET", path, nil, cookie, nil)
	requireStatus(t, response, 200)
	if response.Body.String() != string([]byte{'a', 'b', 'c', 0, 1, 255}) {
		t.Fatal("binary file changed", response.Body.Bytes())
	}
	if _, err := s.Ingest(context.Background(), testPacket(t, "changed", "security_event", ip, at, sudoChunkData("first", "stdout", 0, 6, []byte("xyz"), false)), "127.0.0.1"); err == nil {
		t.Fatal("offset rewrite accepted")
	}
	requireIngest(t, s, testPacket(t, "new-generation", "security_event", ip, at, sudoChunkData("second", "stdout", 0, 1, []byte("x"), true)), "127.0.0.1", true)
	if countRows(t, s, "events") != 0 || countRows(t, s, "outbox") != 0 {
		t.Fatal("sudo blobs duplicated in event history or notified")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	page, err = reopened.SudoSessions(context.Background(), Filter{Page: 1, Size: 20, MachineIP: ip})
	if err != nil || page.Total != 2 {
		t.Fatal("session persistence failed", page, err)
	}
	if _, err := reopened.DB.Exec(`DELETE FROM machines WHERE ip=?`, ip); err != nil {
		t.Fatal(err)
	}
	if countRows(t, reopened, "sudo_io_chunks") != 0 || countRows(t, reopened, "sudo_sessions") != 0 {
		t.Fatal("sudo data did not cascade on machine deletion")
	}
}

func TestSudoChunkValidationRejectsTraversalOverlapAndBadBase64(t *testing.T) {
	s, _ := testStore(t)
	for _, file := range []string{"../stdout", "unknown", "/etc/shadow"} {
		if _, err := parseSudoIOChunk(mustJSON(t, sudoChunkData("first", file, 0, 1, []byte("a"), true))); err == nil {
			t.Fatal("accepted unsafe file", file)
		}
	}
	for _, field := range []string{"session_id", "generation", "content_base64"} {
		data := sudoChunkData("first", "stdout", 0, 1, []byte("a"), true)
		data["details"].(map[string]any)[field] = "../bad"
		if _, err := parseSudoIOChunk(mustJSON(t, data)); err == nil {
			t.Fatal("accepted invalid", field)
		}
	}
	requireIngest(t, s, testPacket(t, "chunk", "security_event", "10.0.0.1", time.Now(), sudoChunkData("first", "stdout", 0, 4, []byte("ab"), false)), "127.0.0.1", true)
	if _, err := s.Ingest(context.Background(), testPacket(t, "overlap", "security_event", "10.0.0.1", time.Now(), sudoChunkData("first", "stdout", 1, 4, []byte("bc"), false)), "127.0.0.1"); err == nil {
		t.Fatal("accepted overlapping ranges")
	}
}

func TestSudoCompletionCanFollowIdenticalDataAndEmptyFiles(t *testing.T) {
	s, _ := testStore(t)
	at := time.Now()
	for i, complete := range []bool{false, true} {
		requireIngest(t, s, testPacket(t, fmt.Sprint("completion-", i), "security_event", "10.0.0.1", at, sudoChunkData("first", "stdout", 0, 1, []byte("x"), complete)), "127.0.0.1", i == 0)
	}
	requireIngest(t, s, testPacket(t, "empty", "security_event", "10.0.0.1", at, sudoChunkData("first", "stdin", 0, 0, []byte{}, true)), "127.0.0.1", true)
	page, err := s.SudoSessions(context.Background(), Filter{Page: 1, Size: 20})
	if err != nil || len(page.Items) != 1 || len(page.Items[0].Files) != 2 {
		t.Fatal(page, err)
	}
	for _, file := range page.Items[0].Files {
		if !file.Complete {
			t.Fatal("file completion metadata lost", file)
		}
	}
}

func TestSudoACKFollowsDedicatedStorageCommit(t *testing.T) {
	s, _ := testStore(t)
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.ServeUDP(ctx, listener, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	defer func() { cancel(); listener.Close(); <-done }()
	client, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var envelope Envelope
	if err := json.Unmarshal(testPacket(t, "sudo-ack", "security_event", "10.0.0.1", time.Now(), sudoChunkData("generation", "stdout", 0, 1, []byte("x"), true)), &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.AckRequested = true
	packet := mustJSON(t, envelope)
	for i := 0; i < 2; i++ {
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := client.Write(packet); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1024)
		n, err := client.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		var ack struct {
			Type    string `json:"type"`
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal(buffer[:n], &ack); err != nil || ack.Type != "ack" || ack.EventID != "sudo-ack" {
			t.Fatal("unexpected sudo ACK", string(buffer[:n]), err)
		}
		if countRows(t, s, "sudo_io_chunks") != 1 || countRows(t, s, "events") != 0 {
			t.Fatal("ACK preceded durable special storage or duplicate blob inserted")
		}
	}
}

func TestV6MigrationRetainsCommandsOutboxAndHighWaterMarks(t *testing.T) {
	s, dir := testStore(t)
	insertHook(t, s, "retained", "http://127.0.0.1/unused", "generic", true)
	requireIngest(t, s, testPacket(t, "old-alert", "alert", "10.0.0.1", time.Now(), testAlert()), "127.0.0.1", true)
	requireIngest(t, s, testPacket(t, "old-command", "command_history", "10.0.0.1", time.Now(), commandData("retained-command", time.Now())), "127.0.0.1", true)
	_, err := s.DB.Exec(`CREATE TEMP TABLE saved_outbox AS SELECT * FROM outbox;
DROP TABLE outbox;
CREATE TABLE events_v6 (
 id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL,machine_ip TEXT NOT NULL REFERENCES machines(ip) ON DELETE CASCADE,
 host TEXT NOT NULL,type TEXT NOT NULL CHECK(type IN ('alert','ssh_login','scan_summary','command_history')),time INTEGER NOT NULL,received_at INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved')),notes TEXT NOT NULL DEFAULT '',data TEXT NOT NULL,login_key TEXT,command_key TEXT,UNIQUE(machine_ip,event_id));
INSERT INTO events_v6 SELECT * FROM events;
DROP TABLE events; ALTER TABLE events_v6 RENAME TO events;
CREATE TABLE outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,webhook_id INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at INTEGER NOT NULL,delivered_at INTEGER,last_error TEXT NOT NULL DEFAULT '',UNIQUE(webhook_id,event_id));
INSERT INTO outbox SELECT * FROM saved_outbox; DROP TABLE saved_outbox;
UPDATE events SET notes='retained notes',status='resolved';
UPDATE outbox SET attempts=3,last_error='retry me';
UPDATE sqlite_sequence SET seq=100 WHERE name='events';
UPDATE sqlite_sequence SET seq=200 WHERE name='outbox';
DROP TABLE machine_security_status;
DROP TABLE sudo_io_chunks; DROP TABLE sudo_session_files; DROP TABLE sudo_sessions;
PRAGMA user_version=6;`)
	if err != nil {
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
	var attempts int
	var lastError, notes, status, commandKey string
	if err := reopened.DB.QueryRow(`SELECT attempts,last_error FROM outbox`).Scan(&attempts, &lastError); err != nil || attempts != 3 || lastError != "retry me" {
		t.Fatal("outbox changed", err)
	}
	if err := reopened.DB.QueryRow(`SELECT notes,status,command_key FROM events WHERE type='command_history'`).Scan(&notes, &status, &commandKey); err != nil || notes != "retained notes" || status != "resolved" || commandKey == "" {
		t.Fatal("command identity or event metadata lost", err)
	}
	requireIngest(t, reopened, testPacket(t, "new-security", "security_event", "10.0.0.1", time.Now(), securityData("warning")), "127.0.0.1", true)
	var eventID, outboxID int64
	if err := reopened.DB.QueryRow(`SELECT MAX(id) FROM events`).Scan(&eventID); err != nil || eventID <= 100 {
		t.Fatal("event sequence regressed", err)
	}
	if err := reopened.DB.QueryRow(`SELECT MAX(id) FROM outbox`).Scan(&outboxID); err != nil || outboxID <= 200 {
		t.Fatal("outbox sequence regressed", err)
	}
	rows, err := reopened.DB.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("migration broke foreign keys")
	}
}
