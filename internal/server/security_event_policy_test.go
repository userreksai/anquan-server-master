package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSecurityMinimumSeverityDefaultsAndAllThresholds(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	at := time.Now().UTC()
	insertHook(t, s, "events", "http://127.0.0.1/unused", "generic", true)
	for _, severity := range []string{"debug", "info", "notice"} {
		requireIngest(t, s, testPacket(t, "default-"+severity, "security_event", "10.0.0.1", at, securityData(severity)), "192.0.2.1", false)
	}
	if countRows(t, s, "events") != 0 || countRows(t, s, "outbox") != 0 {
		t.Fatal("default warning threshold recorded routine observations")
	}
	if _, err := s.DB.Exec(`UPDATE machines SET last_seen=0; INSERT INTO machine_offline_state(machine_ip,event_id) VALUES('10.0.0.1','old-offline')`); err != nil {
		t.Fatal(err)
	}
	requireIngest(t, s, testPacket(t, "filtered-presence", "security_event", "10.0.0.1", at.Add(time.Second), securityData("info")), "192.0.2.2", false)
	machine, err := s.Machine(ctx, "10.0.0.1")
	if err != nil || !machine.Online || machine.SourceIP != "192.0.2.2" || countRows(t, s, "machine_offline_state") != 0 {
		t.Fatalf("severity filtering lost presence: %+v %v", machine, err)
	}
	levels := []string{"debug", "info", "notice", "warning", "error", "critical"}
	wantEvents, wantJobs := 0, 0
	for minRank, minimum := range levels {
		policy := defaultEventPolicy()
		policy.SecurityEventMinSeverity = minimum
		if err := s.SaveEventPolicy(ctx, policy); err != nil {
			t.Fatal(err)
		}
		for rank, severity := range levels {
			packet := testPacket(t, minimum+"-"+severity, "security_event", "10.0.0.1", at, securityData(severity))
			retained := rank >= minRank
			requireIngest(t, s, packet, "127.0.0.1", retained)
			requireIngest(t, s, packet, "127.0.0.1", false)
			if retained {
				wantEvents++
				if rank >= securitySeverityRank("warning") {
					wantJobs++
				}
			}
		}
		if countRows(t, s, "events") != wantEvents || countRows(t, s, "outbox") != wantJobs {
			t.Fatalf("minimum %s lost existing history or created extra jobs", minimum)
		}
	}
	// The runtime-event threshold does not govern explicit history, SSH login,
	// traditional alerts, or complete binary sudo recording uploads.
	requireIngest(t, s, testPacket(t, "separate-alert", "alert", "10.0.0.1", at, testAlert()), "127.0.0.1", true)
	requireIngest(t, s, testPacket(t, "separate-login", "ssh_login", "10.0.0.1", at, map[string]any{"id": "separate-login", "user": "root", "login_time": at}), "127.0.0.1", true)
	requireIngest(t, s, testPacket(t, "separate-command", "command_history", "10.0.0.1", at, commandData("separate-command", at)), "127.0.0.1", true)
	requireIngest(t, s, testPacket(t, "separate-recording", "security_event", "10.0.0.1", at, sudoChunkData("first", "stdout", 0, 3, []byte("abc"), true)), "127.0.0.1", true)
	if countRows(t, s, "events") != wantEvents+3 || countRows(t, s, "outbox") != wantJobs+2 || countRows(t, s, "sudo_io_chunks") != 1 {
		t.Fatal("runtime threshold affected explicit recording or other event types")
	}
}

func TestLegacyAuditExecCompatibilityIsExactAndPreservesRawEvidence(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	at := time.Now().UTC()
	insertHook(t, s, "events", "http://127.0.0.1/unused", "generic", true)
	legacy := securityData("warning")
	legacy["message"] = "Linux audit exec"
	legacy["fields"] = map[string]string{"key": "anquan_exec", "success": "no"}
	legacy["records"] = []string{`type=SYSCALL msg=audit(123.1:1) success=no key="anquan_exec"`}
	requireIngest(t, s, testPacket(t, "legacy-default", "security_event", "10.0.0.1", at, legacy), "127.0.0.1", false)
	policy := defaultEventPolicy()
	policy.SecurityEventMinSeverity = "info"
	if err := s.SaveEventPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	requireIngest(t, s, testPacket(t, "legacy-info", "security_event", "10.0.0.1", at, legacy), "127.0.0.1", true)
	var raw string
	if err := s.DB.QueryRow(`SELECT data FROM events WHERE event_id='legacy-info'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if json.Unmarshal([]byte(raw), &got) != nil || got["severity"] != "warning" || got["message"] != "Linux audit exec" || countRows(t, s, "outbox") != 0 {
		t.Fatal("legacy observation lost raw evidence or notified as a warning", raw)
	}
	if err := s.SaveEventPolicy(ctx, defaultEventPolicy()); err != nil {
		t.Fatal(err)
	}
	for i, replacement := range []map[string]any{{"severity": "error"}, {"severity": "critical"}, {"message": "Custom security warning"}, {"source": "custom"}, {"kind": "rule_match"},
		{"fields": map[string]string{"key": "anquan_exec_denied"}, "records": []string{`type=SYSCALL success=no key="anquan_exec_denied"`}},
		{"fields": map[string]string{"key": "anquan_exec"}, "records": []string{`type=SYSCALL success=no key="anquan_exec_denied"`, `type=SYSCALL key="anquan_exec"`}},
		{"fields": map[string]string{"key": "anquan_exec\x01custom"}},
		{"fields": map[string]string{"key": "anquan_exec"}, "records": []string{`type=SYSCALL key="anquan_exec" key="custom"`}},
		{"fields": nil, "records": []string{`type=SYSCALL key="anquan_exec,custom"`}},
		{"fields": nil, "records": nil}, // Missing rule-key evidence must keep the warning.
	} {
		data := securityData("warning")
		data["message"] = "Linux audit exec"
		data["fields"] = map[string]string{"key": "anquan_exec", "success": "no"}
		data["records"] = []string{`type=SYSCALL success=no key="anquan_exec"`}
		for key, value := range replacement {
			data[key] = value
		}
		requireIngest(t, s, testPacket(t, fmt.Sprint("real-warning-", i), "security_event", "10.0.0.1", at, data), "127.0.0.1", true)
	}
	if countRows(t, s, "events") != 12 || countRows(t, s, "outbox") != 11 {
		t.Fatal("compatibility rule suppressed custom or higher-severity alerts")
	}
}

func TestNotifierCancelsObsoletePendingSecurityJobsWithoutPretendingSuccess(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer endpoint.Close()
	hookID := insertHook(t, s, "events", endpoint.URL, "generic", true)
	at := time.Now().UTC()
	policy := defaultEventPolicy()
	policy.SecurityEventMinSeverity = "debug"
	if err := s.SaveEventPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	requireIngest(t, s, testPacket(t, "lower-than-new-policy", "security_event", "10.0.0.1", at, securityData("warning")), "127.0.0.1", true)
	requireIngest(t, s, testPacket(t, "ignored-tetragon", "security_event", "10.0.0.1", at, tetragonPolicyData("tetragon", "process_exec")), "127.0.0.1", true)
	legacy := securityData("warning")
	legacy["message"] = "Linux audit exec"
	legacy["fields"] = map[string]string{"key": "anquan_exec", "success": "no"}
	legacy["records"] = []string{`type=SYSCALL success=no key="anquan_exec"`}
	requireIngest(t, s, testPacket(t, "legacy-pending", "security_event", "10.0.0.1", at, legacy), "127.0.0.1", true)
	// Emulate a task queued before the compatibility correction was deployed.
	if _, err := s.DB.Exec(`INSERT INTO outbox(webhook_id,event_id,next_attempt_at) SELECT ?,id,0 FROM events WHERE event_id='legacy-pending'`, hookID); err != nil {
		t.Fatal(err)
	}
	policy.SecurityEventMinSeverity = "error"
	policy.TetragonIgnoredKinds = []string{"process_exec"}
	if err := s.SaveEventPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	srv := testServer(s)
	jobs, err := srv.due(ctx)
	if err != nil || len(jobs) != 3 {
		t.Fatalf("expected legacy pending jobs: %+v %v", jobs, err)
	}
	for _, job := range jobs {
		if err := srv.deliver(ctx, job); err != nil {
			t.Fatal(err)
		}
	}
	hook, err := s.Webhook(ctx, hookID)
	if err != nil || hook.LastSuccessAt != nil || calls.Load() != 0 || countRows(t, s, "outbox") != 0 || countRows(t, s, "events") != 3 {
		t.Fatalf("cancelled job sent, claimed success, or removed event evidence: %+v calls=%d %v", hook, calls.Load(), err)
	}
	requireIngest(t, s, testPacket(t, "real-error", "security_event", "10.0.0.1", at, securityData("error")), "127.0.0.1", true)
	requireIngest(t, s, testPacket(t, "ssh-unaffected", "ssh_login", "10.0.0.1", at, map[string]any{"id": "ssh", "user": "ops", "login_time": at}), "127.0.0.1", true)
	jobs, err = srv.due(ctx)
	if err != nil || len(jobs) != 2 {
		t.Fatalf("legitimate notification jobs lost: %+v %v", jobs, err)
	}
	for _, job := range jobs {
		if err := srv.deliver(ctx, job); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("legitimate warning or SSH login was filtered")
	}
	policy.SecurityEventMinSeverity = "warning"
	if err := s.SaveEventPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	custom := securityData("warning")
	custom["message"] = "Linux audit exec"
	custom["fields"] = map[string]string{"key": "anquan_exec"}
	custom["records"] = []string{`type=SYSCALL key="anquan_exec_denied"`, `type=SYSCALL key="anquan_exec"`}
	requireIngest(t, s, testPacket(t, "custom-exec-warning", "security_event", "10.0.0.1", at, custom), "127.0.0.1", true)
	jobs, err = srv.due(ctx)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("custom audit rule warning was not queued: %+v %v", jobs, err)
	}
	if err := srv.deliver(ctx, jobs[0]); err != nil || calls.Load() != 3 {
		t.Fatal("custom audit rule warning was cancelled", calls.Load(), err)
	}
}

func TestV8SeverityPolicyMigrationPreservesSettingsHistoryAndPendingJobs(t *testing.T) {
	s, dir := testStore(t)
	ctx := context.Background()
	policy := EventPolicy{TetragonIgnoredKinds: []string{"process_exec"}, ScanSummaryRetentionHours: 12}
	if err := s.SaveEventPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	insertHook(t, s, "events", "http://127.0.0.1/unused", "generic", true)
	requireIngest(t, s, testPacket(t, "existing-alert", "alert", "10.0.0.1", time.Now(), testAlert()), "127.0.0.1", true)
	if _, err := s.DB.Exec(`ALTER TABLE event_policy DROP COLUMN security_event_min_severity; PRAGMA user_version=8;`); err != nil {
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
	got, err := reopened.EventPolicy(ctx)
	if err != nil || got.SecurityEventMinSeverity != "warning" || got.ScanSummaryRetentionHours != 12 || len(got.TetragonIgnoredKinds) != 1 || got.TetragonIgnoredKinds[0] != "process_exec" {
		t.Fatalf("migration lost policy settings: %+v %v", got, err)
	}
	var pending sql.NullInt64
	if err := reopened.DB.QueryRow(`SELECT delivered_at FROM outbox`).Scan(&pending); err != nil || pending.Valid || countRows(t, reopened, "events") != 1 {
		t.Fatal("migration lost event history or changed pending delivery", pending, err)
	}
}
