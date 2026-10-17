package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestComponentStatusStableReportsOnlyRefreshSnapshotAndPresence(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	insertHook(t, s, "status", "http://127.0.0.1/unused", "generic", true)
	at := time.Now().UTC().Truncate(time.Millisecond)
	for i := range 100 {
		data := componentData("running")
		data["components"].([]any)[0].(map[string]any)["applied_at"] = at.Add(time.Duration(i) * time.Second)
		data["queue"] = map[string]int{"pending": i}
		data["inventory"] = map[string]int{"progress": i}
		data["status_reporting"] = "changes_only"
		data["snapshot_interval_seconds"] = 300
		data["snapshot_only"] = true
		requireIngest(t, s, testPacket(t, fmt.Sprint("stable-", i), "component_status", "10.0.0.1", at.Add(time.Duration(i)*time.Second), data), "192.0.2.1", false)
		if i == 0 {
			if _, err := s.DB.Exec(`UPDATE machines SET last_seen=0; INSERT INTO machine_offline_state(machine_ip,event_id) VALUES('10.0.0.1','offline')`); err != nil {
				t.Fatal(err)
			}
		}
	}
	statuses, err := s.SecurityStatuses(ctx, "10.0.0.1")
	if err != nil || len(statuses) != 1 || !statuses[0].Time.Equal(at.Add(99*time.Second)) || !strings.Contains(string(statuses[0].Data), `"pending":99`) {
		t.Fatalf("latest snapshot missing: %+v %v", statuses, err)
	}
	machine, err := s.Machine(ctx, "10.0.0.1")
	if err != nil || !machine.Online || machine.SourceIP != "192.0.2.1" || machine.LastSeen.Before(at) || countRows(t, s, "machine_offline_state") != 0 {
		t.Fatalf("snapshot did not refresh machine presence: %+v %v", machine, err)
	}
	if countRows(t, s, "events") != 0 || countRows(t, s, "outbox") != 0 {
		t.Fatal("stable health reports produced history or notifications")
	}
}

func TestComponentStatusRecordsAnomalyChangesAndRecoveryOnce(t *testing.T) {
	s, dir := testStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)
	insertHook(t, s, "status", "http://127.0.0.1/unused", "generic", true)
	abnormal := componentData("stopped")
	abnormal["snapshot_only"] = true // Client hints cannot hide a real incident.
	packet := testPacket(t, "first-failure", "component_status", "10.0.0.1", at, abnormal)
	requireIngest(t, s, packet, "127.0.0.1", true)
	requireIngest(t, s, packet, "127.0.0.1", false)
	for i := 1; i <= 100; i++ {
		abnormal["queue"] = map[string]int{"pending": i}
		abnormal["components"].([]any)[0].(map[string]any)["applied_at"] = at.Add(time.Duration(i) * time.Second)
		abnormal["components"] = append(abnormal["components"].([]any)[:1], map[string]any{"name": "sudo", "enabled": true, "state": "ready", "version": fmt.Sprint(i)})
		requireIngest(t, s, testPacket(t, fmt.Sprint("same-failure-", i), "component_status", "10.0.0.1", at.Add(time.Duration(i)*time.Second), abnormal), "127.0.0.1", false)
	}
	if countRows(t, s, "events") != 1 {
		t.Fatal("unchanged abnormal state produced repeated history")
	}
	changed := componentData("failed")
	changed["components"].([]any)[0].(map[string]any)["error"] = "new failure"
	requireIngest(t, s, testPacket(t, "changed-failure", "component_status", "10.0.0.1", at.Add(101*time.Second), changed), "127.0.0.1", true)
	requireIngest(t, s, testPacket(t, "recovery", "component_status", "10.0.0.1", at.Add(102*time.Second), componentData("running")), "127.0.0.1", true)
	requireIngest(t, s, testPacket(t, "stable-recovery", "component_status", "10.0.0.1", at.Add(103*time.Second), componentData("running")), "127.0.0.1", false)
	requireIngest(t, s, packet, "127.0.0.1", false) // Retry cannot undo recovery.
	requireIngest(t, s, testPacket(t, "late-failure", "component_status", "10.0.0.1", at.Add(99*time.Second), componentData("stopped")), "127.0.0.1", false)
	if countRows(t, s, "events") != 3 || countRows(t, s, "outbox") != 0 {
		t.Fatal("component transitions lost history or created webhook jobs")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	requireIngest(t, reopened, testPacket(t, "after-restart", "component_status", "10.0.0.1", at.Add(104*time.Second), componentData("running")), "127.0.0.1", false)
	statuses, err := reopened.SecurityStatuses(ctx, "10.0.0.1")
	if err != nil || len(statuses) != 1 || !strings.Contains(string(statuses[0].Data), `"state":"running"`) || countRows(t, reopened, "events") != 3 {
		t.Fatalf("restart lost snapshot or incident deduplication: %+v %v", statuses, err)
	}
}

func TestComponentStatusAnomalyClassificationAndMeaningfulEvidence(t *testing.T) {
	s, _ := testStore(t)
	at := time.Now().UTC()
	states := []string{"error", "failed", "install_failed", "config_failed", "degraded", "unsupported", "drift", "stopped", "missing", "not_installed", "starting", "installing", "pending", "disabled", "ready", "applied", "audit", "running"}
	for i, state := range states {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		data := componentData(state)
		requireIngest(t, s, testPacket(t, state, "component_status", ip, at, data), "127.0.0.1", i < 10)
		data["components"].([]any)[0].(map[string]any)["enabled"] = false
		requireIngest(t, s, testPacket(t, state+"-disabled", "component_status", ip, at.Add(time.Second), data), "127.0.0.1", i < 10)
	}
	data := componentData("ready")
	component := data["components"].([]any)[0].(map[string]any)
	component["error"] = "diagnostic error"
	component["checks"] = []any{map[string]any{"setting": "a", "compliant": false}, map[string]any{"setting": "b", "compliant": true}}
	requireIngest(t, s, testPacket(t, "error-field", "component_status", "10.0.1.1", at, data), "127.0.0.1", true)
	component["checks"] = []any{map[string]any{"setting": "b", "compliant": true}, map[string]any{"setting": "a", "compliant": false}}
	requireIngest(t, s, testPacket(t, "checks-reordered", "component_status", "10.0.1.1", at.Add(time.Second), data), "127.0.0.1", false)
	component["checks"] = []any{map[string]any{"setting": "a", "compliant": false, "actual": "changed"}}
	requireIngest(t, s, testPacket(t, "checks-changed", "component_status", "10.0.1.1", at.Add(2*time.Second), data), "127.0.0.1", true)
}

func TestComponentStatusSnapshotAndDuplicateReportsAreAcknowledged(t *testing.T) {
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
	if err := json.Unmarshal(testPacket(t, "status-ack", "component_status", "10.0.0.1", time.Now(), componentData("running")), &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.AckRequested = true
	packet := mustJSON(t, envelope)
	for range 2 {
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := client.Write(packet); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1024)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		var ack struct {
			Type    string `json:"type"`
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal(buf[:n], &ack); err != nil {
			t.Fatal(err)
		}
		if ack.Type != "ack" || ack.EventID != envelope.EventID || countRows(t, s, "machine_security_status") != 1 || countRows(t, s, "events") != 0 {
			t.Fatal("snapshot ACK missing or preceded committed snapshot", string(buf[:n]))
		}
	}
}
