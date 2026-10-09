package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/url"
	"testing"
	"time"
)

func commandData(id string, at time.Time) map[string]any {
	return map[string]any{"id": id, "command_time": at, "user": "root", "terminal": "/dev/pts/1", "command": "[ -f ~/.bash_aliases ]", "path": "/var/log/history.log", "offset": 0}
}

func TestCommandHistoryPersistsFiltersAndDeduplicatesOccurrences(t *testing.T) {
	s, dir := testStore(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 9, 2, 42, 50, 0, time.UTC)
	insertHook(t, s, "alerts only", "http://127.0.0.1/unused", "generic", true)
	command := commandData("generation:0", at)
	requireIngest(t, s, testPacket(t, "first", "command_history", "10.0.0.1", at.Add(time.Hour), command), "127.0.0.1", true)
	requireIngest(t, s, testPacket(t, "retry-with-new-envelope-id", "command_history", "10.0.0.1", at.Add(time.Hour), command), "127.0.0.1", false)
	command["id"], command["offset"] = "generation:100", 100
	requireIngest(t, s, testPacket(t, "second", "command_history", "10.0.0.1", at.Add(time.Hour), command), "127.0.0.1", true)
	filter, err := ParseFilter(url.Values{"type": {"command_history"}, "q": {"bash_aliases"}, "from": {at.Format(time.RFC3339)}, "to": {at.Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.Events(ctx, filter)
	if err != nil || page.Total != 2 || !page.Items[0].Time.Equal(at) {
		t.Fatalf("command query/time lost: %+v %v", page, err)
	}
	if countRows(t, s, "outbox") != 0 {
		t.Fatal("normal command triggered webhook")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	page, err = reopened.Events(ctx, filter)
	if err != nil || page.Total != 2 {
		t.Fatal("commands lost after reopen", err)
	}
}

func TestCommandHistoryRejectsInvalidRecords(t *testing.T) {
	s, _ := testStore(t)
	for _, field := range []string{"id", "user", "terminal", "command", "path", "command_time", "offset"} {
		data := commandData("test", time.Now())
		data[field] = ""
		if field == "offset" {
			data[field] = -1
		}
		if inserted, err := s.Ingest(context.Background(), testPacket(t, "invalid-"+field, "command_history", "10.0.0.1", time.Now(), data), "127.0.0.1"); err == nil || inserted {
			t.Fatalf("accepted invalid %s", field)
		}
	}
	if countRows(t, s, "events") != 0 || countRows(t, s, "machines") != 0 {
		t.Fatal("invalid command changed database")
	}
}

func TestCommandACKFollowsDurableInsertAndDuplicate(t *testing.T) {
	s, _ := testStore(t)
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeUDP(ctx, listener, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	defer func() { cancel(); listener.Close(); <-done }()
	client, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	packet := testPacket(t, "ack-id", "command_history", "10.0.0.1", time.Now(), commandData("command-id", time.Now()))
	var envelope Envelope
	if err := json.Unmarshal(packet, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.AckRequested = true
	packet, _ = json.Marshal(envelope)
	for i := 0; i < 2; i++ {
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
			Version int
			Type    string
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal(buf[:n], &ack); err != nil || ack.Version != 1 || ack.Type != "ack" || ack.EventID != "ack-id" {
			t.Fatalf("wrong acknowledgement: %s", buf[:n])
		}
		if countRows(t, s, "events") != 1 {
			t.Fatal("ACK before commit or duplicate command inserted")
		}
	}
}

func TestV2MigrationRetainsOutboxAndHighWaterMarks(t *testing.T) {
	s, dir := testStore(t)
	insertHook(t, s, "retained", "http://127.0.0.1/unused", "generic", true)
	requireIngest(t, s, testPacket(t, "old-alert", "alert", "10.0.0.1", time.Now(), testAlert()), "127.0.0.1", true)
	// Recreate the exact pre-command CHECK constraint and columns. This also
	// ensures migration tests cannot pass just because a new DB already allows it.
	_, err := s.DB.Exec(`CREATE TEMP TABLE saved_outbox AS SELECT * FROM outbox;
DROP TABLE outbox;
DROP INDEX event_command_identity;
CREATE TABLE events_v2 (
 id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL,machine_ip TEXT NOT NULL REFERENCES machines(ip) ON DELETE CASCADE,
 host TEXT NOT NULL,type TEXT NOT NULL CHECK(type IN ('alert','ssh_login','scan_summary')),time INTEGER NOT NULL,received_at INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'open',notes TEXT NOT NULL DEFAULT '',data TEXT NOT NULL,login_key TEXT,UNIQUE(machine_ip,event_id));
INSERT INTO events_v2 SELECT id,event_id,machine_ip,host,type,time,received_at,status,notes,data,login_key FROM events;
DROP TABLE events; ALTER TABLE events_v2 RENAME TO events;
CREATE TABLE outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,webhook_id INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at INTEGER NOT NULL,delivered_at INTEGER,last_error TEXT NOT NULL DEFAULT '',UNIQUE(webhook_id,event_id));
INSERT INTO outbox SELECT * FROM saved_outbox; DROP TABLE saved_outbox;
UPDATE events SET notes='retained notes',status='resolved';
UPDATE outbox SET attempts=3,last_error='retry me';
UPDATE sqlite_sequence SET seq=100 WHERE name IN ('events','outbox');
PRAGMA user_version=2;`)
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
	var lastError, notes, status string
	if err := reopened.DB.QueryRow(`SELECT attempts,last_error FROM outbox`).Scan(&attempts, &lastError); err != nil || attempts != 3 || lastError != "retry me" {
		t.Fatal("outbox changed", err)
	}
	if err := reopened.DB.QueryRow(`SELECT notes,status FROM events`).Scan(&notes, &status); err != nil || notes != "retained notes" || status != "resolved" {
		t.Fatal("event changed", err)
	}
	requireIngest(t, reopened, testPacket(t, "new-command", "command_history", "10.0.0.1", time.Now(), commandData("new", time.Now())), "127.0.0.1", true)
	var id int
	if err := reopened.DB.QueryRow(`SELECT id FROM events WHERE type='command_history'`).Scan(&id); err != nil || id <= 100 {
		t.Fatal("event sequence regressed", err)
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
