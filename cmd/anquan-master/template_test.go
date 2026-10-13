package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/userreksai/anquan-server-master/internal/server"
)

func withTemplateInput(t *testing.T, value string, action func() error) error {
	t.Helper()
	return withPasswordInput(t, value, action)
}

func templateValue(t *testing.T, store *server.Store) string {
	t.Helper()
	var value string
	if err := store.DB.QueryRow(`SELECT yaml FROM agent_config_template WHERE id=1`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSaveAgentTemplateCLIStoresLocallyAndPreservesExistingData(t *testing.T) {
	// The local command must not parse serve settings or create listeners.
	for _, key := range []string{"ANQUAN_HTTP_ADDR", "ANQUAN_UDP_ADDR", "ANQUAN_TCP_ADDR", "ANQUAN_PUBLIC_ORIGIN", "ANQUAN_SECURE_COOKIE"} {
		t.Setenv(key, "invalid-serve-setting")
	}
	dir := filepath.Join(t.TempDir(), "data #本机")
	store, err := server.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var passwordHash string
	if err := store.DB.QueryRow(`SELECT password_hash FROM users WHERE username='admin'`).Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`INSERT INTO sessions(token_hash,username,expires_at) VALUES('retained-session','admin',?)`, time.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	packet, err := json.Marshal(server.Envelope{Version: 1, EventID: "retained-event", IP: "192.0.2.21", Host: "retained-host", Type: "alert", Time: time.Now(), Data: json.RawMessage(`{"module":"files","kind":"modified","target":"/etc/hosts","message":"retained alert"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if inserted, err := store.Ingest(context.Background(), packet, "127.0.0.1"); err != nil || !inserted {
		t.Fatalf("seed event failed: inserted=%v err=%v", inserted, err)
	}
	for _, config := range []string{"# 中文注释与缩进保持原样\nserver: []\n", "# 最新本机模板\nsetup:\n  logs: /var/log/anquan.log\nserver: []\n"} {
		readOutput, writeOutput, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		previous := os.Stdout
		os.Stdout = writeOutput
		err = withTemplateInput(t, config, func() error {
			return run([]string{"save-agent-template", "--data-dir", dir, "--yaml-stdin"})
		})
		os.Stdout = previous
		writeOutput.Close()
		output, readErr := io.ReadAll(readOutput)
		readOutput.Close()
		if err != nil || readErr != nil {
			t.Fatalf("local template save failed: %v %v", err, readErr)
		}
		if strings.Contains(string(output), config) || strings.Contains(string(output), "server:") {
			t.Fatal("CLI printed the template plaintext")
		}
		if templateValue(t, store) != config {
			t.Fatal("running master connection did not see CLI save")
		}
		reopened, err := server.OpenExisting(dir)
		if err != nil {
			t.Fatal(err)
		}
		if templateValue(t, reopened) != config {
			t.Fatal("template save was not durable or changed formatting")
		}
		var retainedHash, eventData string
		if err := reopened.DB.QueryRow(`SELECT password_hash FROM users WHERE username='admin'`).Scan(&retainedHash); err != nil || retainedHash != passwordHash {
			t.Fatalf("local save changed admin credentials: %v", err)
		}
		if err := reopened.DB.QueryRow(`SELECT data FROM events WHERE event_id='retained-event'`).Scan(&eventData); err != nil || !strings.Contains(eventData, "retained alert") {
			t.Fatalf("local save lost existing event: %v", err)
		}
		for table, expected := range map[string]int{"users": 1, "sessions": 1, "machines": 1, "events": 1, "agent_config_template": 1} {
			var count int
			if err := reopened.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != expected {
				t.Fatalf("local save changed %s: count=%d err=%v", table, count, err)
			}
		}
		reopened.Close()
	}
}

func TestSaveAgentTemplateCLIRejectsInvalidInputWithoutOverwriting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	store, err := server.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const original = "# 原模板\nserver: []\n"
	if err := store.SaveAgentConfigTemplate(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		input string
		args  []string
	}{
		{"missing-stdin-switch", "server: []\n", nil},
		{"extra-positional", "server: []\n", []string{"--yaml-stdin", "extra"}},
		{"unknown-option", "server: []\n", []string{"--yaml-stdin", "--unknown"}},
		{"empty", "", []string{"--yaml-stdin"}},
		{"whitespace", " \n\t", []string{"--yaml-stdin"}},
		{"syntax", "[broken", []string{"--yaml-stdin"}},
		{"scalar", "scalar", []string{"--yaml-stdin"}},
		{"list", "- list", []string{"--yaml-stdin"}},
		{"duplicate", "a: 1\na: 2", []string{"--yaml-stdin"}},
		{"multi-document", "a: 1\n---\nb: 2", []string{"--yaml-stdin"}},
		{"oversized", "#" + strings.Repeat("x", 4<<20) + "\nserver: []\n", []string{"--yaml-stdin"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"save-agent-template", "--data-dir", dir}, tc.args...)
			if err := withTemplateInput(t, tc.input, func() error { return run(args) }); err == nil {
				t.Fatal("invalid template input accepted")
			}
			if templateValue(t, store) != original {
				t.Fatal("failed local save overwrote the previous template")
			}
		})
	}
}

func TestSaveAgentTemplateCLINeverCreatesDatabase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-created", "data")
	for _, input := range []string{"server: []\n", "[broken"} {
		if err := withTemplateInput(t, input, func() error {
			return run([]string{"save-agent-template", "--data-dir", dir, "--yaml-stdin"})
		}); err == nil {
			t.Fatal("local command accepted a nonexistent database")
		}
		if _, err := os.Stat(filepath.Dir(dir)); !os.IsNotExist(err) {
			t.Fatalf("local command created a new data directory: %v", err)
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "anquan.db")
	for _, existing := range []string{"", "not a SQLite database"} {
		if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
			t.Fatal(err)
		}
		if err := withTemplateInput(t, "server: []\n", func() error {
			return run([]string{"save-agent-template", "--data-dir", dir, "--yaml-stdin"})
		}); err == nil {
			t.Fatal("local command initialized an invalid/empty database file")
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != existing {
			t.Fatalf("local command changed the invalid database file: %v", err)
		}
	}
}
