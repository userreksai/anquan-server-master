package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgentTemplatePersistsAcrossSessionsAndRestart(t *testing.T) {
	store, dir := testStore(t)
	s := testServer(store)
	path := "/api/settings/agent-config-template"
	config := "# 保留中文注释、缩进和换行\nsetup:\n  logs: /var/log/时间anquan.log\n  prom: /var/lib/node_exporter/textfile_collector/process_monitor.prom\n"
	body := map[string]string{"yaml": config}
	requireStatus(t, testRequest(t, s, "GET", path, nil, nil, nil), 401)
	requireStatus(t, testRequest(t, s, "PUT", path, body, nil, nil), 401)
	cookie := testLogin(t, s, DefaultPassword)
	initial := jsonResult[agentConfigTemplate](t, testRequest(t, s, "GET", path, nil, cookie, nil))
	if initial.YAML != nil {
		t.Fatal("fresh installation must use the built-in example")
	}
	requireStatus(t, testRequest(t, s, "PUT", path, body, cookie, map[string]string{"Origin": "https://other.test"}), 403)
	for _, content := range []string{config, config + "server: []  # 最新模板\n"} {
		config = content
		w := testRequest(t, s, "PUT", path, map[string]string{"yaml": content}, cookie, nil)
		requireStatus(t, w, 200)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("template response must not be cached")
		}
		saved := jsonResult[agentConfigTemplate](t, w)
		if saved.YAML == nil || *saved.YAML != content {
			t.Fatal("template content changed during save")
		}
	}
	otherSession := testLogin(t, s, DefaultPassword)
	w := testRequest(t, s, "GET", path, nil, otherSession, nil)
	requireStatus(t, w, 200)
	loaded := jsonResult[agentConfigTemplate](t, w)
	if loaded.YAML == nil || *loaded.YAML != config || countRows(t, store, "agent_config_template") != 1 {
		t.Fatal("another session did not receive the most recently saved template")
	}
	// Ordinary encryption must not replace the shared template.
	requireStatus(t, testRequest(t, s, "POST", "/api/settings/agent-encryption", map[string]string{"yaml": "server: []\n"}, cookie, nil), 200)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	w = testRequest(t, testServer(reopened), "GET", path, nil, otherSession, nil)
	requireStatus(t, w, 200)
	loaded = jsonResult[agentConfigTemplate](t, w)
	if loaded.YAML == nil || *loaded.YAML != config {
		t.Fatal("saved template did not survive restart or was replaced by encryption")
	}
}

func TestAgentTemplateInvalidSavePreservesPreviousTemplate(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	path := "/api/settings/agent-config-template"
	config := "# 上一次存储\nserver: []\n"
	requireStatus(t, testRequest(t, s, "PUT", path, map[string]string{"yaml": config}, cookie, nil), 200)
	for _, invalid := range []string{"", "  ", "[broken", "scalar", "- list", "a: 1\n---\nb: 2", "a: 1\na: 2", "# " + strings.Repeat("中", maxAgentYAMLBytes/3) + "\na: 1"} {
		requireStatus(t, testRequest(t, s, "PUT", path, map[string]string{"yaml": invalid}, cookie, nil), 400)
	}
	for _, body := range []string{`{"yaml":"a: 1","unknown":true}`, `{"yaml":"a: 1"} {}`, `{"yaml":null}`, `{`} {
		r := httptest.NewRequest("PUT", "http://security.test"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		requireStatus(t, w, 400)
	}
	loaded := jsonResult[agentConfigTemplate](t, testRequest(t, s, "GET", path, nil, cookie, nil))
	if loaded.YAML == nil || *loaded.YAML != config {
		t.Fatal("failed save overwrote the previous template")
	}
}

func TestV4MigrationAddsAgentTemplateWithoutLosingData(t *testing.T) {
	store, dir := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	insertHook(t, store, "retained", "http://127.0.0.1/unused", "generic", true)
	requireIngest(t, store, testPacket(t, "retained", "alert", "10.0.0.1", time.Now(), testAlert()), "127.0.0.1", true)
	if _, err := store.DB.Exec(`DROP TABLE agent_config_template; PRAGMA user_version=4;`); err != nil {
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
	if err := reopened.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 5 {
		t.Fatalf("migration version=%d, error=%v", version, err)
	}
	for _, table := range []string{"machines", "events", "webhooks", "outbox", "sessions", "users"} {
		if countRows(t, reopened, table) != 1 {
			t.Fatalf("migration lost %s", table)
		}
	}
	s = testServer(reopened)
	path := "/api/settings/agent-config-template"
	requireStatus(t, testRequest(t, s, "GET", path, nil, cookie, nil), 200)
	requireStatus(t, testRequest(t, s, "PUT", path, map[string]string{"yaml": "server: []\n"}, cookie, nil), 200)
}
