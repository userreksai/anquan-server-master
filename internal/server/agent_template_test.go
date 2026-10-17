package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgentTemplateLocalProxyOriginSavesOnlyLocalDatabase(t *testing.T) {
	store, dir := testStore(t)
	s := testServer(store)
	if err := s.SetPublicOrigin("https://prodsafety.ops.tw"); err != nil {
		t.Fatal(err)
	}
	// Template storage must never use the webhook/external HTTP client.
	s.Client = &http.Client{Transport: webhookRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("saving a template made an external request: %s", r.URL)
		return nil, nil
	})}
	cookie := testLogin(t, s, DefaultPassword)
	const path = "/api/settings/agent-config-template"
	const config = "# 本机主控保存模板，不连接 Agent\nserver: []\n"
	request := func(content string, headers map[string]string, loggedIn bool) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]string{"yaml": content})
		if err != nil {
			t.Fatal(err)
		}
		// Nginx may replace Host with the local upstream while keeping Origin.
		r := httptest.NewRequest("PUT", "http://127.0.0.1:10110"+path, strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		for key, value := range headers {
			r.Header.Set(key, value)
		}
		if loggedIn {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	publicHeaders := map[string]string{"Origin": "https://prodsafety.ops.tw", "Sec-Fetch-Site": "same-origin"}
	requireStatus(t, request(config, publicHeaders, false), 401)
	if countRows(t, store, "agent_config_template") != 0 {
		t.Fatal("unauthenticated request saved a template")
	}
	requireStatus(t, request(config, publicHeaders, true), 200)
	const rejectedConfig = "# 未授权内容不得覆盖已保存模板\nserver: []\n"
	for _, headers := range []map[string]string{
		{"Origin": "https://evil.example"},
		{"Origin": "http://prodsafety.ops.tw"},
		{"Origin": "https://prodsafety.ops.tw:8443"},
		{"Origin": "http://127.0.0.1:10110"},
		{"Origin": "null"},
		{"Origin": "https://prodsafety.ops.tw/"},
		{"Origin": "https://prodsafety.ops.tw?"},
		{"Origin": "https://prodsafety.ops.tw#"},
		{"Origin": "https://prodsafety.ops.tw", "Sec-Fetch-Site": "cross-site"},
		{"Origin": "https://evil.example", "X-Forwarded-Host": "prodsafety.ops.tw", "X-Forwarded-Proto": "https", "Forwarded": "host=prodsafety.ops.tw;proto=https"},
	} {
		requireStatus(t, request(rejectedConfig, headers, true), 403)
	}
	requireStatus(t, request(rejectedConfig, map[string]string{"Origin": "https://prodsafety.ops.tw", "Content-Type": "text/plain"}, true), 415)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded := jsonResult[agentConfigTemplate](t, testRequest(t, testServer(reopened), "GET", path, nil, cookie, nil))
	if loaded.YAML == nil || *loaded.YAML != config || countRows(t, reopened, "agent_config_template") != 1 {
		t.Fatal("proxy save was not durably stored in the master's local SQLite database")
	}
}

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

func TestAgentTemplatePOSTAndPUTUseSameAuthenticatedSave(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	const path = "/api/settings/agent-config-template"
	const original = "# 先前模板\nserver: []\n"
	if err := store.SaveAgentConfigTemplate(t.Context(), original); err != nil {
		t.Fatal(err)
	}
	cookie := testLogin(t, s, DefaultPassword)
	for _, method := range []string{"POST", "PUT"} {
		t.Run(method, func(t *testing.T) {
			changed := "# " + method + " 保存\nserver: []\n"
			body := map[string]string{"yaml": changed}
			requireStatus(t, testRequest(t, s, method, path, body, nil, nil), 401)
			for _, headers := range []map[string]string{{"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}} {
				requireStatus(t, testRequest(t, s, method, path, body, cookie, headers), 403)
			}
			requireStatus(t, testRequest(t, s, method, path, body, cookie, map[string]string{"Content-Type": "text/plain"}), 415)
			requireStatus(t, testRequest(t, s, method, path, map[string]string{"yaml": "[broken"}, cookie, nil), 400)
			var prior string
			if err := store.DB.QueryRow(`SELECT yaml FROM agent_config_template WHERE id=1`).Scan(&prior); err != nil || prior != original {
				t.Fatalf("rejected %s overwrote shared template: %v", method, err)
			}
			w := testRequest(t, s, method, path, body, cookie, map[string]string{"Origin": "http://security.test"})
			requireStatus(t, w, 200)
			saved := jsonResult[agentConfigTemplate](t, w)
			loaded := jsonResult[agentConfigTemplate](t, testRequest(t, s, "GET", path, nil, cookie, nil))
			if saved.YAML == nil || loaded.YAML == nil || *saved.YAML != changed || *loaded.YAML != changed || countRows(t, store, "agent_config_template") != 1 {
				t.Fatalf("%s did not save/read the shared template", method)
			}
			if err := store.SaveAgentConfigTemplate(t.Context(), original); err != nil {
				t.Fatal(err)
			}
		})
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
	if err := reopened.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 8 {
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
