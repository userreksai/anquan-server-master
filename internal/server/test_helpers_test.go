package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "nested", "data")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func testServer(s *Store) *Server {
	return New(s, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func testRequest(t *testing.T, s *Server, method, path string, body any, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	if body != nil {
		var err error
		b, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, "http://security.test"+path, bytes.NewReader(b))
	r.RemoteAddr = "192.0.2.10:12345"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func requireStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("HTTP %d, want %d: %s", w.Code, status, w.Body.String())
	}
}

func testLogin(t *testing.T, s *Server, password string) *http.Cookie {
	t.Helper()
	w := testRequest(t, s, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": password}, nil, nil)
	requireStatus(t, w, 200)
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("login returned no session cookie")
	return nil
}

func jsonResult[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode response: %v; %s", err, w.Body.String())
	}
	return v
}

func testPacket(t *testing.T, id, kind, ip string, at time.Time, data any) []byte {
	t.Helper()
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(Envelope{Version: 1, EventID: id, IP: ip, Host: "node-a", Time: at, Type: kind, Data: body})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testAlert() map[string]any {
	return map[string]any{"module": "files", "kind": "modified", "target": "/etc/app_100%.conf", "message": "content changed", "before": "900150983cd24fb0d6963f7d28e17f72", "after": "d41d8cd98f00b204e9800998ecf8427e"}
}

func requireIngest(t *testing.T, s *Store, packet []byte, source string, inserted bool) {
	t.Helper()
	got, err := s.Ingest(context.Background(), packet, source)
	if err != nil || got != inserted {
		t.Fatalf("Ingest inserted=%v want=%v err=%v packet=%s", got, inserted, err, packet)
	}
}

func countRows(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func insertHook(t *testing.T, s *Store, name, endpoint, format string, enabled bool) int64 {
	t.Helper()
	now := stamp(time.Now())
	r, err := s.DB.Exec(`INSERT INTO webhooks(name,url,format,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)`, name, endpoint, format, enabled, now, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
