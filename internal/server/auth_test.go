package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAuthenticationCSRFLogoutAndPasswordRevocation(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	for _, path := range []string{"/api/auth/me", "/api/overview", "/api/machines", "/api/events", "/api/webhooks"} {
		requireStatus(t, testRequest(t, s, "GET", path, nil, nil, nil), 401)
	}
	for _, body := range []map[string]string{{"username": "admin", "password": "wrong-password"}, {"username": "nobody", "password": DefaultPassword}} {
		requireStatus(t, testRequest(t, s, "POST", "/api/auth/login", body, nil, nil), 401)
	}
	first, second := testLogin(t, s, DefaultPassword), testLogin(t, s, DefaultPassword)
	if first.Value == second.Value || !first.HttpOnly || first.SameSite != http.SameSiteStrictMode || first.MaxAge != 86400 || first.Secure {
		t.Fatalf("invalid session cookie: %+v", first)
	}
	var stored string
	if err := store.DB.QueryRow(`SELECT token_hash FROM sessions WHERE token_hash=?`, tokenHash(first.Value)).Scan(&stored); err != nil || stored == first.Value {
		t.Fatalf("raw session leaked or hash missing: %v", err)
	}
	requireStatus(t, testRequest(t, s, "GET", "/api/auth/me", nil, first, nil), 200)
	for _, headers := range []map[string]string{{"Origin": "https://evil.example"}, {"Origin": "http://security.test@evil.example"}, {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}} {
		requireStatus(t, testRequest(t, s, "POST", "/api/auth/logout", nil, first, headers), 403)
	}
	// A rejected cross-site request must not revoke a valid session.
	requireStatus(t, testRequest(t, s, "GET", "/api/auth/me", nil, first, nil), 200)
	requireStatus(t, testRequest(t, s, "POST", "/api/auth/logout", nil, first, map[string]string{"Origin": "http://security.test"}), 200)
	requireStatus(t, testRequest(t, s, "GET", "/api/auth/me", nil, first, nil), 401)
	requireStatus(t, testRequest(t, s, "GET", "/api/auth/me", nil, second, nil), 200)
	third := testLogin(t, s, DefaultPassword)
	change := map[string]string{"current_password": "wrong-password", "new_password": "replacement-pass-123"}
	requireStatus(t, testRequest(t, s, "PUT", "/api/auth/password", change, second, nil), 400)
	change["current_password"] = DefaultPassword
	change["new_password"] = "short"
	requireStatus(t, testRequest(t, s, "PUT", "/api/auth/password", change, second, nil), 400)
	change["new_password"] = "replacement-pass-123"
	requireStatus(t, testRequest(t, s, "PUT", "/api/auth/password", change, second, nil), 200)
	for _, cookie := range []*http.Cookie{second, third} {
		requireStatus(t, testRequest(t, s, "GET", "/api/auth/me", nil, cookie, nil), 401)
	}
	if countRows(t, store, "sessions") != 0 {
		t.Fatal("password change left old sessions active")
	}
	requireStatus(t, testRequest(t, s, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": DefaultPassword}, nil, nil), 401)
	current := testLogin(t, s, change["new_password"])
	if _, err := store.DB.Exec(`UPDATE sessions SET expires_at=?`, stamp(time.Now().Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, testRequest(t, s, "GET", "/api/auth/me", nil, current, nil), 401)
}

func TestResetPersistsWithoutRestoringDefaultCredentials(t *testing.T) {
	store, dir := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	if err := store.ResetAdmin(context.Background(), "reset-new-password"); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, testRequest(t, s, "GET", "/api/auth/me", nil, cookie, nil), 401)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s = testServer(reopened)
	requireStatus(t, testRequest(t, s, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": DefaultPassword}, nil, nil), 401)
	testLogin(t, s, "reset-new-password")
	for _, invalid := range []string{"", "seven77", strings.Repeat("x", 73)} {
		if err := reopened.ResetAdmin(context.Background(), invalid); err == nil {
			t.Fatalf("invalid reset password accepted: %d bytes", len(invalid))
		}
	}
	// Invalid resets must not alter the currently working credential.
	testLogin(t, s, "reset-new-password")
}

func TestLoginRateLimitAndSecureCookie(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	s.SecureCookie = true
	cookie := testLogin(t, s, DefaultPassword)
	if !cookie.Secure {
		t.Fatal("HTTPS deployment cookie must be Secure")
	}
	// Invalid JSON reaches the limiter without spending bcrypt work. The login
	// above counted once; ten total attempts per source are permitted per minute.
	for i := 1; i < 10; i++ {
		requireStatus(t, testRequest(t, s, "POST", "/api/auth/login", map[string]any{"unknown": true}, nil, nil), 400)
	}
	w := testRequest(t, s, "POST", "/api/auth/login", map[string]any{"unknown": true}, nil, nil)
	requireStatus(t, w, 429)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("rate limit lacks retry advice")
	}
}
