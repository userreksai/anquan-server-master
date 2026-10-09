package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func webhookEvent(t *testing.T) Event {
	t.Helper()
	data, err := json.Marshal(testAlert())
	if err != nil {
		t.Fatal(err)
	}
	return Event{EventID: "event-unique", MachineIP: "10.0.0.1", Host: "node-a", Type: "alert", Time: time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC), Data: data}
}

func TestWebhookAcknowledgementAndPayloadContracts(t *testing.T) {
	event := webhookEvent(t)
	for _, tc := range []struct {
		name, format, body string
		status             int
		wantError          bool
	}{
		{"feishu-current", "feishu", `{"code":0}`, 200, false},
		{"feishu-legacy", "feishu", `{"StatusCode":0}`, 200, false},
		{"feishu-refused", "feishu", `{"code":19001,"msg":"private-secret"}`, 200, true},
		{"wecom-ok", "wecom", `{"errcode":0}`, 200, false},
		{"wecom-refused", "wecom", `{"errcode":40013}`, 200, true},
		{"null-not-ack", "feishu", `{"code":null}`, 200, true},
		{"null-wecom", "wecom", `{"errcode":null}`, 200, true},
		{"string-not-ack", "feishu", `{"code":"0"}`, 200, true},
		{"missing-ack", "feishu", `{}`, 200, true},
		{"malformed-ack", "feishu", `not JSON`, 200, true},
		{"generic-status", "generic", ``, 202, false},
		{"http-failure", "generic", `private-secret`, 500, true},
		{"oversized", "generic", strings.Repeat("x", 65537), 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var received map[string]json.RawMessage
			var key, contentType string
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				key = r.Header.Get("Idempotency-Key")
				contentType = r.Header.Get("Content-Type")
				if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
					t.Errorf("invalid outgoing JSON: %v", err)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer endpoint.Close()
			err := PostEvent(context.Background(), WebhookClient(), Webhook{URL: endpoint.URL + "?token=private-secret", Format: tc.format}, event)
			if (err != nil) != tc.wantError {
				t.Fatalf("PostEvent error=%v wantError=%v", err, tc.wantError)
			}
			if err != nil && strings.Contains(err.Error(), "private-secret") {
				t.Fatal("webhook error leaked URL/response secrets")
			}
			if key != "10.0.0.1:event-unique" || contentType != "application/json" {
				t.Fatalf("missing receiver idempotency or content type: %q %q", key, contentType)
			}
			switch tc.format {
			case "feishu":
				if string(received["msg_type"]) != `"text"` || !strings.Contains(string(received["content"]), "app_100%.conf") {
					t.Fatalf("invalid Feishu payload: %s", received)
				}
			case "wecom":
				if string(received["msgtype"]) != `"text"` || !strings.Contains(string(received["text"]), "900150983cd24fb0d6963f7d28e17f72") {
					t.Fatalf("missing WeCom evidence: %s", received)
				}
			case "generic":
				if string(received["machine_ip"]) != `"10.0.0.1"` || len(received["data"]) == 0 {
					t.Fatalf("missing generic structured evidence: %s", received)
				}
			}
		})
	}
}

func TestWebhookDoesNotFollowRedirectAndHonorsTimeout(t *testing.T) {
	var targetCalls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/target", http.StatusTemporaryRedirect)
		case "/target":
			targetCalls.Add(1)
			w.WriteHeader(204)
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(500 * time.Millisecond):
			}
		}
	}))
	defer endpoint.Close()
	event := webhookEvent(t)
	if err := PostEvent(context.Background(), WebhookClient(), Webhook{URL: endpoint.URL + "/redirect", Format: "generic"}, event); err == nil {
		t.Fatal("redirect considered delivered")
	}
	if targetCalls.Load() != 0 {
		t.Fatal("webhook followed an unexpected redirect")
	}
	client := WebhookClient()
	client.Timeout = 30 * time.Millisecond
	start := time.Now()
	if err := PostEvent(context.Background(), client, Webhook{URL: endpoint.URL + "/slow", Format: "generic"}, event); err == nil {
		t.Fatal("slow webhook did not time out")
	}
	if time.Since(start) > time.Second {
		t.Fatal("HTTP client timeout was not honored")
	}
}

func TestWebhookRetrySurvivesReopenAndOneFailureDoesNotBlockOtherURLs(t *testing.T) {
	for _, eventType := range []string{"alert", "ssh_login"} {
		t.Run(eventType, func(t *testing.T) { testWebhookRetry(t, eventType) })
	}
}

func testWebhookRetry(t *testing.T, eventType string) {
	t.Helper()
	store, dir := testStore(t)
	s := testServer(store)
	ctx := context.Background()
	var badCalls, goodCalls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/flaky" && badCalls.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"code":19001}`)
			return
		}
		if r.URL.Path == "/good" {
			goodCalls.Add(1)
		}
		_, _ = io.WriteString(w, `{"code":0}`)
	}))
	defer endpoint.Close()
	badID := insertHook(t, store, "flaky", endpoint.URL+"/flaky", "feishu", true)
	goodID := insertHook(t, store, "good", endpoint.URL+"/good", "feishu", true)
	insertHook(t, store, "disabled", endpoint.URL+"/disabled", "feishu", false)
	data := testAlert()
	if eventType == "ssh_login" {
		data = map[string]any{"id": "login-1", "user": "root", "source_ip": "192.0.2.9", "terminal": "/dev/pts/1", "method": "publickey", "login_time": time.Now()}
	}
	packet := testPacket(t, "event-1", eventType, "10.0.0.1", time.Now(), data)
	requireIngest(t, store, packet, "127.0.0.1", true)
	jobs, err := s.due(ctx)
	if err != nil || len(jobs) != 2 {
		t.Fatalf("pending enabled jobs: %v %v", jobs, err)
	}
	for _, job := range jobs {
		if err := s.deliver(ctx, job); err != nil {
			t.Fatal(err)
		}
	}
	bad, err := store.Webhook(ctx, badID)
	if err != nil {
		t.Fatal(err)
	}
	good, err := store.Webhook(ctx, goodID)
	if err != nil {
		t.Fatal(err)
	}
	if bad.PendingCount != 1 || bad.LastError == "" || bad.LastSuccessAt != nil || good.PendingCount != 0 || good.LastSuccessAt == nil {
		t.Fatalf("failure affected another endpoint: bad=%+v good=%+v", bad, good)
	}
	var attempts int
	var dueAt int64
	var delivered sql.NullInt64
	if err := store.DB.QueryRow(`SELECT attempts,next_attempt_at,delivered_at FROM outbox WHERE webhook_id=?`, badID).Scan(&attempts, &dueAt, &delivered); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || delivered.Valid || dueAt <= stamp(time.Now()) {
		t.Fatal("failure was not retained with a future retry")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s = testServer(reopened)
	jobs, err = s.due(ctx)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("restart ignored persisted backoff: %v %v", jobs, err)
	}
	// Advance the persisted retry deadline instead of sleeping five seconds.
	if _, err := reopened.DB.Exec(`UPDATE outbox SET next_attempt_at=0 WHERE webhook_id=?`, badID); err != nil {
		t.Fatal(err)
	}
	jobs, err = s.due(ctx)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("retry was lost: %v %v", jobs, err)
	}
	if err := s.deliver(ctx, jobs[0]); err != nil {
		t.Fatal(err)
	}
	bad, err = reopened.Webhook(ctx, badID)
	if err != nil {
		t.Fatal(err)
	}
	if bad.PendingCount != 0 || bad.LastError != "" || bad.LastSuccessAt == nil || badCalls.Load() != 2 || goodCalls.Load() != 1 {
		t.Fatalf("retry didn't recover independently: bad=%+v requests=%d/%d", bad, badCalls.Load(), goodCalls.Load())
	}
	requireIngest(t, reopened, packet, "127.0.0.1", false)
	if countRows(t, reopened, "outbox") != 2 {
		t.Fatal("replay requeued notifications")
	}
}

func TestNotifierContinuesOtherDeliveryWhileEndpointIsBlocked(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	blockedStarted := make(chan struct{}, 1)
	fastDone := make(chan struct{}, 1)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blocked" {
			blockedStarted <- struct{}{}
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
			return
		}
		fastDone <- struct{}{}
		_, _ = fmt.Fprint(w, `{"code":0}`)
	}))
	defer endpoint.Close()
	insertHook(t, store, "blocked", endpoint.URL+"/blocked", "feishu", true)
	insertHook(t, store, "fast", endpoint.URL+"/fast", "feishu", true)
	requireIngest(t, store, testPacket(t, "notify", "alert", "10.0.0.1", time.Now(), testAlert()), "127.0.0.1", true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); s.RunNotifier(ctx) }()
	select {
	case <-blockedStarted:
	case <-time.After(4 * time.Second):
		t.Fatal("notifier did not start")
	}
	select {
	case <-fastDone:
	case <-time.After(time.Second):
		t.Fatal("blocked URL prevented delivery to another URL")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation failed to stop notifier")
	}
}
