package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Decode the public API contract independently of the sender's Go result type.
type webhookTestResponse struct {
	Message      string `json:"message"`
	Success      *bool  `json:"success"`
	Text         string `json:"text"`
	Format       string `json:"format"`
	HTTPStatus   *int   `json:"http_status"`
	BusinessCode *int   `json:"business_code"`
	DurationMS   *int64 `json:"duration_ms"`
}

type receivedWebhook struct {
	Path        string
	Method      string
	ContentType string
	Key         string
	Body        map[string]json.RawMessage
}

func captureWebhook(t *testing.T, r *http.Request) receivedWebhook {
	t.Helper()
	v := receivedWebhook{Path: r.URL.Path, Method: r.Method, ContentType: r.Header.Get("Content-Type"), Key: r.Header.Get("Idempotency-Key")}
	if err := json.NewDecoder(r.Body).Decode(&v.Body); err != nil {
		t.Errorf("decode outgoing webhook: %v", err)
	}
	return v
}

func awaitCapturedWebhook(t *testing.T, received <-chan receivedWebhook) receivedWebhook {
	t.Helper()
	select {
	case request := <-received:
		return request
	case <-time.After(2 * time.Second):
		t.Fatal("test API reported success without sending a webhook")
		return receivedWebhook{}
	}
}

func createHTTPWebhook(t *testing.T, s *Server, cookie *http.Cookie, name, endpoint, format string, enabled bool) Webhook {
	t.Helper()
	body := map[string]any{"name": name, "url": endpoint, "enabled": enabled}
	if format != "" {
		body["format"] = format
	}
	w := testRequest(t, s, http.MethodPost, "/api/webhooks", body, cookie, nil)
	requireStatus(t, w, http.StatusOK)
	return jsonResult[Webhook](t, w)
}

func requireFeishuText(t *testing.T, received receivedWebhook, expected string) {
	t.Helper()
	if received.Method != http.MethodPost || received.ContentType != "application/json" || received.Key == "" {
		t.Fatalf("incorrect outbound request: %+v", received)
	}
	var content struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(received.Body["content"], &content); err != nil {
		t.Fatalf("invalid Feishu content: %v", err)
	}
	if string(received.Body["msg_type"]) != `"text"` || content.Text == "" || content.Text != expected {
		t.Fatalf("outgoing Feishu text differs from API result: payload=%s result=%q", received.Body, expected)
	}
}

func requireWebhookTestResult(t *testing.T, w *httptest.ResponseRecorder, success bool, format string) webhookTestResponse {
	t.Helper()
	v := jsonResult[webhookTestResponse](t, w)
	if v.Success == nil || *v.Success != success || v.Format != format || v.Message == "" || v.Text == "" || v.DurationMS == nil || *v.DurationMS < 0 {
		t.Fatalf("incomplete webhook test result: %s", w.Body.String())
	}
	return v
}

func TestHTTPSavedWebhookTestSendsDefaultFeishuAndPersistsResult(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	received := make(chan receivedWebhook, 3)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- captureWebhook(t, r)
		_, _ = w.Write([]byte(`{"code":0,"msg":"success"}`))
	}))
	defer endpoint.Close()
	// Omitted format must use the same msg_type/content.text format as the user's example.
	hook := createHTTPWebhook(t, s, cookie, "security", endpoint.URL, "", true)
	if hook.Format != "feishu" {
		t.Fatalf("unexpected default format: %q", hook.Format)
	}
	path := fmt.Sprintf("/api/webhooks/%d/test", hook.ID)
	w := testRequest(t, s, http.MethodPost, path, nil, cookie, nil)
	requireStatus(t, w, http.StatusOK)
	result := requireWebhookTestResult(t, w, true, "feishu")
	if result.HTTPStatus == nil || *result.HTTPStatus != 200 || result.BusinessCode == nil || *result.BusinessCode != 0 {
		t.Fatalf("missing successful receiver acknowledgment: %s", w.Body.String())
	}
	requireFeishuText(t, awaitCapturedWebhook(t, received), result.Text)
	updated, err := store.Webhook(context.Background(), hook.ID)
	if err != nil || updated.LastSuccessAt == nil || updated.LastError != "" || updated.PendingCount != 0 {
		t.Fatalf("test success was not recorded: %+v err=%v", updated, err)
	}
	if countRows(t, store, "events") != 0 || countRows(t, store, "outbox") != 0 {
		t.Fatal("manual test created an alert or a retry job")
	}

	// Pausing automatic notification must still allow an explicit manual test.
	if _, err := store.DB.Exec(`UPDATE webhooks SET enabled=0 WHERE id=?`, hook.ID); err != nil {
		t.Fatal(err)
	}
	w = testRequest(t, s, http.MethodPost, path, map[string]string{"message": "人工验证：配置已暂停，但测试应该送达。"}, cookie, nil)
	requireStatus(t, w, http.StatusOK)
	result = requireWebhookTestResult(t, w, true, "feishu")
	if !strings.Contains(result.Text, "人工验证：配置已暂停，但测试应该送达。") {
		t.Fatalf("custom test message missing: %q", result.Text)
	}
	requireFeishuText(t, awaitCapturedWebhook(t, received), result.Text)
	updated, err = store.Webhook(context.Background(), hook.ID)
	if err != nil || updated.Enabled || updated.LastSuccessAt == nil || updated.PendingCount != 0 {
		t.Fatalf("manual test changed pause state or queued a delivery: %+v err=%v", updated, err)
	}
}

func TestHTTPWebhookTestReportsBusinessRejectionAndPersistsFailure(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = captureWebhook(t, r)
		if r.URL.Path == "/generic" {
			_, _ = w.Write([]byte(`{"code":19002,"msg":"receiver refused"}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":19001,"msg":"receiver refused"}`))
	}))
	defer endpoint.Close()
	for _, tc := range []struct {
		format string
		code   int
	}{{"feishu", 19001}, {"generic", 19002}} {
		t.Run(tc.format, func(t *testing.T) {
			hook := createHTTPWebhook(t, s, cookie, tc.format, endpoint.URL+"/"+tc.format, tc.format, true)
			w := testRequest(t, s, http.MethodPost, fmt.Sprintf("/api/webhooks/%d/test", hook.ID), nil, cookie, nil)
			requireStatus(t, w, http.StatusBadGateway)
			result := requireWebhookTestResult(t, w, false, tc.format)
			if result.HTTPStatus == nil || *result.HTTPStatus != 200 || result.BusinessCode == nil || *result.BusinessCode != tc.code {
				t.Fatalf("HTTP 200 concealed receiver rejection: %s", w.Body.String())
			}
			if !strings.Contains(result.Message, fmt.Sprint(tc.code)) {
				t.Fatalf("failure message omits actionable business code: %q", result.Message)
			}
			updated, err := store.Webhook(context.Background(), hook.ID)
			if err != nil || updated.LastError == "" || updated.LastSuccessAt != nil || updated.PendingCount != 0 {
				t.Fatalf("rejection incorrectly recorded as success: %+v err=%v", updated, err)
			}
		})
	}
	if calls.Load() != 2 || countRows(t, store, "outbox") != 0 {
		t.Fatal("manual failures were silently retried or no request was sent")
	}
}

func TestHTTPDraftWebhookTestUsesCurrentFormWithoutSaving(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	received := make(chan receivedWebhook, 1)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- captureWebhook(t, r)
		_, _ = w.Write([]byte(`{"StatusCode":0}`))
	}))
	defer endpoint.Close()
	saved := createHTTPWebhook(t, s, cookie, "saved", endpoint.URL+"/saved", "generic", false)
	body := map[string]any{"url": endpoint.URL + "/draft", "enabled": false, "message": "验证当前表单里的新地址"}
	w := testRequest(t, s, http.MethodPost, "/api/webhooks/test", body, cookie, nil)
	requireStatus(t, w, http.StatusOK)
	result := requireWebhookTestResult(t, w, true, "feishu")
	request := awaitCapturedWebhook(t, received)
	if request.Path != "/draft" || !strings.Contains(result.Text, "验证当前表单里的新地址") {
		t.Fatalf("draft test did not use the current form: request=%+v result=%+v", request, result)
	}
	requireFeishuText(t, request, result.Text)
	unchanged, err := store.Webhook(context.Background(), saved.ID)
	if err != nil || !reflect.DeepEqual(saved, unchanged) {
		t.Fatalf("draft changed saved configuration or status: before=%+v after=%+v err=%v", saved, unchanged, err)
	}
	if countRows(t, store, "webhooks") != 1 || countRows(t, store, "events") != 0 || countRows(t, store, "outbox") != 0 {
		t.Fatal("draft test saved configuration, history, or a retry job")
	}
}

func TestHTTPWebhookTestRejectsInvalidAndUnauthorizedBeforeSending(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	var calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer endpoint.Close()
	hook := createHTTPWebhook(t, s, cookie, "saved", endpoint.URL, "feishu", true)
	savedPath := fmt.Sprintf("/api/webhooks/%d/test", hook.ID)
	for _, body := range []any{
		map[string]any{},
		map[string]any{"url": "ftp://localhost/hook"},
		map[string]any{"url": endpoint.URL, "format": "unsupported"},
		map[string]any{"url": endpoint.URL, "message": []string{"wrong type"}},
		map[string]any{"url": endpoint.URL, "unexpected": true},
	} {
		requireStatus(t, testRequest(t, s, http.MethodPost, "/api/webhooks/test", body, cookie, nil), http.StatusBadRequest)
	}
	requireStatus(t, testRequest(t, s, http.MethodPost, savedPath, map[string]any{"message": []string{"wrong type"}}, cookie, nil), http.StatusBadRequest)
	requireStatus(t, testRequest(t, s, http.MethodPost, savedPath, map[string]any{"url": endpoint.URL}, cookie, nil), http.StatusBadRequest)
	requireStatus(t, testRequest(t, s, http.MethodPost, "/api/webhooks/999999/test", nil, cookie, nil), http.StatusNotFound)
	requireStatus(t, testRequest(t, s, http.MethodPost, savedPath, nil, nil, nil), http.StatusUnauthorized)
	requireStatus(t, testRequest(t, s, http.MethodPost, "/api/webhooks/test", map[string]string{"url": endpoint.URL}, nil, nil), http.StatusUnauthorized)
	if calls.Load() != 0 || countRows(t, store, "outbox") != 0 {
		t.Fatal("invalid or unauthorized request reached the receiver")
	}
	unchanged, err := store.Webhook(context.Background(), hook.ID)
	if err != nil || !reflect.DeepEqual(hook, unchanged) {
		t.Fatalf("rejected test changed delivery status: %+v err=%v", unchanged, err)
	}
}

func TestHTTPConfiguredWebhookAutomaticallyDeliversNewAlert(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	received := make(chan receivedWebhook, 2)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- captureWebhook(t, r)
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer endpoint.Close()
	hook := createHTTPWebhook(t, s, cookie, "运维安全告警", endpoint.URL, "", true)
	packet := testPacket(t, "automatic-alert", "alert", "10.20.30.40", time.Now(), testAlert())
	requireIngest(t, store, packet, "127.0.0.1", true)
	requireIngest(t, store, packet, "127.0.0.1", false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.RunNotifier(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("notifier did not stop")
		}
	}()
	select {
	case request := <-received:
		var content struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(request.Body["content"], &content); err != nil {
			t.Fatal(err)
		}
		requireFeishuText(t, request, content.Text)
		for _, evidence := range []string{"10.20.30.40", "node-a", "/etc/app_100%.conf", "900150983cd24fb0d6963f7d28e17f72", "d41d8cd98f00b204e9800998ecf8427e", "automatic-alert"} {
			if !strings.Contains(content.Text, evidence) {
				t.Fatalf("automatic notification missing %q: %s", evidence, content.Text)
			}
		}
		if request.Key != "10.20.30.40:automatic-alert" {
			t.Fatalf("invalid automatic delivery identity: %q", request.Key)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("API-configured webhook did not receive the new alert")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		updated, err := store.Webhook(context.Background(), hook.ID)
		if err != nil {
			t.Fatal(err)
		}
		if updated.PendingCount == 0 && updated.LastSuccessAt != nil && updated.LastError == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("automatic delivery result not persisted: %+v", updated)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if countRows(t, store, "events") != 1 || countRows(t, store, "outbox") != 1 {
		t.Fatal("replayed alert created duplicate events or notification jobs")
	}
}
