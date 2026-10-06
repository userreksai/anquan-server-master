package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type webhookRoundTripFunc func(*http.Request) (*http.Response, error)

func (f webhookRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestLarkOfficialURLCorrectsLegacyGenericWireFormat(t *testing.T) {
	const endpoint = "https://open.larksuite.com/open-apis/bot/v2/hook/test-secret"
	for _, tc := range []struct {
		name string
		body string
		code int
		ok   bool
	}{
		{"current-success", `{"code":0,"msg":"success"}`, 0, true},
		{"legacy-success", `{"StatusCode":0,"StatusMessage":"success"}`, 0, true},
		{"http-200-business-rejection", `{"code":9499,"msg":"Bad Request"}`, 9499, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var received receivedWebhook
			client := WebhookClient()
			client.Transport = webhookRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != endpoint {
					t.Errorf("unexpected outbound destination: %s", r.URL)
				}
				received = captureWebhook(t, r)
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
			})
			result, err := SendEvent(context.Background(), client, Webhook{URL: endpoint, Format: "generic"}, webhookEvent(t))
			if calls != 1 || (err == nil) != tc.ok || result.Success != tc.ok || result.Format != "feishu" {
				t.Fatalf("Lark compatibility failed: calls=%d result=%+v err=%v", calls, result, err)
			}
			if result.HTTPStatus != 200 || result.BusinessCode == nil || *result.BusinessCode != tc.code {
				t.Fatalf("Lark acknowledgment not reflected in result: %+v", result)
			}
			requireFeishuText(t, received, result.Text)
			for _, genericKey := range []string{"event_id", "kind", "text", "data"} {
				if _, exists := received.Body[genericKey]; exists {
					t.Fatalf("legacy generic payload field %q sent to Lark: %s", genericKey, received.Body)
				}
			}
			if !tc.ok && (err == nil || !strings.Contains(result.Message, fmt.Sprint(tc.code))) {
				t.Fatalf("HTTP success hid Lark rejection: %+v err=%v", result, err)
			}
			if strings.Contains(result.Message, "test-secret") {
				t.Fatalf("delivery diagnostic leaked webhook secret: %q", result.Message)
			}
		})
	}
}

func TestLarkFormatDetectionRequiresExactOfficialHostAndBotPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		want string
	}{
		{"lark", "https://open.larksuite.com/open-apis/bot/v2/hook/test-secret", "feishu"},
		{"feishu", "https://open.feishu.cn/open-apis/bot/v2/hook/test-secret", "feishu"},
		{"case-insensitive-host", "https://OPEN.LARKSUITE.COM/open-apis/bot/v2/hook/test-secret", "feishu"},
		{"lark-suffix-attacker", "https://open.larksuite.com.attacker.test/open-apis/bot/v2/hook/test-secret", "generic"},
		{"feishu-suffix-attacker", "https://open.feishu.cn.attacker.test/open-apis/bot/v2/hook/test-secret", "generic"},
		{"unrecognized-subdomain", "https://attacker.open.larksuite.com/open-apis/bot/v2/hook/test-secret", "generic"},
		{"similar-name", "https://notopen.larksuite.com/open-apis/bot/v2/hook/test-secret", "generic"},
		{"unrelated-path", "https://open.larksuite.com/custom/webhook", "generic"},
		{"lookalike-path", "https://open.larksuite.com/open-apis/bot/v2/hook-extra/test-secret", "generic"},
		{"generic-bot-path", "https://receiver.example/open-apis/bot/v2/hook/test-secret", "generic"},
		{"generic-query", "https://receiver.example/hook?url=https://open.larksuite.com/open-apis/bot/v2/hook/test-secret", "generic"},
		{"ordinary-webhook", "https://receiver.example/webhook", "generic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := Webhook{Name: "format check", URL: tc.url, Format: "generic"}
			if got := webhookFormat(hook); got != tc.want {
				t.Fatalf("webhookFormat(%q)=%q, want %q", tc.url, got, tc.want)
			}
			if err := validateWebhook(&hook); err != nil || hook.Format != tc.want {
				t.Fatalf("validated format=%q want=%q err=%v", hook.Format, tc.want, err)
			}
		})
	}
}

func TestReadLegacyLarkGenericConfigurationNormalizesFormat(t *testing.T) {
	store, _ := testStore(t)
	larkID := insertHook(t, store, "legacy Lark", "https://open.larksuite.com/open-apis/bot/v2/hook/test-secret", "generic", true)
	feishuID := insertHook(t, store, "legacy Feishu", "https://open.feishu.cn/open-apis/bot/v2/hook/test-secret", "generic", true)
	genericID := insertHook(t, store, "generic", "https://receiver.example/webhook", "generic", true)
	wants := map[int64]string{larkID: "feishu", feishuID: "feishu", genericID: "generic"}
	for id, want := range wants {
		hook, err := store.Webhook(context.Background(), id)
		if err != nil || hook.Format != want {
			t.Fatalf("legacy config id=%d format=%q want=%q err=%v", id, hook.Format, want, err)
		}
	}
	hooks, err := store.Webhooks(context.Background())
	if err != nil || len(hooks) != len(wants) {
		t.Fatalf("list legacy configs: count=%d err=%v", len(hooks), err)
	}
	for _, hook := range hooks {
		if hook.Format != wants[hook.ID] {
			t.Fatalf("list returned incorrect legacy format: %+v", hook)
		}
	}
}
