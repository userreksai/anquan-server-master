package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestEventFiltersPaginationAndMachineScopedLiteralSearch(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	at := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		requireIngest(t, store, testPacket(t, fmt.Sprint(i), "alert", "10.0.0.1", at.Add(time.Duration(i)*time.Second), testAlert()), "127.0.0.1", true)
	}
	requireIngest(t, store, testPacket(t, "other", "alert", "10.0.0.2", at, testAlert()), "127.0.0.1", true)
	var ids []int64
	for page := 1; page <= 2; page++ {
		w := testRequest(t, s, "GET", fmt.Sprintf("/api/events?machine_ip=10.0.0.1&type=alert&page=%d&page_size=2", page), nil, cookie, nil)
		requireStatus(t, w, 200)
		p := jsonResult[Page[Event]](t, w)
		if p.Total != 3 || p.Page != page || p.PageSize != 2 {
			t.Fatalf("bad page: %+v", p)
		}
		for _, e := range p.Items {
			ids = append(ids, e.ID)
			if e.MachineIP != "10.0.0.1" {
				t.Fatal("machine filter leaked another machine")
			}
		}
	}
	if len(ids) != 3 || ids[0] <= ids[1] || ids[1] <= ids[2] {
		t.Fatalf("unstable pagination ordering: %v", ids)
	}
	values := url.Values{"machine_ip": {"10.0.0.1"}, "q": {"100%"}, "from": {at.Add(time.Second).Format(time.RFC3339)}, "to": {at.Add(time.Second).In(time.FixedZone("east", 8*3600)).Format(time.RFC3339)}}
	w := testRequest(t, s, "GET", "/api/events?"+values.Encode(), nil, cookie, nil)
	requireStatus(t, w, 200)
	if page := jsonResult[Page[Event]](t, w); page.Total != 1 {
		t.Fatalf("inclusive timezone-aware filter/literal percent search: %+v", page)
	}
	values = url.Values{"q": {"app_100%"}}
	w = testRequest(t, s, "GET", "/api/events?"+values.Encode(), nil, cookie, nil)
	requireStatus(t, w, 200)
	if p := jsonResult[Page[Event]](t, w); p.Total != 4 {
		t.Fatal("literal LIKE search lost file paths")
	}
	values.Set("q", "' OR 1=1 --")
	w = testRequest(t, s, "GET", "/api/events?"+values.Encode(), nil, cookie, nil)
	requireStatus(t, w, 200)
	if p := jsonResult[Page[Event]](t, w); p.Total != 0 {
		t.Fatal("query text changed SQL semantics")
	}
	for _, query := range []string{"page=0", "page=-1", "page=1000001", "page=1&page=2", "page_size=0", "page_size=101", "page_size=abc", "from=2026-10-02", "from=2026-10-03T00:00:00Z&to=2026-10-02T00:00:00Z", "type=command", "status=deleted", "machine_ip=not-an-ip"} {
		requireStatus(t, testRequest(t, s, "GET", "/api/events?"+query, nil, cookie, nil), 400)
	}
}

func TestHTTPCRUDAndForeignKeyCascades(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	create := func(name string) Webhook {
		w := testRequest(t, s, "POST", "/api/webhooks", map[string]any{"name": name, "url": "http://127.0.0.1:1/hook", "format": "generic", "enabled": true}, cookie, nil)
		requireStatus(t, w, 200)
		return jsonResult[Webhook](t, w)
	}
	first, second := create("first"), create("second")
	for i := 0; i < 2; i++ {
		requireIngest(t, store, testPacket(t, fmt.Sprint(i), "alert", "10.0.0.1", time.Now(), testAlert()), "127.0.0.1", true)
	}
	if countRows(t, store, "outbox") != 4 {
		t.Fatal("not all enabled URLs queued")
	}
	w := testRequest(t, s, "PATCH", "/api/machines/10.0.0.1", map[string]string{"alias": "production", "notes": "owner operations"}, cookie, nil)
	requireStatus(t, w, 200)
	if m := jsonResult[Machine](t, w); m.Alias != "production" || m.Notes != "owner operations" {
		t.Fatal("machine edit not persisted")
	}
	w = testRequest(t, s, "GET", "/api/machines?q=production", nil, cookie, nil)
	requireStatus(t, w, 200)
	if p := jsonResult[Page[Machine]](t, w); p.Total != 1 {
		t.Fatal("machine alias search failed")
	}
	page, err := store.Events(context.Background(), Filter{Page: 1, Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	id := page.Items[0].ID
	w = testRequest(t, s, "PATCH", fmt.Sprintf("/api/events/%d", id), map[string]string{"status": "resolved", "notes": "reviewed"}, cookie, nil)
	requireStatus(t, w, 200)
	if e := jsonResult[Event](t, w); e.Status != "resolved" || e.Notes != "reviewed" {
		t.Fatal("event edit not persisted")
	}
	w = testRequest(t, s, "GET", "/api/events?status=resolved", nil, cookie, nil)
	requireStatus(t, w, 200)
	if p := jsonResult[Page[Event]](t, w); p.Total != 1 {
		t.Fatal("resolved filter failed")
	}
	requireStatus(t, testRequest(t, s, "DELETE", fmt.Sprintf("/api/events/%d", id), nil, cookie, nil), 200)
	if countRows(t, store, "outbox") != 2 {
		t.Fatal("event delete did not cascade to pending deliveries")
	}
	requireStatus(t, testRequest(t, s, "GET", fmt.Sprintf("/api/events/%d", id), nil, cookie, nil), 404)
	w = testRequest(t, s, "PUT", fmt.Sprintf("/api/webhooks/%d", first.ID), map[string]any{"name": "disabled", "url": first.URL, "format": "generic", "enabled": false}, cookie, nil)
	requireStatus(t, w, 200)
	if jsonResult[Webhook](t, w).Enabled {
		t.Fatal("disable did not persist")
	}
	requireStatus(t, testRequest(t, s, "DELETE", fmt.Sprintf("/api/webhooks/%d", second.ID), nil, cookie, nil), 200)
	if countRows(t, store, "outbox") != 1 {
		t.Fatal("webhook delete did not cascade")
	}
	requireStatus(t, testRequest(t, s, "DELETE", "/api/machines/10.0.0.1", nil, cookie, nil), 200)
	if countRows(t, store, "events") != 0 || countRows(t, store, "outbox") != 0 || countRows(t, store, "webhooks") != 1 {
		t.Fatal("machine cascade damaged unrelated configuration or left orphans")
	}
	requireStatus(t, testRequest(t, s, "DELETE", "/api/machines/10.0.0.1", nil, cookie, nil), 404)
}

func TestRequestValidationRejectsMalformedAndUnsafeWebhookInputs(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	for _, endpoint := range []string{"file:///etc/passwd", "ftp://example.com/hook", "https://user:pass@example.com/hook", "https://example.com/hook#token"} {
		requireStatus(t, testRequest(t, s, "POST", "/api/webhooks", map[string]any{"name": "invalid", "url": endpoint, "format": "generic"}, cookie, nil), 400)
	}
	for _, body := range []string{`{"name":"x"} {}`, `{"name":"x","unknown":true}`, `{`, string(bytes.Repeat([]byte("x"), 65537))} {
		r := httptest.NewRequest("POST", "http://security.test/api/webhooks", bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		requireStatus(t, w, 400)
	}
	requireStatus(t, testRequest(t, s, "POST", "/api/webhooks", map[string]string{"name": "x"}, cookie, map[string]string{"Content-Type": "text/plain"}), 415)
	if countRows(t, store, "webhooks") != 0 {
		t.Fatal("invalid webhook input persisted")
	}
}
