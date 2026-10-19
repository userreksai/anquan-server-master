package server

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"testing"
	"time"
)

func TestEventOrderAppliesBeforePaginationWithSameSecondCommands(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	at := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	// Insert out of timestamp order so that both the primary time order and
	// the same-second ID tie-breaker must be applied before splitting pages.
	for _, command := range []struct {
		id string
		at time.Time
	}{
		{"late", at.Add(time.Second)},
		{"same-second-1", at},
		{"early", at.Add(-time.Second)},
		{"same-second-2", at},
		{"same-second-3", at},
	} {
		data := commandData(command.id, command.at)
		data["command"] = "printf " + command.id
		requireIngest(t, store, testPacket(t, command.id, "command_history", "10.0.0.1", at, data), "127.0.0.1", true)
	}
	requireIngest(t, store, testPacket(t, "other-machine", "command_history", "10.0.0.2", at, commandData("other-machine", at)), "127.0.0.1", true)
	requireIngest(t, store, testPacket(t, "other-type", "alert", "10.0.0.1", at, testAlert()), "127.0.0.1", true)

	ascending := []string{"early", "same-second-1", "same-second-2", "same-second-3", "late"}
	descending := []string{"late", "same-second-3", "same-second-2", "same-second-1", "early"}
	for _, tc := range []struct {
		name, order string
		want        []string
	}{
		{"default-descending", "", descending},
		{"explicit-descending", "desc", descending},
		{"ascending", "asc", ascending},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for page := 1; page <= 3; page++ {
				query := url.Values{
					"machine_ip": {"10.0.0.1"},
					"type":       {"command_history"},
					"page_size":  {"2"},
					"page":       {fmt.Sprint(page)},
				}
				if tc.order != "" {
					query.Set("order", tc.order)
				}
				w := testRequest(t, s, "GET", "/api/events?"+query.Encode(), nil, cookie, nil)
				requireStatus(t, w, 200)
				result := jsonResult[Page[Event]](t, w)
				if result.Total != 5 || result.Page != page || result.PageSize != 2 {
					t.Fatalf("unexpected pagination metadata: %+v", result)
				}
				wantSize := 2
				if page == 3 {
					wantSize = 1
				}
				if len(result.Items) != wantSize {
					t.Fatalf("page %d contains %d records, want %d", page, len(result.Items), wantSize)
				}
				for _, event := range result.Items {
					got = append(got, event.EventID)
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("cross-page command order = %v, want %v", got, tc.want)
			}
		})
	}

	// Existing direct Store callers leave Order empty and must keep newest first.
	result, err := store.Events(context.Background(), Filter{Page: 1, Size: 2, MachineIP: "10.0.0.1", Type: "command_history"})
	if err != nil || len(result.Items) != 2 || result.Items[0].EventID != "late" || result.Items[1].EventID != "same-second-3" {
		t.Fatalf("empty Store order changed the default: %+v, %v", result, err)
	}
}

func TestEventOrderRejectsInvalidOrRepeatedParameters(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	for _, tc := range []struct {
		name   string
		values []string
	}{
		{"empty", []string{""}},
		{"unknown", []string{"newest"}},
		{"uppercase", []string{"ASC"}},
		{"whitespace", []string{" asc"}},
		{"SQL-fragment", []string{"asc; DROP TABLE events"}},
		{"repeated-same", []string{"asc", "asc"}},
		{"repeated-different", []string{"asc", "desc"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := url.Values{"order": tc.values}
			requireStatus(t, testRequest(t, s, "GET", "/api/events?"+query.Encode(), nil, cookie, nil), 400)
		})
	}
	if _, err := store.Events(context.Background(), Filter{Page: 1, Size: 2, Order: "asc; DROP TABLE events"}); err == nil {
		t.Fatal("Store accepted an order outside the SQL direction whitelist")
	}
}
