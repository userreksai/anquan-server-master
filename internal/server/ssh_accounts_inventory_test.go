package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testSSHAccountsSnapshot(at time.Time, names ...string) map[string]any {
	users := make([]any, 0, len(names))
	for i, name := range names {
		users = append(users, map[string]any{"name": name, "uid": i, "gid": i, "shell": "/bin/bash", "login_shell": true})
	}
	return map[string]any{"state": "ready", "source": "/etc/passwd", "checked_at": at, "total": len(users), "truncated": false, "users": users}
}

func testSSHAccountsStatus(snapshot any) map[string]any {
	data := componentData("running")
	data["inventory"] = map[string]any{"ssh_accounts": snapshot, "os": "Linux"}
	return data
}

func TestSSHAccountsInventoryValidation(t *testing.T) {
	at := time.Now().UTC()
	for _, tc := range []struct {
		name   string
		modify func(map[string]any)
	}{
		{"state", func(v map[string]any) { v["state"] = "running" }},
		{"source", func(v map[string]any) { v["source"] = "/etc/shadow" }},
		{"zero_time", func(v map[string]any) { v["checked_at"] = time.Time{} }},
		{"invalid_time", func(v map[string]any) { v["checked_at"] = "yesterday" }},
		{"negative_total", func(v map[string]any) { v["total"] = -1 }},
		{"fractional_total", func(v map[string]any) { v["total"] = 1.5 }},
		{"total_below_count", func(v map[string]any) { v["total"] = 0 }},
		{"unmarked_truncation", func(v map[string]any) { v["total"] = 2 }},
		{"truncated_type", func(v map[string]any) { v["truncated"] = "false" }},
		{"users_type", func(v map[string]any) { v["users"] = map[string]any{} }},
		{"duplicate_users", func(v map[string]any) {
			v["users"] = []any{v["users"].([]any)[0], v["users"].([]any)[0]}
			v["total"] = 2
		}},
		{"error_with_users", func(v map[string]any) { v["state"] = "error" }},
		{"unsupported_with_users", func(v map[string]any) { v["state"] = "unsupported" }},
		{"error_with_total", func(v map[string]any) { v["state"] = "error"; v["users"] = []any{} }},
		{"unsupported_truncated", func(v map[string]any) {
			v["state"] = "unsupported"
			v["users"] = []any{}
			v["total"] = 0
			v["truncated"] = true
		}},
		{"unknown_snapshot_field", func(v map[string]any) { v["shadow"] = "private-ssh-test-content" }},
		{"error_type", func(v map[string]any) { v["error"] = []string{"private-ssh-test-content"} }},
		{"error_null", func(v map[string]any) { v["error"] = nil }},
		{"error_length", func(v map[string]any) { v["error"] = strings.Repeat("x", 4097) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := testSSHAccountsSnapshot(at, "ubuntu")
			tc.modify(v)
			if err := validateComponentStatus(mustJSON(t, testSSHAccountsStatus(v))); err != errSSHAccountsInventory {
				t.Fatalf("invalid snapshot was not rejected with a bounded diagnostic: %v", err)
			}
		})
	}
	for _, field := range []string{"state", "source", "checked_at", "total", "truncated", "users"} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("required_%s_missing_%t", field, missing), func(t *testing.T) {
				v := testSSHAccountsSnapshot(at, "ubuntu")
				v[field] = nil
				if missing {
					delete(v, field)
				}
				if err := validateComponentStatus(mustJSON(t, testSSHAccountsStatus(v))); err == nil {
					t.Fatal("missing/null required snapshot field was accepted")
				}
			})
		}
	}
	for _, tc := range []struct {
		name  string
		field string
		value any
	}{
		{"name_pattern", "name", "private-ssh-test-content\nroot"},
		{"name_length", "name", strings.Repeat("a", 129)},
		{"uid_negative", "uid", -1},
		{"uid_overflow", "uid", uint64(1) << 32},
		{"uid_fraction", "uid", 0.5},
		{"gid_negative", "gid", -1},
		{"gid_overflow", "gid", uint64(1) << 32},
		{"shell_length", "shell", strings.Repeat("a", 257)},
		{"shell_control", "shell", "/bin/bash\n"},
		{"shell_unicode_control", "shell", "/bin/bash\u0085"},
		{"login_shell_type", "login_shell", "true"},
		{"password", "password", "private-ssh-test-content"},
		{"shadow", "shadow", "private-ssh-test-content"},
		{"home", "home", "/home/private-ssh-test-content"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := testSSHAccountsSnapshot(at, "ubuntu")
			v["users"].([]any)[0].(map[string]any)[tc.field] = tc.value
			if err := validateComponentStatus(mustJSON(t, testSSHAccountsStatus(v))); err != errSSHAccountsInventory || strings.Contains(err.Error(), "private-ssh-test-content") {
				t.Fatalf("invalid account was accepted or echoed: %v", err)
			}
		})
	}
	for _, field := range []string{"name", "uid", "gid", "shell", "login_shell"} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("account_%s_missing_%t", field, missing), func(t *testing.T) {
				v := testSSHAccountsSnapshot(at, "ubuntu")
				account := v["users"].([]any)[0].(map[string]any)
				account[field] = nil
				if missing {
					delete(account, field)
				}
				if err := validateComponentStatus(mustJSON(t, testSSHAccountsStatus(v))); err == nil {
					t.Fatal("missing/null required account field was accepted")
				}
			})
		}
	}
	for _, invalid := range []any{nil, []any{}, "ready", map[string]any{}} {
		if err := validateComponentStatus(mustJSON(t, testSSHAccountsStatus(invalid))); err == nil {
			t.Fatal("invalid account inventory shape was accepted")
		}
	}
}

func TestSSHAccountsInventoryBoundsAndCompatibility(t *testing.T) {
	at := time.Now().UTC()
	maximum := testSSHAccountsSnapshot(at)
	users := []any{}
	for i := range maxSSHInventoryUsers + 1 {
		users = append(users, map[string]any{"name": fmt.Sprintf("u%x", i), "uid": 0, "gid": 0, "shell": "", "login_shell": true})
	}
	maximum["users"], maximum["total"] = users[:maxSSHInventoryUsers], maxSSHInventoryUsers
	if err := validateComponentStatus(mustJSON(t, testSSHAccountsStatus(maximum))); err != nil {
		t.Fatalf("maximum account count was rejected: %v", err)
	}
	maximum["users"], maximum["total"] = users, len(users)
	if len(mustJSON(t, maximum)) > maxSSHAccountsInventoryBytes {
		t.Fatal("account-count fixture also exceeds the byte bound")
	}
	if err := validateComponentStatus(mustJSON(t, testSSHAccountsStatus(maximum))); err == nil {
		t.Fatal("too many users were accepted")
	}
	maximum["users"], maximum["total"] = users[:100], 100
	for _, account := range users[:100] {
		account.(map[string]any)["shell"] = strings.Repeat("a", 256)
	}
	if len(mustJSON(t, maximum)) <= maxSSHAccountsInventoryBytes {
		t.Fatal("inventory byte-limit fixture is too small")
	}
	if err := validateComponentStatus(mustJSON(t, testSSHAccountsStatus(maximum))); err == nil {
		t.Fatal("oversized account inventory was accepted")
	}
	for _, state := range []string{"ready", "error", "unsupported"} {
		v := testSSHAccountsSnapshot(at)
		v["state"] = state
		if state != "ready" {
			v["error"] = "account inventory is unavailable"
		}
		if err := validateComponentStatus(mustJSON(t, testSSHAccountsStatus(v))); err != nil {
			t.Fatalf("valid empty %s inventory was rejected: %v", state, err)
		}
	}
	truncated := testSSHAccountsSnapshot(at, strings.Repeat("a", 127)+"$")
	truncated["total"], truncated["truncated"] = 300, true
	account := truncated["users"].([]any)[0].(map[string]any)
	account["uid"], account["gid"], account["shell"], account["login_shell"] = uint64(1)<<32-1, uint64(1)<<32-1, strings.Repeat("a", 256), false
	if err := validateComponentStatus(mustJSON(t, testSSHAccountsStatus(truncated))); err != nil {
		t.Fatalf("valid truncated inventory or account boundary was rejected: %v", err)
	}
	for _, inventory := range []any{nil, "legacy inventory", []string{"legacy"}, map[string]any{"progress": 2, "future_extension": map[string]any{"version": 2}}} {
		data := componentData("running")
		data["inventory"] = inventory
		if err := validateComponentStatus(mustJSON(t, data)); err != nil {
			t.Fatalf("unrelated legacy inventory was rejected: %v", err)
		}
	}
	if err := validateComponentStatus(mustJSON(t, componentData("running"))); err != nil {
		t.Fatalf("older Agent report without inventory was rejected: %v", err)
	}
}

func TestSSHAccountsInventoryCannotHideUnknownFieldsInDuplicateObjects(t *testing.T) {
	valid := string(mustJSON(t, testSSHAccountsSnapshot(time.Now().UTC(), "ubuntu")))
	invalid := strings.TrimSuffix(valid, "}") + `,"password":"private-ssh-test-content"}`
	for _, raw := range []string{
		`{"components":[],"inventory":{"ssh_accounts":` + invalid + `,"ssh_accounts":` + valid + `}}`,
		`{"components":[],"inventory":{"ssh_accounts":` + invalid + `},"inventory":{"ssh_accounts":` + valid + `}}`,
		`{"components":[],"Inventory":{"SSH_ACCOUNTS":` + invalid + `}}`,
	} {
		if err := validateComponentStatus(json.RawMessage(raw)); err != errSSHAccountsInventory {
			t.Fatalf("hidden account fields were accepted or echoed: %v", err)
		}
	}
}

func TestSSHAccountsInventoryRejectedBeforeStorage(t *testing.T) {
	s, _ := testStore(t)
	at := time.Now().UTC()
	snapshot := testSSHAccountsSnapshot(at, "ubuntu")
	snapshot["users"].([]any)[0].(map[string]any)["password"] = "private-ssh-test-content"
	if _, err := s.Ingest(context.Background(), testPacket(t, "invalid-accounts", "component_status", "10.0.0.1", at, testSSHAccountsStatus(snapshot)), "127.0.0.1"); err != errSSHAccountsInventory {
		t.Fatalf("sensitive account payload was not rejected with a safe error: %v", err)
	}
	for _, table := range []string{"machines", "machine_security_status", "events", "outbox"} {
		if countRows(t, s, table) != 0 {
			t.Fatalf("invalid inventory changed %s", table)
		}
	}
}

func TestSSHAccountsInventoryLatestSnapshotsStayIsolatedAndHaveNoHistory(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)
	insertHook(t, s, "accounts", "http://127.0.0.1/unused", "generic", true)
	requireIngest(t, s, testPacket(t, "node-a-accounts", "component_status", "10.0.0.1", at, testSSHAccountsStatus(testSSHAccountsSnapshot(at, "ubuntu"))), "127.0.0.1", false)
	requireIngest(t, s, testPacket(t, "node-b-accounts", "component_status", "10.0.0.2", at, testSSHAccountsStatus(testSSHAccountsSnapshot(at, "ec2-user"))), "127.0.0.1", false)
	updated := testSSHAccountsSnapshot(at.Add(time.Minute), "ubuntu", "deploy")
	requireIngest(t, s, testPacket(t, "node-a-updated", "component_status", "10.0.0.1", at.Add(time.Minute), testSSHAccountsStatus(updated)), "127.0.0.1", false)
	// Even a newer inventory checked_at cannot make a late envelope current.
	requireIngest(t, s, testPacket(t, "node-a-late", "component_status", "10.0.0.1", at.Add(time.Second), testSSHAccountsStatus(testSSHAccountsSnapshot(at.Add(time.Hour), "stale-user"))), "127.0.0.1", false)
	server := testServer(s)
	cookie := testLogin(t, server, DefaultPassword)
	for ip, want := range map[string][]string{"10.0.0.1": {"ubuntu", "deploy"}, "10.0.0.2": {"ec2-user"}} {
		response := testRequest(t, server, "GET", "/api/security/status?machine_ip="+ip, nil, cookie, nil)
		requireStatus(t, response, 200)
		result := jsonResult[struct {
			Items []SecurityStatus `json:"items"`
		}](t, response)
		if len(result.Items) != 1 || result.Items[0].MachineIP != ip {
			t.Fatal("account inventory leaked across the machine filter")
		}
		var data struct {
			Inventory struct {
				SSHAccounts struct {
					Users []struct {
						Name string `json:"name"`
					} `json:"users"`
				} `json:"ssh_accounts"`
			} `json:"inventory"`
		}
		if err := json.Unmarshal(result.Items[0].Data, &data); err != nil || len(data.Inventory.SSHAccounts.Users) != len(want) {
			t.Fatalf("latest inventory was not returned: %v", err)
		}
		for i, name := range want {
			if data.Inventory.SSHAccounts.Users[i].Name != name {
				t.Fatal("account snapshot was rolled back or mixed with another host")
			}
		}
	}
	for i, state := range []string{"error", "unsupported"} {
		unavailable := testSSHAccountsSnapshot(at.Add(time.Duration(i+2) * time.Minute))
		unavailable["state"], unavailable["error"] = state, "account inventory is unavailable"
		requireIngest(t, s, testPacket(t, "accounts-"+state, "component_status", "10.0.0.1", at.Add(time.Duration(i+2)*time.Minute), testSSHAccountsStatus(unavailable)), "127.0.0.1", false)
	}
	// A newer legacy report replaces the whole snapshot rather than preserving
	// an account list that its current Agent no longer reports.
	requireIngest(t, s, testPacket(t, "legacy-agent", "component_status", "10.0.0.1", at.Add(4*time.Minute), componentData("running")), "127.0.0.1", false)
	statuses, err := s.SecurityStatuses(ctx, "10.0.0.1")
	if err != nil || len(statuses) != 1 || strings.Contains(string(statuses[0].Data), "ssh_accounts") {
		t.Fatalf("newer legacy report retained a stale account list: %v", err)
	}
	if countRows(t, s, "events") != 0 || countRows(t, s, "outbox") != 0 {
		t.Fatal("account inventory changes produced security history or notifications")
	}
}
