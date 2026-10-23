package server

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHardeningProfileIndependentKernelSwitchesAndWithdrawal(t *testing.T) {
	values := map[string]any{"kernel.dmesg_restrict": "1", "kernel.kptr_restrict": "2", "net.ipv4.conf.all.rp_filter": "1", "net.ipv4.tcp_syncookies": "1", "net.ipv4.ip_forward": "0"}
	patch := map[string]any{"policies": map[string]any{"mode": "enforce", "sysctl": values, "ssh": map[string]any{"disable_forwarding": true, "strong_crypto": true}}}
	config, _, err := composeProfile("server: {}\n", patch)
	if err != nil {
		t.Fatal(err)
	}
	for key := range values {
		if !strings.Contains(config, key+":") {
			t.Fatalf("missing kernel policy %s in %s", key, config)
		}
	}
	delete(values, "kernel.kptr_restrict")
	config, _, err = composeProfile(config, map[string]any{"policies": map[string]any{"sysctl": values}})
	if err != nil || strings.Contains(config, "kernel.kptr_restrict:") || !strings.Contains(config, "net.ipv4.tcp_syncookies:") || !strings.Contains(config, "net.ipv4.ip_forward:") {
		t.Fatal("withdrawal changed other kernel policies", config, err)
	}
	for key, limit := range map[string]int{"kernel.dmesg_restrict": 1, "kernel.kptr_restrict": 2, "net.ipv4.conf.all.rp_filter": 2, "net.ipv4.tcp_syncookies": 2} {
		for _, value := range []string{"-1", fmt.Sprint(limit + 1), "+1", "01", " 1", "1 ", "true", "1\n2"} {
			_, _, err := composeProfile("server: {}\n", map[string]any{"policies": map[string]any{"sysctl": map[string]any{key: value}}})
			if err == nil {
				t.Fatalf("accepted %s=%q", key, value)
			}
		}
		for value := 0; value <= limit; value++ {
			if _, _, err := composeProfile("server: {}\n", map[string]any{"policies": map[string]any{"sysctl": map[string]any{key: fmt.Sprint(value)}}}); err != nil {
				t.Fatalf("valid custom kernel value rejected: %s=%d: %v", key, value, err)
			}
		}
	}
}

func TestHardeningProfileSudoRestrictionsAndGRUBRequirements(t *testing.T) {
	for _, users := range [][]any{{"root"}, {"ALL"}, {"ops", "ops"}, {"ops ALL=(ALL)"}, {""}, make([]any, 129)} {
		if _, _, err := composeProfile("server: {}\n", map[string]any{"sudo": map[string]any{"restrict_users": users}}); err == nil {
			t.Fatal("unsafe restrict_users accepted", users)
		}
	}
	if _, _, err := composeProfile("server: {}\n", map[string]any{"sudo": map[string]any{"restrict_users": []any{"ops", "deploy"}}}); err != nil {
		t.Fatal(err)
	}
	input := "security:\n  policies:\n    mode: audit\n    grub:\n      enabled: true\n      protect_single_user: true\n"
	if _, _, err := composeProfile(input, map[string]any{"policies": map[string]any{"mode": "enforce"}}); err == nil {
		t.Fatal("partial enforce patch bypassed missing GRUB hash")
	}
	if _, _, err := composeProfile(input, map[string]any{"policies": map[string]any{"grub": map[string]any{"enabled": false}}}); err == nil {
		t.Fatal("partial patch bypassed protection dependency")
	}
	patch := map[string]any{"policies": map[string]any{"mode": "enforce", "grub": map[string]any{"password_hash": "grub.pbkdf2.sha512.10000.AABB.1234"}}}
	if _, _, err := composeProfile(input, patch); err != nil {
		t.Fatal("valid GRUB policy rejected", err)
	}
	for _, hash := range []string{"grub.pbkdf2.sha512.0.AA.12", "grub.pbkdf2.sha512.01.AA.12", "grub.pbkdf2.sha512.+1.AA.12", "grub.pbkdf2.sha512.4294967296.AA.12", "grub.pbkdf2.sha512.1000.A.12", "grub.pbkdf2.sha512.1000.AA.123", "grub.pbkdf2.sha512.1000.AA.ZZ", "grub.pbkdf2.sha512.1000..12", strings.Repeat("A", 4097)} {
		patch["policies"].(map[string]any)["grub"].(map[string]any)["password_hash"] = hash
		if _, _, err := composeProfile(input, patch); err == nil {
			t.Fatal("unusable GRUB hash accepted", hash)
		}
	}
	for _, timeout := range []float64{1, 59, 86401} {
		if _, _, err := composeProfile("server: {}\n", map[string]any{"policies": map[string]any{"session_timeout_seconds": timeout}}); err == nil {
			t.Fatal("invalid session timeout accepted", timeout)
		}
	}
}

func TestPolicyStatusRetainsModeChecksAndDeduplicatesCheckTimes(t *testing.T) {
	s, _ := testStore(t)
	at := time.Now().UTC().Truncate(time.Millisecond)
	component := map[string]any{"name": "policies", "enabled": true, "installed": true, "running": false, "state": "audit_drift", "policy_mode": "audit", "checked_at": at, "checks": []any{map[string]any{"setting": "sysctl.kernel.kptr_restrict", "expected": "2", "actual": "1", "compliant": false, "message": "only checked", "error": ""}}}
	data := map[string]any{"components": []any{component}}
	requireIngest(t, s, testPacket(t, "policy-initial", "component_status", "10.0.0.1", at, data), "127.0.0.1", true)
	component["checked_at"] = at.Add(time.Second)
	requireIngest(t, s, testPacket(t, "policy-same", "component_status", "10.0.0.1", at.Add(time.Second), data), "127.0.0.1", false)
	statuses, err := s.SecurityStatuses(context.Background(), "10.0.0.1")
	if err != nil || len(statuses) != 1 || !strings.Contains(string(statuses[0].Data), `"policy_mode":"audit"`) || !strings.Contains(string(statuses[0].Data), `"checked_at"`) || !strings.Contains(string(statuses[0].Data), `"actual":"1"`) {
		t.Fatal("policy snapshot lost evidence", statuses, err)
	}
	component["policy_mode"], component["state"] = "enforce", "drift"
	requireIngest(t, s, testPacket(t, "policy-enforce-drift", "component_status", "10.0.0.1", at.Add(2*time.Second), data), "127.0.0.1", true)
	component["state"] = "error"
	component["checks"].([]any)[0].(map[string]any)["error"] = "permission denied"
	requireIngest(t, s, testPacket(t, "policy-check-error", "component_status", "10.0.0.1", at.Add(3*time.Second), data), "127.0.0.1", true)
	component["state"] = "compliant"
	component["checks"] = []any{map[string]any{"setting": "sysctl.kernel.kptr_restrict", "expected": "2", "actual": "2", "compliant": true}}
	requireIngest(t, s, testPacket(t, "policy-recovered", "component_status", "10.0.0.1", at.Add(4*time.Second), data), "127.0.0.1", true)
	if countRows(t, s, "events") != 4 {
		t.Fatal("policy transitions lost history or timestamp repeated history")
	}
}
