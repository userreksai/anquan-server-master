package server

import (
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func TestAgentEncryptionUsesFixedKeyAndRequiresAuthentication(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/settings/agent-encryption"
	config := "# 配置说明\noutput_dir: /usr/local/anquan\nserver:\n  - 192.0.2.1:55555\n"
	body := map[string]string{"yaml": config}
	requireStatus(t, testRequest(t, s, "POST", path, body, nil, nil), 401)
	requireStatus(t, testRequest(t, s, "GET", path, nil, nil, nil), 401)
	cookie := testLogin(t, s, DefaultPassword)
	requireStatus(t, testRequest(t, s, "POST", path, body, cookie, map[string]string{"Origin": "https://other.test"}), 403)
	t.Setenv("ANQU_AGENT_AGE_RECIPIENT", id.Recipient().String())
	settings := jsonResult[map[string]string](t, testRequest(t, s, "GET", path, nil, cookie, nil))
	if settings["recipient"] != "" || settings["filename"] != "config.age" {
		t.Fatal("settings mismatch")
	}
	previous := ""
	for i := 0; i < 2; i++ {
		w := testRequest(t, s, "POST", path, body, cookie, nil)
		requireStatus(t, w, 200)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("response must not be cached")
		}
		result := jsonResult[map[string]string](t, w)
		ciphertext := result["ciphertext"]
		if ciphertext == previous || strings.Contains(ciphertext, "output_dir") || result["filename"] != "config.age" {
			t.Fatal("invalid encrypted response")
		}
		data, err := io.ReadAll(armor.NewReader(strings.NewReader(ciphertext)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(data), "age-encryption.org/v1\n") || result["recipient"] != "" {
			t.Fatal("invalid age armor or recipient exposed")
		}
		if _, err := age.Decrypt(strings.NewReader(string(data)), id); err == nil {
			t.Fatal("environment variable unexpectedly overrode built-in recipient")
		}
		previous = ciphertext
	}
	for _, invalid := range []string{"", "[broken", "scalar", "- list", "a: 1\n---\nb: 2", "a: 1\na: 2", strings.Repeat("x", maxAgentYAMLBytes+1)} {
		body["yaml"] = invalid
		w := testRequest(t, s, "POST", path, body, cookie, nil)
		requireStatus(t, w, 400)
		if strings.Contains(w.Body.String(), "ciphertext") {
			t.Fatal("invalid configuration encrypted")
		}
	}
	body["yaml"] = config
	// Caller-supplied public or private keys must not override the server pair.
	body["recipient"] = id.Recipient().String()
	requireStatus(t, testRequest(t, s, "POST", path, body, cookie, nil), 400)
	body["recipient"] = id.String()
	w := testRequest(t, s, "POST", path, body, cookie, nil)
	requireStatus(t, w, 400)
	if strings.Contains(w.Body.String(), id.String()) {
		t.Fatal("private key echoed")
	}
}
