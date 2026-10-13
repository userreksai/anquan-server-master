package server

import "testing"

func TestPublicOriginValidationAndExplicitMatching(t *testing.T) {
	s := &Server{}
	for _, value := range []string{
		"https://prodsafety.ops.tw", "https://prodsafety.ops.tw:8443",
		"http://127.0.0.1:10111", "http://localhost:10111", "https://[::1]:8443",
	} {
		if err := s.SetPublicOrigin(value); err != nil {
			t.Fatalf("valid public origin rejected %q: %v", value, err)
		}
		if !s.trustedOrigin(value, "127.0.0.1:10110") {
			t.Fatalf("configured origin was rejected behind local proxy: %s", value)
		}
	}
	const expected = "https://prodsafety.ops.tw"
	if err := s.SetPublicOrigin(expected); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		" ", "null", "prodsafety.ops.tw", "//prodsafety.ops.tw", "ftp://prodsafety.ops.tw",
		"https://prodsafety.ops.tw/", "https://prodsafety.ops.tw/api", "https://prodsafety.ops.tw?",
		"https://prodsafety.ops.tw?a=1", "https://prodsafety.ops.tw#", "https://prodsafety.ops.tw#fragment",
		"https://admin@prodsafety.ops.tw", "https://*.ops.tw", "https://", "https://-invalid.example",
		"https://prodsafety.ops.tw:0", "https://prodsafety.ops.tw:65536", "https://prodsafety.ops.tw:",
		"https://prodsafety.ops.tw:abc", "https://prodsafety.ops.tw,https://other.test",
		"https://[example.com]", "https://[127.0.0.1]", "https://::", "https://::1", "https://2001:db8::1",
	} {
		if err := s.SetPublicOrigin(value); err == nil {
			t.Fatalf("invalid public origin accepted: %q", value)
		}
		if s.publicOrigin.String() != expected {
			t.Fatal("invalid configuration replaced the previous origin")
		}
	}
	for _, value := range []string{"http://prodsafety.ops.tw", "https://prodsafety.ops.tw:8443", "https://other.test", "http://127.0.0.1:10110", "https://prodsafety.ops.tw?", "https://prodsafety.ops.tw#"} {
		if s.trustedOrigin(value, "prodsafety.ops.tw") {
			t.Fatalf("Host-based fallback bypassed configured origin: %s", value)
		}
	}
	if !s.trustedOrigin("https://PRODSAFETY.OPS.TW", "127.0.0.1:10110") {
		t.Fatal("DNS host comparison must be case-insensitive")
	}
	if err := s.SetPublicOrigin(""); err != nil {
		t.Fatal(err)
	}
	if !s.trustedOrigin("http://security.test", "security.test") || s.trustedOrigin("http://security.test", "other.test") {
		t.Fatal("empty configuration did not restore legacy Host validation")
	}
}
