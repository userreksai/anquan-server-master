package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/userreksai/anquan-server-master/internal/server"
	"golang.org/x/crypto/bcrypt"
)

func withPasswordInput(t *testing.T, value string, action func() error) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "password-input")
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	previous := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = previous }()
	return action()
}

func TestResetAdminCLIRequiresExistingDBAndValidStdin(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := reset([]string{"--data-dir", dir}); err == nil {
		t.Fatal("password without stdin switch accepted")
	}
	if err := withPasswordInput(t, "replacement-pass\n", func() error { return reset([]string{"--data-dir", dir, "--password-stdin"}) }); err == nil {
		t.Fatal("reset silently initialized nonexistent database")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("failed reset created a directory: %v", err)
	}
	store, err := server.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`INSERT INTO sessions(token_hash,username,expires_at) VALUES('old-session','admin',?)`, time.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"short\n", "first-line\nsecond-line\n", strings.Repeat("x", 73), strings.Repeat("x", 1025)} {
		if err := withPasswordInput(t, invalid, func() error { return run([]string{"reset-admin", "--data-dir", dir, "--password-stdin"}) }); err == nil {
			t.Fatalf("invalid stdin accepted (%d bytes)", len(invalid))
		}
	}
	var original string
	if err := store.DB.QueryRow(`SELECT password_hash FROM users WHERE username='admin'`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(original), []byte(server.DefaultPassword)); err != nil {
		t.Fatal("invalid input changed password")
	}
	if err := withPasswordInput(t, "reset-password-123\r\n", func() error { return run([]string{"reset-admin", "--data-dir", dir, "--password-stdin"}) }); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := server.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var hash string
	var sessions int
	if err := reopened.DB.QueryRow(`SELECT password_hash FROM users WHERE username='admin'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("reset-password-123")); err != nil {
		t.Fatal("CLI password reset was not durable")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(server.DefaultPassword)); err == nil {
		t.Fatal("default password still works after reset")
	}
	if err := reopened.DB.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("reset left sessions active: %d %v", sessions, err)
	}
}

func TestCLIRejectsUnexpectedArgumentsAndInvalidEnvironment(t *testing.T) {
	t.Setenv("ANQUAN_SECURE_COOKIE", "false")
	for _, args := range [][]string{{"serve", "extra"}, {"reset-admin", "extra"}, {"--not-a-flag"}} {
		if err := run(args); err == nil {
			t.Fatalf("arguments accepted: %v", args)
		}
	}
	t.Setenv("ANQUAN_SECURE_COOKIE", "not-a-bool")
	if err := run([]string{}); err == nil {
		t.Fatal("invalid boolean environment accepted")
	}
}

func TestTCPListenFailureAbortsMasterStartup(t *testing.T) {
	t.Setenv("ANQUAN_SECURE_COOKIE", "false")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// The env value is also covered here; --tcp explicitly overrides it below.
	t.Setenv("ANQUAN_TCP_ADDR", listener.Addr().String())
	for _, args := range [][]string{
		{"--data-dir", t.TempDir(), "--http", "127.0.0.1:0", "--udp", "127.0.0.1:0"},
		{"--data-dir", t.TempDir(), "--http", "127.0.0.1:0", "--udp", "127.0.0.1:0", "--tcp", listener.Addr().String()},
	} {
		if err := run(args); err == nil || !strings.Contains(err.Error(), "listen agent configuration TCP") {
			t.Fatalf("occupied config port did not abort startup: %v", err)
		}
	}
}

func TestInvalidPublicOriginAbortsBeforeDatabaseCreation(t *testing.T) {
	t.Setenv("ANQUAN_SECURE_COOKIE", "false")
	for _, useEnvironment := range []bool{false, true} {
		dir := filepath.Join(t.TempDir(), "not-created")
		args := []string{"--data-dir", dir, "--http", "invalid-listen-address"}
		if useEnvironment {
			t.Setenv("ANQUAN_PUBLIC_ORIGIN", "https://*.ops.tw")
		} else {
			t.Setenv("ANQUAN_PUBLIC_ORIGIN", "")
			args = append(args, "--public-origin", "https://prodsafety.ops.tw/api")
		}
		if err := run(args); err == nil || !strings.Contains(err.Error(), "--public-origin/ANQUAN_PUBLIC_ORIGIN") {
			t.Fatalf("invalid public origin was not rejected before startup: %v", err)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("invalid public origin created the database directory: %v", err)
		}
	}
}

func TestPublicOriginFlagOverridesEnvironment(t *testing.T) {
	t.Setenv("ANQUAN_SECURE_COOKIE", "false")
	t.Setenv("ANQUAN_PUBLIC_ORIGIN", "https://*.ops.tw")
	dir := filepath.Join(t.TempDir(), "data")
	err := run([]string{"--data-dir", dir, "--public-origin", "https://prodsafety.ops.tw", "--http", "invalid-listen-address", "--udp", "127.0.0.1:0"})
	if err == nil || strings.Contains(err.Error(), "--public-origin/ANQUAN_PUBLIC_ORIGIN") {
		t.Fatalf("explicit public origin did not override environment: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "anquan.db")); err != nil {
		t.Fatalf("valid explicit origin did not reach local database startup: %v", err)
	}
}
