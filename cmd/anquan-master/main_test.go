package main

import (
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
