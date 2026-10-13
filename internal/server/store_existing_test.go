package server

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenExistingRejectsOtherSQLiteWithoutMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anquan.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE unrelated (value TEXT); INSERT INTO unrelated(value) VALUES('retain'); PRAGMA user_version=99;`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if store, err := OpenExisting(dir); err == nil {
		store.Close()
		t.Fatal("local template command accepted an unrelated SQLite database")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("rejected database was migrated or had journal mode changed: %v", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); !os.IsNotExist(err) {
			t.Fatalf("rejected database created %s: %v", suffix, err)
		}
	}
}
