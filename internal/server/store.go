package server

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const DefaultPassword = "admin1818."

type Store struct{ DB *sql.DB }

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	path := filepath.Join(dataDir, "anquan.db")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// One writer connection avoids SQLITE_BUSY races; WAL allows the reset CLI to coexist.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{DB: db}
	if _, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;`); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate() error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var schemaVersion int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&schemaVersion); err != nil {
		return err
	}
	if schemaVersion > 5 {
		return fmt.Errorf("unsupported database schema version %d", schemaVersion)
	}
	_, err = tx.Exec(`
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS machines (
 ip TEXT PRIMARY KEY, host TEXT NOT NULL, source_ip TEXT NOT NULL, reported_ip TEXT NOT NULL DEFAULT '',
 alias TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
 last_event_at INTEGER NOT NULL, last_agent_at INTEGER NOT NULL, last_summary_at INTEGER NOT NULL DEFAULT 0,
 last_summary TEXT, interval_seconds INTEGER NOT NULL DEFAULT 300
);
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL, machine_ip TEXT NOT NULL REFERENCES machines(ip) ON DELETE CASCADE,
 host TEXT NOT NULL, type TEXT NOT NULL CHECK(type IN ('alert','ssh_login','scan_summary')),
 time INTEGER NOT NULL, received_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved')),
 notes TEXT NOT NULL DEFAULT '', data TEXT NOT NULL, login_key TEXT, UNIQUE(machine_ip,event_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS event_login_identity ON events(machine_ip,login_key) WHERE login_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_machine_time ON events(machine_ip,time DESC,id DESC);
CREATE INDEX IF NOT EXISTS events_time ON events(time DESC,id DESC);
CREATE INDEX IF NOT EXISTS events_type_time ON events(type,time DESC,id DESC);
CREATE TABLE IF NOT EXISTS webhooks (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL,
 format TEXT NOT NULL CHECK(format IN ('feishu','wecom','generic')), enabled INTEGER NOT NULL DEFAULT 1,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_error TEXT NOT NULL DEFAULT '', last_success_at INTEGER
);
CREATE TABLE IF NOT EXISTS outbox (
 id INTEGER PRIMARY KEY AUTOINCREMENT, webhook_id INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
 event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, delivered_at INTEGER,
 last_error TEXT NOT NULL DEFAULT '', UNIQUE(webhook_id,event_id)
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(delivered_at,next_attempt_at);
`)
	if err != nil {
		return err
	}
	if schemaVersion < 2 {
		// Version 1 databases retain every machine, event, password, session and
		// queued notification. Fresh databases take the same migration path.
		if _, err = tx.Exec(`ALTER TABLE machines ADD COLUMN heartbeat_interval_seconds INTEGER NOT NULL DEFAULT 0;
ALTER TABLE machines ADD COLUMN last_heartbeat_at INTEGER NOT NULL DEFAULT 0;
PRAGMA user_version=2;`); err != nil {
			return err
		}
	}
	if schemaVersion < 3 {
		if err := migrateCommandEvents(tx); err != nil {
			return err
		}
	}
	if schemaVersion < 4 {
		// Keep incident state separate from events: deleting an alert must not
		// notify again while the same machine remains continuously offline.
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS machine_offline_state (
 machine_ip TEXT PRIMARY KEY REFERENCES machines(ip) ON DELETE CASCADE,
 event_id TEXT NOT NULL
);
PRAGMA user_version=4;`); err != nil {
			return err
		}
	}
	if schemaVersion < 5 {
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS agent_config_template (
 id INTEGER PRIMARY KEY CHECK(id=1), yaml TEXT NOT NULL
);
PRAGMA user_version=5;`); err != nil {
			return err
		}
	}
	var count int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM users WHERE username='admin'`).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		hash, e := bcrypt.GenerateFromPassword([]byte(DefaultPassword), 12)
		if e != nil {
			return e
		}
		if _, err = tx.Exec(`INSERT INTO users(username,password_hash) VALUES('admin',?)`, string(hash)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func ValidatePassword(password string) error {
	if len(password) < 8 || len(password) > 72 {
		return fmt.Errorf("密码长度必须为 8–72 字节")
	}
	return nil
}

func (s *Store) ResetAdmin(ctx context.Context, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE username='admin'`, string(hash)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE username='admin'`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Overview(ctx context.Context) (Overview, error) {
	var o Overview
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(type='alert'),0), COALESCE(SUM(type='alert' AND status='open'),0),
 COALESCE(SUM(type='ssh_login'),0), (SELECT COUNT(*) FROM outbox WHERE delivered_at IS NULL) FROM events`).
		Scan(&o.Events, &o.Alerts, &o.OpenAlerts, &o.SSHLogins, &o.PendingNotifications)
	if err != nil {
		return o, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT last_seen,interval_seconds,heartbeat_interval_seconds FROM machines`)
	if err != nil {
		return o, err
	}
	defer rows.Close()
	now := time.Now()
	for rows.Next() {
		var lastSeen int64
		var interval, heartbeat int
		if err := rows.Scan(&lastSeen, &interval, &heartbeat); err != nil {
			return o, err
		}
		online, _, _ := machinePresence(unstamp(lastSeen), interval, heartbeat, now)
		o.Machines++
		if online {
			o.OnlineMachines++
		}
	}
	return o, rows.Err()
}
