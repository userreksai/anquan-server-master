package server

import "database/sql"

// Extend the event CHECK constraint without losing existing IDs, delivery jobs,
// command identities, or AUTOINCREMENT high-water marks.
func migrateSecurityEvents(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TEMP TABLE security_migration_outbox AS SELECT * FROM outbox;
CREATE TEMP TABLE security_migration_sequences AS SELECT name,seq FROM sqlite_sequence WHERE name IN ('events','outbox');
DROP TABLE outbox;
CREATE TABLE events_security (
 id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL, machine_ip TEXT NOT NULL REFERENCES machines(ip) ON DELETE CASCADE,
 host TEXT NOT NULL, type TEXT NOT NULL CHECK(type IN ('alert','ssh_login','scan_summary','command_history','security_event','component_status')),
 time INTEGER NOT NULL, received_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved')),
 notes TEXT NOT NULL DEFAULT '', data TEXT NOT NULL, login_key TEXT, command_key TEXT, UNIQUE(machine_ip,event_id)
);
INSERT INTO events_security SELECT * FROM events;
DROP TABLE events;
ALTER TABLE events_security RENAME TO events;
INSERT INTO sqlite_sequence(name,seq) SELECT 'events',0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='events');
UPDATE sqlite_sequence SET seq=MAX(seq,COALESCE((SELECT seq FROM security_migration_sequences WHERE name='events'),0)) WHERE name='events';
CREATE UNIQUE INDEX event_login_identity ON events(machine_ip,login_key) WHERE login_key IS NOT NULL;
CREATE UNIQUE INDEX event_command_identity ON events(machine_ip,command_key) WHERE command_key IS NOT NULL;
CREATE INDEX events_machine_time ON events(machine_ip,time DESC,id DESC);
CREATE INDEX events_time ON events(time DESC,id DESC);
CREATE INDEX events_type_time ON events(type,time DESC,id DESC);
CREATE TABLE outbox (
 id INTEGER PRIMARY KEY AUTOINCREMENT, webhook_id INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
 event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, delivered_at INTEGER,
 last_error TEXT NOT NULL DEFAULT '', UNIQUE(webhook_id,event_id)
);
INSERT INTO outbox SELECT * FROM security_migration_outbox;
INSERT INTO sqlite_sequence(name,seq) SELECT 'outbox',0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='outbox');
UPDATE sqlite_sequence SET seq=MAX(seq,COALESCE((SELECT seq FROM security_migration_sequences WHERE name='outbox'),0)) WHERE name='outbox';
CREATE INDEX outbox_due ON outbox(delivered_at,next_attempt_at);
DROP TABLE security_migration_outbox;
DROP TABLE security_migration_sequences;
CREATE TABLE IF NOT EXISTS machine_security_status (
 machine_ip TEXT PRIMARY KEY REFERENCES machines(ip) ON DELETE CASCADE,
 host TEXT NOT NULL, time INTEGER NOT NULL, received_at INTEGER NOT NULL, data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sudo_sessions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, machine_ip TEXT NOT NULL REFERENCES machines(ip) ON DELETE CASCADE,
 host TEXT NOT NULL, session_key TEXT NOT NULL, generation TEXT NOT NULL, time INTEGER NOT NULL, received_at INTEGER NOT NULL,
 UNIQUE(machine_ip,session_key,generation)
);
CREATE INDEX IF NOT EXISTS sudo_sessions_machine_time ON sudo_sessions(machine_ip,time DESC,id DESC);
CREATE TABLE IF NOT EXISTS sudo_session_files (
 session_id INTEGER NOT NULL REFERENCES sudo_sessions(id) ON DELETE CASCADE, name TEXT NOT NULL,
 total_size INTEGER NOT NULL, complete_requested INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(session_id,name)
);
CREATE TABLE IF NOT EXISTS sudo_io_chunks (
 session_id INTEGER NOT NULL, name TEXT NOT NULL, offset INTEGER NOT NULL, data BLOB NOT NULL,
 machine_ip TEXT NOT NULL, event_id TEXT NOT NULL, PRIMARY KEY(session_id,name,offset), UNIQUE(machine_ip,event_id),
 FOREIGN KEY(session_id,name) REFERENCES sudo_session_files(session_id,name) ON DELETE CASCADE
);
PRAGMA user_version=7;
`)
	return err
}
