package server

import "database/sql"

// SQLite cannot alter a CHECK constraint. Rebuild events and its referencing
// outbox in one transaction, retaining IDs, notes, delivery attempts and the
// AUTOINCREMENT high-water marks (including IDs of deleted records).
func migrateCommandEvents(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TEMP TABLE command_migration_outbox AS SELECT * FROM outbox;
CREATE TEMP TABLE command_migration_sequences AS SELECT name,seq FROM sqlite_sequence WHERE name IN ('events','outbox');
DROP TABLE outbox;
CREATE TABLE events_commands (
 id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL, machine_ip TEXT NOT NULL REFERENCES machines(ip) ON DELETE CASCADE,
 host TEXT NOT NULL, type TEXT NOT NULL CHECK(type IN ('alert','ssh_login','scan_summary','command_history')),
 time INTEGER NOT NULL, received_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved')),
 notes TEXT NOT NULL DEFAULT '', data TEXT NOT NULL, login_key TEXT, command_key TEXT, UNIQUE(machine_ip,event_id)
);
INSERT INTO events_commands(id,event_id,machine_ip,host,type,time,received_at,status,notes,data,login_key)
 SELECT id,event_id,machine_ip,host,type,time,received_at,status,notes,data,login_key FROM events;
DROP TABLE events;
ALTER TABLE events_commands RENAME TO events;
INSERT INTO sqlite_sequence(name,seq) SELECT 'events',0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='events');
UPDATE sqlite_sequence SET seq=MAX(seq,COALESCE((SELECT seq FROM command_migration_sequences WHERE name='events'),0)) WHERE name='events';
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
INSERT INTO outbox SELECT * FROM command_migration_outbox;
INSERT INTO sqlite_sequence(name,seq) SELECT 'outbox',0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name='outbox');
UPDATE sqlite_sequence SET seq=MAX(seq,COALESCE((SELECT seq FROM command_migration_sequences WHERE name='outbox'),0)) WHERE name='outbox';
CREATE INDEX outbox_due ON outbox(delivered_at,next_attempt_at);
DROP TABLE command_migration_outbox;
DROP TABLE command_migration_sequences;
PRAGMA user_version=3;
`)
	return err
}
