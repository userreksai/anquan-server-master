package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

// Only the meaningful state of abnormal components determines history. Queue
// counts, inventory, application timestamps and report metadata remain in the
// latest snapshot without producing a new history row every polling interval.
type componentState struct {
	Name       string          `json:"name"`
	Enabled    bool            `json:"enabled"`
	Installed  bool            `json:"installed"`
	Running    bool            `json:"running"`
	State      string          `json:"state"`
	Version    string          `json:"version"`
	ConfigHash string          `json:"config_hash"`
	PolicyMode string          `json:"policy_mode,omitempty"`
	Error      string          `json:"error"`
	Message    string          `json:"message"`
	Checks     json.RawMessage `json:"checks,omitempty"`
}

func (c componentState) abnormal() bool {
	if !c.Enabled {
		return false
	}
	if strings.TrimSpace(c.Error) != "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(c.State)) {
	case "error", "failed", "install_failed", "config_failed", "degraded", "unsupported", "drift", "audit_drift", "stopped", "missing", "not_installed":
		return true
	default:
		return false
	}
}

func componentAnomalyKey(data json.RawMessage) (string, error) {
	var report struct {
		Components []componentState `json:"components"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return "", err
	}
	abnormal := []componentState{}
	for _, component := range report.Components {
		if !component.abnormal() {
			continue
		}
		component.State = strings.ToLower(strings.TrimSpace(component.State))
		component.Error = strings.TrimSpace(component.Error)
		component.Message = strings.TrimSpace(component.Message)
		if len(component.Checks) > 0 {
			// Policy checks are sets; a different collection order is not a new
			// incident. Preserve all check contents, including diagnostic evidence.
			var checks []json.RawMessage
			if json.Unmarshal(component.Checks, &checks) == nil {
				for i, check := range checks {
					var value any
					if err := json.Unmarshal(check, &value); err != nil {
						return "", err
					}
					checks[i], _ = json.Marshal(value)
				}
				slices.SortFunc(checks, func(a, b json.RawMessage) int { return strings.Compare(string(a), string(b)) })
				component.Checks, _ = json.Marshal(checks)
			} else {
				var value any
				if err := json.Unmarshal(component.Checks, &value); err != nil {
					return "", err
				}
				component.Checks, _ = json.Marshal(value)
			}
		}
		abnormal = append(abnormal, component)
	}
	if len(abnormal) == 0 {
		return "", nil
	}
	slices.SortFunc(abnormal, func(a, b componentState) int { return strings.Compare(a.Name, b.Name) })
	key, err := json.Marshal(abnormal)
	return string(key), err
}

func storeComponentStatus(ctx context.Context, tx *sql.Tx, e Envelope, ip string, now int64) (bool, error) {
	var previousAt int64
	var previous string
	err := tx.QueryRowContext(ctx, `SELECT time,data FROM machine_security_status WHERE machine_ip=?`, ip).Scan(&previousAt, &previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err == nil && stamp(e.Time) < previousAt {
		return false, nil
	}
	// A retry of an already retained event must not mutate the latest snapshot
	// or create a false recovery, including different payloads reusing that ID.
	var duplicate bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE machine_ip=? AND event_id=?)`, ip, e.EventID).Scan(&duplicate); err != nil {
		return false, err
	}
	if duplicate {
		return false, nil
	}
	currentKey, err := componentAnomalyKey(e.Data)
	if err != nil {
		return false, err
	}
	previousKey := ""
	if previous != "" {
		previousKey, err = componentAnomalyKey(json.RawMessage(previous))
		if err != nil {
			return false, err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO machine_security_status(machine_ip,host,time,received_at,data) VALUES(?,?,?,?,?)
ON CONFLICT(machine_ip) DO UPDATE SET host=excluded.host,time=excluded.time,received_at=excluded.received_at,data=excluded.data
WHERE excluded.time>=machine_security_status.time`, ip, e.Host, stamp(e.Time), now, string(e.Data))
	if err != nil || currentKey == previousKey {
		return false, err
	}
	// snapshot_only is an Agent display hint, never authority to suppress an
	// actual abnormal state. A first abnormal state, changed anomaly or recovery
	// is retained once; stable normal and stable abnormal reports add no history.
	result, err := tx.ExecContext(ctx, `INSERT INTO events(event_id,machine_ip,host,type,time,received_at,data) VALUES(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`, e.EventID, ip, e.Host, e.Type, stamp(e.Time), now, string(e.Data))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}
