package server

import (
	"encoding/json"
	"time"
)

type Envelope struct {
	Version int             `json:"version"`
	EventID string          `json:"event_id"`
	IP      string          `json:"ip,omitempty"`
	Host    string          `json:"host"`
	Time    time.Time       `json:"time"`
	Type    string          `json:"type"`
	Data    json.RawMessage `json:"data"`
}

type Machine struct {
	IP                       string          `json:"ip"`
	Host                     string          `json:"host"`
	SourceIP                 string          `json:"source_ip"`
	ReportedIP               string          `json:"reported_ip"`
	Alias                    string          `json:"alias"`
	Notes                    string          `json:"notes"`
	FirstSeen                time.Time       `json:"first_seen"`
	LastSeen                 time.Time       `json:"last_seen"`
	LastEventAt              time.Time       `json:"last_event_at"`
	LastSummary              json.RawMessage `json:"last_summary"`
	IntervalSeconds          int             `json:"interval_seconds"`
	HeartbeatIntervalSeconds int             `json:"heartbeat_interval_seconds"`
	OfflineAfterSeconds      int             `json:"offline_after_seconds"`
	Status                   string          `json:"status"`
	EventCount               int             `json:"event_count"`
	AlertCount               int             `json:"alert_count"`
	OpenAlertCount           int             `json:"open_alert_count"`
	LoginCount               int             `json:"login_count"`
	Online                   bool            `json:"online"`
}

type Event struct {
	ID         int64           `json:"id"`
	EventID    string          `json:"event_id"`
	MachineIP  string          `json:"machine_ip"`
	Host       string          `json:"host"`
	Type       string          `json:"type"`
	Time       time.Time       `json:"time"`
	ReceivedAt time.Time       `json:"received_at"`
	Status     string          `json:"status"`
	Notes      string          `json:"notes"`
	Data       json.RawMessage `json:"data"`
}

type Webhook struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	URL           string     `json:"url"`
	Format        string     `json:"format"`
	Enabled       bool       `json:"enabled"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastError     string     `json:"last_error"`
	LastSuccessAt *time.Time `json:"last_success_at"`
	PendingCount  int        `json:"pending_count"`
}

type Overview struct {
	Machines             int `json:"machines"`
	OnlineMachines       int `json:"online_machines"`
	Events               int `json:"events"`
	Alerts               int `json:"alerts"`
	OpenAlerts           int `json:"open_alerts"`
	SSHLogins            int `json:"ssh_logins"`
	PendingNotifications int `json:"pending_notifications"`
}

type Page[T any] struct {
	Items    []T `json:"items"`
	Total    int `json:"total"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

func stamp(t time.Time) int64   { return t.UTC().UnixMilli() }
func unstamp(t int64) time.Time { return time.UnixMilli(t).UTC() }
