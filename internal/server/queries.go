package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Filter struct {
	Page      int
	Size      int
	Query     string
	MachineIP string
	Type      string
	Status    string
	From      *time.Time
	To        *time.Time
}

func ParseFilter(values url.Values) (Filter, error) {
	f := Filter{Page: 1, Size: 20, Query: strings.TrimSpace(values.Get("q")), MachineIP: values.Get("machine_ip"), Type: values.Get("type"), Status: values.Get("status")}
	for _, field := range []struct {
		name   string
		target *int
		max    int
	}{{"page", &f.Page, 1000000}, {"page_size", &f.Size, 100}} {
		if v, ok := values[field.name]; ok {
			if len(v) != 1 {
				return f, fmt.Errorf("%s 参数无效", field.name)
			}
			n, err := strconv.Atoi(v[0])
			if err != nil || n < 1 || n > field.max {
				return f, fmt.Errorf("%s 必须为 1–%d", field.name, field.max)
			}
			*field.target = n
		}
	}
	if len(f.Query) > 256 {
		return f, fmt.Errorf("搜索内容过长")
	}
	if f.MachineIP != "" {
		v, e := normalizeIP(f.MachineIP)
		if e != nil {
			return f, e
		}
		f.MachineIP = v
	}
	if f.Type != "" && f.Type != "alert" && f.Type != "ssh_login" && f.Type != "scan_summary" && f.Type != "command_history" {
		return f, fmt.Errorf("事件类型无效")
	}
	if f.Status != "" && f.Status != "open" && f.Status != "resolved" {
		return f, fmt.Errorf("状态无效")
	}
	for _, field := range []struct {
		name   string
		target **time.Time
	}{{"from", &f.From}, {"to", &f.To}} {
		if v, ok := values[field.name]; ok {
			if len(v) != 1 {
				return f, fmt.Errorf("%s 时间无效", field.name)
			}
			t, err := time.Parse(time.RFC3339Nano, v[0])
			if err != nil || t.Year() < 1970 || t.Year() > 9999 {
				return f, fmt.Errorf("%s 必须为含时区的 ISO8601 时间", field.name)
			}
			*field.target = &t
		}
	}
	if f.From != nil && f.To != nil && f.From.After(*f.To) {
		return f, fmt.Errorf("开始时间不能晚于结束时间")
	}
	return f, nil
}

func like(q string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q) + "%"
}

type scanner interface{ Scan(...any) error }

const machineSelect = `SELECT m.ip,m.host,m.source_ip,m.reported_ip,m.alias,m.notes,m.first_seen,m.last_seen,m.last_event_at,m.last_summary,m.interval_seconds,m.heartbeat_interval_seconds,
 (SELECT COUNT(*) FROM events e WHERE e.machine_ip=m.ip),
 (SELECT COUNT(*) FROM events e WHERE e.machine_ip=m.ip AND e.type='alert'),
 (SELECT COUNT(*) FROM events e WHERE e.machine_ip=m.ip AND e.type='alert' AND e.status='open'),
 (SELECT COUNT(*) FROM events e WHERE e.machine_ip=m.ip AND e.type='ssh_login') FROM machines m`

func scanMachine(row scanner) (Machine, error) {
	var m Machine
	var first, last, event int64
	var summary sql.NullString
	err := row.Scan(&m.IP, &m.Host, &m.SourceIP, &m.ReportedIP, &m.Alias, &m.Notes, &first, &last, &event, &summary, &m.IntervalSeconds, &m.HeartbeatIntervalSeconds, &m.EventCount, &m.AlertCount, &m.OpenAlertCount, &m.LoginCount)
	m.FirstSeen = unstamp(first)
	m.LastSeen = unstamp(last)
	m.LastEventAt = unstamp(event)
	if summary.Valid {
		m.LastSummary = []byte(summary.String)
	}
	m.Online, m.Status, m.OfflineAfterSeconds = machinePresence(m.LastSeen, m.IntervalSeconds, m.HeartbeatIntervalSeconds, time.Now())
	return m, err
}

// Machine lists, details and the overview use exactly the same presence rule.
// Legacy agents without independent heartbeats keep their scan-based allowance.
func machinePresence(lastSeen time.Time, scanInterval, heartbeatInterval int, now time.Time) (bool, string, int) {
	seconds := max(scanInterval*3, 120)
	if heartbeatInterval > 0 {
		seconds = max(heartbeatInterval*3, 30)
	}
	online := !now.After(lastSeen.Add(time.Duration(seconds) * time.Second))
	status := "abnormal_offline"
	if online {
		status = "online"
	}
	return online, status, seconds
}

func (s *Store) Machines(ctx context.Context, f Filter) (Page[Machine], error) {
	page := Page[Machine]{Items: []Machine{}, Page: f.Page, PageSize: f.Size}
	where := ""
	args := []any{}
	if f.Query != "" {
		where = ` WHERE m.ip LIKE ? ESCAPE '\' OR m.host LIKE ? ESCAPE '\' OR m.alias LIKE ? ESCAPE '\' OR m.notes LIKE ? ESCAPE '\'`
		q := like(f.Query)
		args = append(args, q, q, q, q)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM machines m`+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	args = append(args, f.Size, (f.Page-1)*f.Size)
	rows, err := s.DB.QueryContext(ctx, machineSelect+where+` ORDER BY m.last_seen DESC,m.ip ASC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		m, err := scanMachine(rows)
		if err != nil {
			return page, err
		}
		page.Items = append(page.Items, m)
	}
	return page, rows.Err()
}

func (s *Store) Machine(ctx context.Context, ip string) (Machine, error) {
	return scanMachine(s.DB.QueryRowContext(ctx, machineSelect+` WHERE m.ip=?`, ip))
}

const eventSelect = `SELECT id,event_id,machine_ip,host,type,time,received_at,status,notes,data FROM events`

func scanEvent(row scanner) (Event, error) {
	var e Event
	var at, received int64
	var data string
	err := row.Scan(&e.ID, &e.EventID, &e.MachineIP, &e.Host, &e.Type, &at, &received, &e.Status, &e.Notes, &data)
	e.Time = unstamp(at)
	e.ReceivedAt = unstamp(received)
	e.Data = []byte(data)
	return e, err
}

func (s *Store) Events(ctx context.Context, f Filter) (Page[Event], error) {
	page := Page[Event]{Items: []Event{}, Page: f.Page, PageSize: f.Size}
	where := []string{}
	args := []any{}
	for _, filter := range []struct{ key, value string }{{"machine_ip", f.MachineIP}, {"type", f.Type}, {"status", f.Status}} {
		if filter.value != "" {
			where = append(where, filter.key+"=?")
			args = append(args, filter.value)
		}
	}
	if f.From != nil {
		where = append(where, "time>=?")
		args = append(args, stamp(*f.From))
	}
	if f.To != nil {
		where = append(where, "time<=?")
		args = append(args, stamp(*f.To))
	}
	if f.Query != "" {
		where = append(where, `(machine_ip LIKE ? ESCAPE '\' OR host LIKE ? ESCAPE '\' OR data LIKE ? ESCAPE '\' OR notes LIKE ? ESCAPE '\')`)
		q := like(f.Query)
		args = append(args, q, q, q, q)
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`+clause, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	args = append(args, f.Size, (f.Page-1)*f.Size)
	rows, err := s.DB.QueryContext(ctx, eventSelect+clause+` ORDER BY time DESC,id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return page, err
		}
		page.Items = append(page.Items, event)
	}
	return page, rows.Err()
}

func (s *Store) Event(ctx context.Context, id int64) (Event, error) {
	return scanEvent(s.DB.QueryRowContext(ctx, eventSelect+` WHERE id=?`, id))
}

const webhookSelect = `SELECT w.id,w.name,w.url,w.format,w.enabled,w.created_at,w.updated_at,w.last_error,w.last_success_at,
 (SELECT COUNT(*) FROM outbox o WHERE o.webhook_id=w.id AND o.delivered_at IS NULL) FROM webhooks w`

func scanWebhook(row scanner) (Webhook, error) {
	var w Webhook
	var created, updated int64
	var success sql.NullInt64
	err := row.Scan(&w.ID, &w.Name, &w.URL, &w.Format, &w.Enabled, &created, &updated, &w.LastError, &success, &w.PendingCount)
	w.Format = webhookFormat(w)
	w.CreatedAt = unstamp(created)
	w.UpdatedAt = unstamp(updated)
	if success.Valid {
		t := unstamp(success.Int64)
		w.LastSuccessAt = &t
	}
	return w, err
}

func (s *Store) Webhook(ctx context.Context, id int64) (Webhook, error) {
	return scanWebhook(s.DB.QueryRowContext(ctx, webhookSelect+` WHERE w.id=?`, id))
}
func (s *Store) Webhooks(ctx context.Context) ([]Webhook, error) {
	items := []Webhook{}
	rows, err := s.DB.QueryContext(ctx, webhookSelect+` ORDER BY w.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		w, e := scanWebhook(rows)
		if e != nil {
			return nil, e
		}
		items = append(items, w)
	}
	return items, rows.Err()
}
