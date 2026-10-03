package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"
)

const MaxDatagram = 60000

func normalizeIP(value string) (string, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return "", fmt.Errorf("invalid IP address")
	}
	return ip.Unmap().String(), nil
}

func (s *Store) Ingest(ctx context.Context, packet []byte, source string) (bool, error) {
	if len(packet) == 0 || len(packet) > MaxDatagram {
		return false, fmt.Errorf("invalid datagram length")
	}
	var e Envelope
	d := json.NewDecoder(bytes.NewReader(packet))
	if err := d.Decode(&e); err != nil {
		return false, fmt.Errorf("invalid JSON: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return false, fmt.Errorf("trailing JSON content")
	}
	if e.Version != 1 || strings.TrimSpace(e.EventID) == "" || len(e.EventID) > 256 || strings.TrimSpace(e.Host) == "" || len(e.Host) > 255 || e.Time.IsZero() || e.Time.Year() < 1970 || e.Time.Year() > 9999 {
		return false, fmt.Errorf("invalid envelope")
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(e.Data, &object) != nil || object == nil {
		return false, fmt.Errorf("data must be an object")
	}
	sourceIP, err := normalizeIP(source)
	if err != nil {
		return false, err
	}
	ip, reported := sourceIP, ""
	if e.IP != "" {
		reported, err = normalizeIP(e.IP)
		if err != nil {
			return false, err
		}
		ip = reported
	}
	eventTime := e.Time
	interval := 0
	heartbeatInterval := 0
	var loginKey any
	switch e.Type {
	case "heartbeat":
		var heartbeat struct {
			Interval int `json:"interval_seconds"`
		}
		if json.Unmarshal(e.Data, &heartbeat) != nil || heartbeat.Interval < 1 || heartbeat.Interval > 86400 {
			return false, fmt.Errorf("invalid heartbeat")
		}
		heartbeatInterval = heartbeat.Interval
	case "scan_summary":
		var summary struct {
			Success   *bool      `json:"collection_success"`
			Alerts    int        `json:"alerts"`
			Errors    int        `json:"errors"`
			Files     int        `json:"files"`
			Processes int        `json:"processes"`
			Interval  int        `json:"interval_seconds"`
			Finished  *time.Time `json:"finished_at"`
		}
		if json.Unmarshal(e.Data, &summary) != nil || summary.Success == nil || summary.Alerts < 0 || summary.Errors < 0 || summary.Files < 0 || summary.Processes < 0 || summary.Interval < 0 || summary.Interval > 604800 {
			return false, fmt.Errorf("invalid scan summary")
		}
		if summary.Interval > 0 {
			interval = summary.Interval
		}
	case "alert":
		var alert struct {
			Module  string `json:"module"`
			Kind    string `json:"kind"`
			Target  string `json:"target"`
			Message string `json:"message"`
			Before  string `json:"before"`
			After   string `json:"after"`
		}
		if json.Unmarshal(e.Data, &alert) != nil || strings.TrimSpace(alert.Kind) == "" || strings.TrimSpace(alert.Message) == "" {
			return false, fmt.Errorf("invalid alert")
		}
	case "ssh_login":
		var login struct {
			ID        string    `json:"id"`
			SourceIP  string    `json:"source_ip"`
			LoginTime time.Time `json:"login_time"`
			User      string    `json:"user"`
			Terminal  string    `json:"terminal"`
			Method    string    `json:"method"`
		}
		if json.Unmarshal(e.Data, &login) != nil || login.LoginTime.IsZero() || login.LoginTime.Year() < 1970 || login.LoginTime.Year() > 9999 || login.User == "" {
			return false, fmt.Errorf("invalid login record")
		}
		if login.SourceIP != "" {
			login.SourceIP, err = normalizeIP(login.SourceIP)
			if err != nil {
				return false, fmt.Errorf("invalid login source IP")
			}
		}
		eventTime = login.LoginTime
		identity := login.ID
		if identity == "" {
			identity = login.SourceIP + "|" + login.LoginTime.UTC().Format(time.RFC3339Nano) + "|" + login.User + "|" + login.Terminal + "|" + login.Method
		}
		hash := sha256.Sum256([]byte(identity))
		loginKey = hex.EncodeToString(hash[:])
	default:
		return false, fmt.Errorf("unsupported event type")
	}
	now := stamp(time.Now())
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO machines(ip,host,source_ip,reported_ip,first_seen,last_seen,last_event_at,last_agent_at)
 VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET
 host=CASE WHEN excluded.last_agent_at>=machines.last_agent_at THEN excluded.host ELSE machines.host END,
 source_ip=CASE WHEN excluded.last_agent_at>=machines.last_agent_at THEN excluded.source_ip ELSE machines.source_ip END,
 reported_ip=CASE WHEN excluded.last_agent_at>=machines.last_agent_at THEN excluded.reported_ip ELSE machines.reported_ip END,
 last_seen=MAX(machines.last_seen,excluded.last_seen),last_event_at=MAX(machines.last_event_at,excluded.last_event_at),
 last_agent_at=MAX(machines.last_agent_at,excluded.last_agent_at)`, ip, e.Host, sourceIP, reported, now, now, stamp(eventTime), stamp(e.Time))
	if err != nil {
		return false, err
	}
	if e.Type == "heartbeat" {
		// Independent heartbeats update automatic registration/presence only;
		// they never create history events or notification jobs. Keep their own
		// ordering clock so delayed scans cannot roll heartbeat settings back.
		_, err = tx.ExecContext(ctx, `UPDATE machines SET heartbeat_interval_seconds=?,last_heartbeat_at=? WHERE ip=? AND last_heartbeat_at<=?`, heartbeatInterval, stamp(e.Time), ip, stamp(e.Time))
		if err != nil {
			return false, err
		}
		return true, tx.Commit()
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO events(event_id,machine_ip,host,type,time,received_at,data,login_key) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`, e.EventID, ip, e.Host, e.Type, stamp(eventTime), now, string(e.Data), loginKey)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, tx.Commit()
	}
	if e.Type == "scan_summary" {
		_, err = tx.ExecContext(ctx, `UPDATE machines SET last_summary=?,last_summary_at=?,interval_seconds=CASE WHEN ?>0 THEN ? ELSE interval_seconds END WHERE ip=? AND last_summary_at<=?`, string(e.Data), stamp(e.Time), interval, interval, ip, stamp(e.Time))
		if err != nil {
			return false, err
		}
	}
	if e.Type == "alert" {
		id, e := result.LastInsertId()
		if e != nil {
			return false, e
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO outbox(webhook_id,event_id,next_attempt_at) SELECT id,?,? FROM webhooks WHERE enabled=1`, id, now); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

// ServeUDP accepts versioned JSON messages. Closing conn stops the receiver.
func (s *Store) ServeUDP(ctx context.Context, conn *net.UDPConn, logger *slog.Logger) error {
	buf := make([]byte, 65535)
	var rejected uint64
	for {
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, remote, err := conn.ReadFromUDP(buf)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		if _, err = s.Ingest(ctx, buf[:n], remote.IP.String()); err != nil {
			rejected++
			// Bound log volume from malformed datagrams without echoing attacker payloads.
			if rejected == 1 || rejected%100 == 0 {
				logger.Warn("UDP event rejected", "rejected_total", rejected, "error", err)
			}
		}
	}
}
