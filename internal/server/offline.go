package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type offlineAlert struct {
	Module              string    `json:"module"`
	Kind                string    `json:"kind"`
	Target              string    `json:"target"`
	Message             string    `json:"message"`
	Alias               string    `json:"alias,omitempty"`
	LastSeen            time.Time `json:"last_seen"`
	OfflineSince        time.Time `json:"offline_since"`
	DetectedAt          time.Time `json:"detected_at"`
	OfflineAfterSeconds int       `json:"offline_after_seconds"`
}

// DetectOffline creates one durable incident per continuous outage. It never
// changes last_seen, so a master-generated alert cannot make a machine online.
func (s *Store) DetectOffline(ctx context.Context, now time.Time) (int, error) {
	now = unstamp(stamp(now))
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	// Match machinePresence, including its strict greater-than boundary. Bound
	// each transaction so a large outage does not monopolize the ingest writer.
	rows, err := tx.QueryContext(ctx, `SELECT m.ip,m.host,m.alias,m.last_seen,m.interval_seconds,m.heartbeat_interval_seconds
 FROM machines m WHERE NOT EXISTS (SELECT 1 FROM machine_offline_state o WHERE o.machine_ip=m.ip)
 AND m.last_seen < ? - 1000 * CASE WHEN m.heartbeat_interval_seconds>0 THEN MAX(m.heartbeat_interval_seconds*3,30) ELSE MAX(m.interval_seconds*3,120) END
 ORDER BY m.last_seen,m.ip LIMIT 256`, stamp(now))
	if err != nil {
		return 0, err
	}
	type candidate struct {
		ip, host, alias string
		lastSeen        int64
		scan, heartbeat int
	}
	var candidates []candidate
	for rows.Next() {
		var m candidate
		if err := rows.Scan(&m.ip, &m.host, &m.alias, &m.lastSeen, &m.scan, &m.heartbeat); err != nil {
			rows.Close()
			return 0, err
		}
		candidates = append(candidates, m)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	created := 0
	for _, m := range candidates {
		lastSeen := unstamp(m.lastSeen)
		online, _, seconds := machinePresence(lastSeen, m.scan, m.heartbeat, now)
		if online {
			continue
		}
		since := lastSeen.Add(time.Duration(seconds) * time.Second)
		data, err := json.Marshal(offlineAlert{
			Module: "machine", Kind: "abnormal_offline", Target: m.ip, Alias: m.alias,
			Message:  fmt.Sprintf("机器异常离线：超过 %d 秒未收到有效上报。持续离线仅通知一次，恢复在线后再次离线会重新通知。", seconds),
			LastSeen: lastSeen, OfflineSince: since, DetectedAt: now, OfflineAfterSeconds: seconds,
		})
		if err != nil {
			return 0, err
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return 0, err
		}
		eventID := "master-offline-" + hex.EncodeToString(random[:])
		if _, err := tx.ExecContext(ctx, `INSERT INTO events(event_id,machine_ip,host,type,time,received_at,data) VALUES(?,?,?,'alert',?,?,?)`, eventID, m.ip, m.host, stamp(since), stamp(now), string(data)); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO machine_offline_state(machine_ip,event_id) VALUES(?,?)`, m.ip, eventID); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE machines SET last_event_at=MAX(last_event_at,?) WHERE ip=?`, stamp(since), m.ip); err != nil {
			return 0, err
		}
		created++
	}
	// If notifications are enabled after an outage starts, send that ongoing
	// incident once to the newly enabled destination. Delivered jobs stay unique.
	if _, err := tx.ExecContext(ctx, `INSERT INTO outbox(webhook_id,event_id,next_attempt_at)
 SELECT w.id,e.id,? FROM machine_offline_state o
 JOIN events e ON e.machine_ip=o.machine_ip AND e.event_id=o.event_id
 JOIN webhooks w ON w.enabled=1
 WHERE NOT EXISTS (SELECT 1 FROM outbox q WHERE q.webhook_id=w.id AND q.event_id=e.id)
 ON CONFLICT(webhook_id,event_id) DO NOTHING`, stamp(now)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return created, nil
}

// RunOfflineMonitor is independent of HTTP deliveries, which can be slow.
func (s *Server) RunOfflineMonitor(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastError time.Time
	for ctx.Err() == nil {
		if _, err := s.Store.DetectOffline(ctx, time.Now()); err != nil && ctx.Err() == nil {
			if lastError.IsZero() || time.Since(lastError) >= time.Minute {
				s.Logger.Error("检测机器异常离线失败", "error", err)
				lastError = time.Now()
			}
		} else {
			lastError = time.Time{}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func offlineNotificationText(event Event, alert offlineAlert) string {
	text := fmt.Sprintf("【安全中心：机器异常离线】\n机器 IP：%s\n主机名：%s", event.MachineIP, event.Host)
	if alert.Alias != "" {
		text += "\n机器别名：" + alert.Alias
	}
	return text + fmt.Sprintf("\n状态：异常离线\n最后上报时间（UTC）：%s\n离线判定时间（UTC）：%s\n超时阈值：%d 秒\n说明：本次持续离线仅通知一次，恢复在线后再次离线会重新通知。\n事件编号：%s",
		alert.LastSeen.UTC().Format("2006-01-02 15:04:05"), alert.OfflineSince.UTC().Format("2006-01-02 15:04:05"), alert.OfflineAfterSeconds, event.EventID)
}
