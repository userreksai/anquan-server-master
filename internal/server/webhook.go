package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

func WebhookClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func AlertText(event Event) string {
	var alert struct {
		Module  string `json:"module"`
		Kind    string `json:"kind"`
		Target  string `json:"target"`
		Message string `json:"message"`
		Before  string `json:"before"`
		After   string `json:"after"`
	}
	_ = json.Unmarshal(event.Data, &alert)
	text := fmt.Sprintf("【安全中心告警】\n机器 IP：%s\n主机：%s\n类型：%s / %s\n目标：%s\n时间：%s\n内容：%s", event.MachineIP, event.Host, alert.Module, alert.Kind, alert.Target, event.Time.UTC().Format(time.RFC3339), alert.Message)
	if alert.Before != "" {
		text += "\n变更前：" + alert.Before
	}
	if alert.After != "" {
		text += "\n变更后：" + alert.After
	}
	return text + "\n事件 ID：" + event.EventID
}

// PostEvent deliberately does not put URL secrets or response bodies into errors.
func PostEvent(ctx context.Context, client *http.Client, hook Webhook, event Event) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	text := AlertText(event)
	var payload any
	switch hook.Format {
	case "feishu":
		payload = map[string]any{"msg_type": "text", "content": map[string]string{"text": text}}
	case "wecom":
		payload = map[string]any{"msgtype": "text", "text": map[string]string{"content": text}}
	case "generic":
		payload = map[string]any{"event_id": event.EventID, "kind": event.Type, "text": text, "created_at": event.Time, "machine_ip": event.MachineIP, "host": event.Host, "data": event.Data}
	default:
		return errors.New("不支持的 Webhook 格式")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("Webhook 地址无效")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", event.MachineIP+":"+event.EventID)
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("Webhook 连接失败或超时")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Webhook HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 {
		return errors.New("Webhook 响应读取失败或过大")
	}
	if hook.Format == "generic" {
		return nil
	}
	var ack map[string]json.RawMessage
	if json.Unmarshal(data, &ack) != nil || ack == nil {
		return errors.New("Webhook 响应不是有效 JSON")
	}
	keys := []string{"code", "StatusCode"}
	if hook.Format == "wecom" {
		keys = []string{"errcode"}
	}
	found := false
	for _, key := range keys {
		if raw, ok := ack[key]; ok {
			found = true
			var code *int
			if json.Unmarshal(raw, &code) != nil || code == nil || *code != 0 {
				return errors.New("Webhook 业务响应拒绝通知")
			}
		}
	}
	if !found {
		return errors.New("Webhook 响应缺少确认码")
	}
	return nil
}

type delivery struct {
	ID, WebhookID, EventID int64
	Attempts               int
}

func (s *Server) due(ctx context.Context) ([]delivery, error) {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT o.id,o.webhook_id,o.event_id,o.attempts FROM outbox o JOIN webhooks w ON w.id=o.webhook_id WHERE o.delivered_at IS NULL AND o.next_attempt_at<=? AND w.enabled=1 ORDER BY o.next_attempt_at,o.id LIMIT 16`, stamp(time.Now()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []delivery{}
	for rows.Next() {
		var d delivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.EventID, &d.Attempts); err != nil {
			return nil, err
		}
		jobs = append(jobs, d)
	}
	return jobs, rows.Err()
}

func (s *Server) deliver(ctx context.Context, d delivery) error {
	hook, err := s.Store.Webhook(ctx, d.WebhookID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !hook.Enabled {
		return nil
	}
	event, err := s.Store.Event(ctx, d.EventID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	deliveryErr := PostEvent(ctx, s.Client, hook, event)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := stamp(time.Now())
	if deliveryErr == nil {
		if _, err = tx.ExecContext(ctx, `UPDATE outbox SET attempts=attempts+1,delivered_at=?,last_error='' WHERE id=? AND delivered_at IS NULL`, now, d.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE webhooks SET last_error='',last_success_at=? WHERE id=?`, now, d.WebhookID); err != nil {
			return err
		}
	} else {
		// Retries survive restarts, with capped exponential delay and no silent expiry.
		delay := min(time.Duration(1<<min(d.Attempts, 10))*5*time.Second, time.Hour)
		if _, err = tx.ExecContext(ctx, `UPDATE outbox SET attempts=attempts+1,next_attempt_at=?,last_error=? WHERE id=? AND delivered_at IS NULL`, stamp(time.Now().Add(delay)), deliveryErr.Error(), d.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE webhooks SET last_error=? WHERE id=?`, deliveryErr.Error(), d.WebhookID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RunNotifier is intended to run once per database. At most four HTTP sends run concurrently.
// An interrupted send remains pending; consumers can deduplicate using Idempotency-Key.
func (s *Server) RunNotifier(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		jobs, err := s.due(ctx)
		if err != nil {
			if ctx.Err() == nil {
				s.Logger.Error("read notification outbox", "error", err)
			}
			continue
		}
		sem := make(chan struct{}, 4)
		var wg sync.WaitGroup
		for _, job := range jobs {
			if ctx.Err() != nil {
				break
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(d delivery) {
				defer wg.Done()
				defer func() { <-sem }()
				if err := s.deliver(ctx, d); err != nil && ctx.Err() == nil {
					s.Logger.Error("persist notification result", "outbox_id", d.ID, "error", err)
				}
			}(job)
		}
		wg.Wait()
	}
}
