package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
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

func NotificationText(event Event) string {
	if event.Type != "ssh_login" {
		return AlertText(event)
	}
	var login struct {
		User     string `json:"user"`
		SourceIP string `json:"source_ip"`
		Terminal string `json:"terminal"`
		Method   string `json:"method"`
	}
	_ = json.Unmarshal(event.Data, &login)
	for _, value := range []*string{&login.User, &login.SourceIP, &login.Terminal, &login.Method} {
		if strings.TrimSpace(*value) == "" {
			*value = "N/A"
		}
	}
	return fmt.Sprintf("【安全中心 SSH 登录通知】\n机器 IP：%s\n主机：%s\n类型：ssh_login\n登录用户：%s\n登录来源 IP：%s\n终端：%s\n登录方式：%s\n登录时间：%s\n事件 ID：%s", event.MachineIP, event.Host, login.User, login.SourceIP, login.Terminal, login.Method, event.Time.UTC().Format(time.RFC3339), event.EventID)
}

// WebhookResult exposes the actual outgoing text and safe delivery diagnostics.
// A zero business code confirms acceptance by the provider, not human receipt.
type WebhookResult struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	Text         string `json:"text"`
	Format       string `json:"format"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	BusinessCode *int   `json:"business_code,omitempty"`
	DurationMS   int64  `json:"duration_ms"`
}

func webhookFormat(hook Webhook) string {
	// Older configurations may have selected generic for a Lark URL. Always use
	// the bot's wire contract for official bot endpoints, including queued jobs.
	if u, err := url.Parse(hook.URL); err == nil && strings.HasPrefix(u.Path, "/open-apis/bot/v2/hook/") {
		switch strings.ToLower(u.Hostname()) {
		case "open.larksuite.com", "open.feishu.cn":
			return "feishu"
		}
	}
	if hook.Format == "" || hook.Format == "lark" {
		return "feishu"
	}
	return hook.Format
}

// PostEvent deliberately does not put URL secrets or response bodies into errors.
func PostEvent(ctx context.Context, client *http.Client, hook Webhook, event Event) error {
	_, err := SendEvent(ctx, client, hook, event)
	return err
}

func SendEvent(ctx context.Context, client *http.Client, hook Webhook, event Event) (result WebhookResult, err error) {
	started := time.Now()
	hook.Format = webhookFormat(hook)
	result = WebhookResult{Text: NotificationText(event), Format: hook.Format}
	defer func() {
		result.DurationMS = time.Since(started).Milliseconds()
		result.Success = err == nil
		if err != nil {
			result.Message = err.Error()
		} else if result.BusinessCode != nil {
			result.Message = "Webhook 接收端已确认接收测试消息，请到对应群查看"
		} else {
			result.Message = "Webhook 已返回 HTTP 成功状态，但未提供业务确认码，请在接收端确认消息"
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	text := result.Text
	var payload any
	switch hook.Format {
	case "feishu":
		payload = map[string]any{"msg_type": "text", "content": map[string]string{"text": text}}
	case "wecom":
		payload = map[string]any{"msgtype": "text", "text": map[string]string{"content": text}}
	case "generic":
		payload = map[string]any{"event_id": event.EventID, "kind": event.Type, "text": text, "created_at": event.Time, "machine_ip": event.MachineIP, "host": event.Host, "data": event.Data}
	default:
		return result, errors.New("不支持的 Webhook 格式")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return result, errors.New("Webhook 消息编码失败")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return result, errors.New("Webhook 地址无效")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", event.MachineIP+":"+event.EventID)
	resp, err := client.Do(req)
	if err != nil {
		return result, webhookNetworkError(err)
	}
	defer resp.Body.Close()
	result.HTTPStatus = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("Webhook HTTP %d：接收端未接受请求，请检查地址和主控服务器出口网络", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 {
		return result, errors.New("Webhook 响应读取失败或过大")
	}
	var ack map[string]json.RawMessage
	if json.Unmarshal(data, &ack) != nil || ack == nil {
		if hook.Format == "generic" {
			return result, nil
		}
		return result, errors.New("Webhook 响应不是有效 JSON，无法确认机器人已接收，请检查 URL 是否为群机器人地址")
	}
	keys := []string{"code", "StatusCode"}
	if hook.Format == "wecom" {
		keys = []string{"errcode"}
	} else if hook.Format == "generic" {
		// Do not turn a provider's HTTP 200 business rejection into success even
		// when a proxy URL was configured using the generic payload format.
		keys = []string{"code", "StatusCode", "errcode"}
	}
	found := false
	for _, key := range keys {
		if raw, ok := ack[key]; ok {
			found = true
			var code *int
			if json.Unmarshal(raw, &code) != nil || code == nil {
				return result, fmt.Errorf("Webhook 业务确认码 %s 无效", key)
			}
			result.BusinessCode = code
			if *code != 0 {
				return result, fmt.Errorf("Webhook 业务响应拒绝通知（HTTP %d，%s=%d）：请检查消息格式、机器人关键词、签名和 IP 白名单", resp.StatusCode, key, *code)
			}
		}
	}
	if !found && hook.Format != "generic" {
		return result, errors.New("Webhook 响应缺少业务确认码，无法确认机器人已接收，请检查消息格式和机器人 URL")
	}
	return result, nil
}

func webhookNetworkError(err error) error {
	var dns *net.DNSError
	var certificate *tls.CertificateVerificationError
	var network net.Error
	switch {
	case errors.As(err, &dns):
		return errors.New("Webhook 域名解析失败，请检查主控服务器 DNS")
	case errors.As(err, &certificate):
		return errors.New("Webhook TLS 证书校验失败，请检查主控服务器 CA 证书和系统时间")
	case errors.Is(err, context.Canceled):
		return errors.New("Webhook 请求已取消，未确认接收结果")
	case errors.As(err, &network) && network.Timeout():
		return errors.New("Webhook 请求超时，请检查主控服务器到接收端的网络")
	default:
		return errors.New("Webhook 连接失败，请检查主控服务器出口网络及代理配置")
	}
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
		s.Logger.Warn("webhook delivery failed", "webhook_id", d.WebhookID, "event_id", event.EventID, "attempt", d.Attempts+1, "error", deliveryErr)
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
