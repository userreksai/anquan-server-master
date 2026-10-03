package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	Store         *Store
	SecureCookie  bool
	Logger        *slog.Logger
	Client        *http.Client
	loginMu       sync.Mutex
	loginAttempts map[string]attempt
}

func New(s *Store, secureCookie bool, logger *slog.Logger) *Server {
	return &Server{Store: s, SecureCookie: secureCookie, Logger: logger, Client: WebhookClient(), loginAttempts: map[string]attempt{}}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Store.DB.PingContext(r.Context()); err != nil {
			fail(w, 503, "数据库不可用")
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /api/auth/login", s.login)
	mux.HandleFunc("GET /api/auth/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"username": "admin"})
	})
	mux.HandleFunc("POST /api/auth/logout", s.logout)
	mux.HandleFunc("PUT /api/auth/password", s.password)
	mux.HandleFunc("GET /api/overview", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Store.Overview(r.Context())
		s.respond(w, v, e)
	})
	mux.HandleFunc("GET /api/machines", s.machines)
	mux.HandleFunc("GET /api/machines/{ip}", s.machine)
	mux.HandleFunc("PATCH /api/machines/{ip}", s.updateMachine)
	mux.HandleFunc("DELETE /api/machines/{ip}", s.deleteMachine)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/events/{id}", s.event)
	mux.HandleFunc("PATCH /api/events/{id}", s.updateEvent)
	mux.HandleFunc("DELETE /api/events/{id}", s.deleteEvent)
	mux.HandleFunc("GET /api/webhooks", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Store.Webhooks(r.Context())
		s.respond(w, v, e)
	})
	mux.HandleFunc("POST /api/webhooks", s.saveWebhook)
	mux.HandleFunc("PUT /api/webhooks/{id}", s.saveWebhook)
	mux.HandleFunc("DELETE /api/webhooks/{id}", s.deleteWebhook)
	mux.HandleFunc("POST /api/webhooks/{id}/test", s.testWebhook)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, "接口不存在") })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, r.Host) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
					fail(w, 403, "请求来源不受信任")
					return
				}
			}
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				fail(w, 403, "不允许跨站请求")
				return
			}
			if r.ContentLength != 0 {
				mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil || mt != "application/json" {
					fail(w, 415, "请求必须使用 application/json")
					return
				}
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/auth/login" {
			if !s.authenticated(r) {
				fail(w, 401, "请先登录")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"message": message})
}
func (s *Server) respond(w http.ResponseWriter, v any, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "记录不存在")
		return
	}
	if err != nil {
		s.Logger.Error("database request failed", "error", err)
		fail(w, 500, "服务器处理失败")
		return
	}
	writeJSON(w, 200, v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		fail(w, 400, "JSON 请求内容无效")
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		fail(w, 400, "JSON 请求只能包含一个对象")
		return false
	}
	return true
}
func idFrom(w http.ResponseWriter, r *http.Request) (int64, bool) {
	v, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || v <= 0 {
		fail(w, 400, "记录 ID 无效")
		return 0, false
	}
	return v, true
}
func ipFrom(w http.ResponseWriter, r *http.Request) (string, bool) {
	v, err := normalizeIP(r.PathValue("ip"))
	if err != nil {
		fail(w, 400, "机器 IP 无效")
		return "", false
	}
	return v, true
}

func (s *Server) machines(w http.ResponseWriter, r *http.Request) {
	f, e := ParseFilter(r.URL.Query())
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	v, e := s.Store.Machines(r.Context(), f)
	s.respond(w, v, e)
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	f, e := ParseFilter(r.URL.Query())
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	v, e := s.Store.Events(r.Context(), f)
	s.respond(w, v, e)
}
func (s *Server) machine(w http.ResponseWriter, r *http.Request) {
	ip, ok := ipFrom(w, r)
	if !ok {
		return
	}
	v, e := s.Store.Machine(r.Context(), ip)
	s.respond(w, v, e)
}
func (s *Server) event(w http.ResponseWriter, r *http.Request) {
	id, ok := idFrom(w, r)
	if !ok {
		return
	}
	v, e := s.Store.Event(r.Context(), id)
	s.respond(w, v, e)
}
func (s *Server) updateMachine(w http.ResponseWriter, r *http.Request) {
	ip, ok := ipFrom(w, r)
	if !ok {
		return
	}
	var body struct {
		Alias *string `json:"alias"`
		Notes *string `json:"notes"`
	}
	if !decode(w, r, &body) {
		return
	}
	if (body.Alias == nil && body.Notes == nil) || (body.Alias != nil && len(*body.Alias) > 255) || (body.Notes != nil && len(*body.Notes) > 10000) {
		fail(w, 400, "请填写别名或备注（别名最多 255 字节，备注最多 10000 字节）")
		return
	}
	result, e := s.Store.DB.ExecContext(r.Context(), `UPDATE machines SET alias=COALESCE(?,alias),notes=COALESCE(?,notes) WHERE ip=?`, body.Alias, body.Notes, ip)
	if !s.changed(w, result, e) {
		return
	}
	v, e := s.Store.Machine(r.Context(), ip)
	s.respond(w, v, e)
}
func (s *Server) updateEvent(w http.ResponseWriter, r *http.Request) {
	id, ok := idFrom(w, r)
	if !ok {
		return
	}
	var body struct {
		Status *string `json:"status"`
		Notes  *string `json:"notes"`
	}
	if !decode(w, r, &body) {
		return
	}
	if (body.Status == nil && body.Notes == nil) || (body.Status != nil && *body.Status != "open" && *body.Status != "resolved") || (body.Notes != nil && len(*body.Notes) > 10000) {
		fail(w, 400, "状态或备注无效")
		return
	}
	result, e := s.Store.DB.ExecContext(r.Context(), `UPDATE events SET status=COALESCE(?,status),notes=COALESCE(?,notes) WHERE id=?`, body.Status, body.Notes, id)
	if !s.changed(w, result, e) {
		return
	}
	v, e := s.Store.Event(r.Context(), id)
	s.respond(w, v, e)
}
func (s *Server) changed(w http.ResponseWriter, result sql.Result, err error) bool {
	if err != nil {
		s.respond(w, nil, err)
		return false
	}
	n, err := result.RowsAffected()
	if err != nil {
		s.respond(w, nil, err)
		return false
	}
	if n == 0 {
		fail(w, 404, "记录不存在")
		return false
	}
	return true
}
func (s *Server) deleteMachine(w http.ResponseWriter, r *http.Request) {
	ip, ok := ipFrom(w, r)
	if !ok {
		return
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM machines WHERE ip=?`, ip)
	if s.changed(w, res, err) {
		writeJSON(w, 200, map[string]string{"message": "机器及其记录已删除"})
	}
}
func (s *Server) deleteEvent(w http.ResponseWriter, r *http.Request) {
	id, ok := idFrom(w, r)
	if !ok {
		return
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM events WHERE id=?`, id)
	if s.changed(w, res, err) {
		writeJSON(w, 200, map[string]string{"message": "记录已删除"})
	}
}

func validateWebhook(w *Webhook) error {
	w.Name = strings.TrimSpace(w.Name)
	w.URL = strings.TrimSpace(w.URL)
	if w.Name == "" || len(w.Name) > 128 {
		return errors.New("通知名称必须为 1–128 字节")
	}
	if len(w.URL) > 4096 {
		return errors.New("通知地址过长")
	}
	u, err := url.Parse(w.URL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Fragment != "" {
		return errors.New("通知地址必须为 HTTP(S) URL，不能包含用户信息或片段")
	}
	if w.Format == "" {
		w.Format = "feishu"
	}
	if w.Format != "feishu" && w.Format != "wecom" && w.Format != "generic" {
		return errors.New("通知格式无效")
	}
	return nil
}
func (s *Server) saveWebhook(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Format  string `json:"format"`
		Enabled *bool  `json:"enabled"`
	}
	if !decode(w, r, &body) {
		return
	}
	hook := Webhook{Name: body.Name, URL: body.URL, Format: body.Format, Enabled: true}
	if body.Enabled != nil {
		hook.Enabled = *body.Enabled
	}
	if err := validateWebhook(&hook); err != nil {
		fail(w, 400, err.Error())
		return
	}
	now := stamp(time.Now())
	if r.Method == http.MethodPost {
		res, e := s.Store.DB.ExecContext(r.Context(), `INSERT INTO webhooks(name,url,format,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)`, hook.Name, hook.URL, hook.Format, hook.Enabled, now, now)
		if e != nil {
			s.respond(w, nil, e)
			return
		}
		hook.ID, e = res.LastInsertId()
		if e != nil {
			s.respond(w, nil, e)
			return
		}
	} else {
		id, ok := idFrom(w, r)
		if !ok {
			return
		}
		hook.ID = id
		res, e := s.Store.DB.ExecContext(r.Context(), `UPDATE webhooks SET name=?,url=?,format=?,enabled=?,updated_at=? WHERE id=?`, hook.Name, hook.URL, hook.Format, hook.Enabled, now, id)
		if !s.changed(w, res, e) {
			return
		}
	}
	v, e := s.Store.Webhook(r.Context(), hook.ID)
	s.respond(w, v, e)
}
func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	id, ok := idFrom(w, r)
	if !ok {
		return
	}
	res, err := s.Store.DB.ExecContext(r.Context(), `DELETE FROM webhooks WHERE id=?`, id)
	if s.changed(w, res, err) {
		writeJSON(w, 200, map[string]string{"message": "通知地址已删除"})
	}
}
func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) {
	id, ok := idFrom(w, r)
	if !ok {
		return
	}
	hook, err := s.Store.Webhook(r.Context(), id)
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	event := Event{EventID: "test-" + strconv.FormatInt(time.Now().UnixNano(), 10), MachineIP: "127.0.0.1", Host: "安全中心", Type: "alert", Time: time.Now().UTC(), Data: json.RawMessage(`{"module":"test","kind":"webhook_test","target":"-","message":"这是一条来自安全中心的测试通知"}`)}
	err = PostEvent(r.Context(), s.Client, hook, event)
	if err != nil {
		_, _ = s.Store.DB.ExecContext(r.Context(), `UPDATE webhooks SET last_error=? WHERE id=?`, err.Error(), id)
		fail(w, 502, err.Error())
		return
	}
	_, err = s.Store.DB.ExecContext(r.Context(), `UPDATE webhooks SET last_error='',last_success_at=? WHERE id=?`, stamp(time.Now()), id)
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	writeJSON(w, 200, map[string]string{"message": "测试通知发送成功"})
}
