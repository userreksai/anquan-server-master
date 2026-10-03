package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const cookieName = "anquan_session"

type attempt struct {
	Count int
	Until time.Time
}

func tokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Server) authenticated(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil || len(c.Value) != 64 {
		return false
	}
	var user string
	err = s.Store.DB.QueryRowContext(r.Context(), `SELECT username FROM sessions WHERE token_hash=? AND expires_at>?`, tokenHash(c.Value), stamp(time.Now())).Scan(&user)
	return err == nil && user == "admin"
}
func (s *Server) cookie(w http.ResponseWriter, token string, expires time.Time, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", Expires: expires, MaxAge: maxAge, HttpOnly: true, Secure: s.SecureCookie, SameSite: http.SameSiteStrictMode})
}
func (s *Server) allowLogin(remote string) bool {
	ip, _, err := net.SplitHostPort(remote)
	if err != nil {
		ip = remote
	}
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	now := time.Now()
	for key, value := range s.loginAttempts {
		if now.After(value.Until) {
			delete(s.loginAttempts, key)
		}
	}
	v := s.loginAttempts[ip]
	if v.Count >= 10 {
		return false
	}
	if v.Count == 0 {
		if len(s.loginAttempts) >= 10000 {
			return false
		}
		v.Until = now.Add(time.Minute)
	}
	v.Count++
	s.loginAttempts[ip] = v
	return true
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.allowLogin(r.RemoteAddr) {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "登录请求过多，请稍后重试")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(body.Username) > 128 || len(body.Password) > 72 {
		fail(w, 401, "账号或密码错误")
		return
	}
	var hash string
	// Always check admin's hash, even for an unknown username, to avoid a cheap username oracle.
	err := s.Store.DB.QueryRowContext(r.Context(), `SELECT password_hash FROM users WHERE username='admin'`).Scan(&hash)
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) != nil || body.Username != "admin" {
		fail(w, 401, "账号或密码错误")
		return
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		s.respond(w, nil, err)
		return
	}
	token := hex.EncodeToString(random)
	now := time.Now()
	expires := now.Add(24 * time.Hour)
	tx, err := s.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), `DELETE FROM sessions WHERE expires_at<=?`, stamp(now)); err != nil {
		s.respond(w, nil, err)
		return
	}
	// A concurrent CLI password reset invalidates this login's old credential snapshot too.
	res, err := tx.ExecContext(r.Context(), `INSERT INTO sessions(token_hash,username,expires_at) SELECT ?,'admin',? FROM users WHERE username='admin' AND password_hash=?`, tokenHash(token), stamp(expires), hash)
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	if n == 0 {
		fail(w, 401, "密码已变更，请重新登录")
		return
	}
	if err = tx.Commit(); err != nil {
		s.respond(w, nil, err)
		return
	}
	s.cookie(w, token, expires, 86400)
	writeJSON(w, 200, map[string]string{"username": "admin"})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(cookieName); err == nil {
		if _, err = s.Store.DB.ExecContext(r.Context(), `DELETE FROM sessions WHERE token_hash=?`, tokenHash(cookie.Value)); err != nil {
			s.respond(w, nil, err)
			return
		}
	}
	s.cookie(w, "", time.Unix(1, 0), -1)
	writeJSON(w, 200, map[string]string{"message": "已退出登录"})
}
func (s *Server) password(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := ValidatePassword(body.New); err != nil {
		fail(w, 400, err.Error())
		return
	}
	var current string
	err := s.Store.DB.QueryRowContext(r.Context(), `SELECT password_hash FROM users WHERE username='admin'`).Scan(&current)
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(current), []byte(body.Current)) != nil {
		fail(w, 400, "当前密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(body.New), 12)
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	tx, err := s.Store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(r.Context(), `UPDATE users SET password_hash=? WHERE username='admin' AND password_hash=?`, string(newHash), current)
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	if n == 0 {
		fail(w, 409, "密码已变更，请重新登录")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `DELETE FROM sessions WHERE username='admin'`); err != nil {
		s.respond(w, nil, err)
		return
	}
	if err = tx.Commit(); err != nil {
		s.respond(w, nil, err)
		return
	}
	s.cookie(w, "", time.Unix(1, 0), -1)
	writeJSON(w, 200, map[string]string{"message": "密码已更新，请重新登录"})
}
