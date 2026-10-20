package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	packageDefaultWindow       = 15
	packageMaxWindow           = 60
	packageLeaseDuration       = 10 * time.Minute
	packageMaxSessions         = 128
	packageMaxConnections      = 32
	packageMaxAgentConnections = 8
	packageMaxStreamBytes      = 512 << 20
	packageMaxLeaseBytes       = 2 << 30
	packageIdleTimeout         = 60 * time.Second
)

// Only known official package/release origins are enabled by default. Operators
// can add exact hostnames; arbitrary wildcard proxy rules are not accepted.
var defaultPackageHosts = []string{
	"archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com", "*.ec2.archive.ubuntu.com",
	"deb.debian.org", "security.debian.org",
	"github.com", "api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com",
	"download.fedoraproject.org", "dl.fedoraproject.org", "mirrors.fedoraproject.org",
	"dl.rockylinux.org", "mirrors.rockylinux.org", "repo.almalinux.org", "mirrors.almalinux.org",
	"mirror.stream.centos.org", "mirrors.centos.org", "cdn.amazonlinux.com",
	"cdn.redhat.com", "cdn-ubi.redhat.com",
}

type packageDownloadStatus struct {
	Enabled           bool       `json:"enabled"`
	ExpiresAt         *time.Time `json:"expires_at"`
	WindowMinutes     int        `json:"window_minutes"`
	AllowedHosts      []string   `json:"allowed_hosts"`
	ActiveSessions    int        `json:"active_sessions"`
	ActiveConnections int        `json:"active_connections"`
	BytesTransferred  int64      `json:"bytes_transferred"`
	LastError         string     `json:"last_error"`
}

type packageDownloads struct {
	mu          sync.Mutex
	enabled     bool
	expires     time.Time
	window      int
	hosts       []string
	leases      map[string]*packageLease
	connections int
	bytes       int64
	lastError   string
	timer       *time.Timer
	idleTimeout time.Duration
	// Dependencies are explicit so security and expiry tests never use the network.
	lookup func(context.Context, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
}

type packageLease struct {
	token   string
	owner   *agentConfigConnection
	expires time.Time
	streams map[*packageStream]struct{}
	bytes   int64
	timer   *time.Timer
}

type packageStream struct {
	client      net.Conn
	upstream    net.Conn
	cancel      context.CancelFunc
	expires     time.Time
	idleTimeout time.Duration
	activityMu  sync.Mutex
}

// HTTP GET becomes silent in the upload direction while a large response is
// still downloading. Activity in either direction refreshes both deadlines.
func (stream *packageStream) touch() {
	stream.activityMu.Lock()
	defer stream.activityMu.Unlock()
	deadline := time.Now().Add(stream.idleTimeout)
	if stream.expires.Before(deadline) {
		deadline = stream.expires
	}
	_ = stream.client.SetDeadline(deadline)
	_ = stream.upstream.SetDeadline(deadline)
}

func (stream *packageStream) close() {
	stream.cancel()
	_ = stream.client.Close()
	if stream.upstream != nil {
		_ = stream.upstream.Close()
	}
}

func newPackageDownloads(store *Store, logger *slog.Logger) *packageDownloads {
	p := &packageDownloads{window: packageDefaultWindow, hosts: slices.Clone(defaultPackageHosts), leases: map[string]*packageLease{}, idleTimeout: packageIdleTimeout}
	p.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	p.dial = dialer.DialContext // Deliberately bypass HTTP_PROXY/HTTPS_PROXY.
	if store == nil {
		return p
	}
	var raw string
	err := store.DB.QueryRow(`SELECT window_minutes,allowed_hosts FROM package_download_settings WHERE id=1`).Scan(&p.window, &raw)
	if err == nil {
		var hosts []string
		if err = json.Unmarshal([]byte(raw), &hosts); err == nil {
			p.hosts, err = normalizePackageHosts(hosts)
		}
		if p.window < 1 || p.window > packageMaxWindow {
			err = errors.New("invalid saved package download window")
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		p.window, p.hosts = packageDefaultWindow, slices.Clone(defaultPackageHosts)
		p.lastError = "下载设置读取失败，已保持关闭"
		logger.Error("load package download settings", "error", err)
	}
	// Windows/tokens are intentionally memory-only: restart always disables relay.
	return p
}

func packageToken() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func packageHost(value string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(value, "."))
	if len(host) == 0 || len(host) > 253 || strings.TrimSpace(host) != host || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return "", errors.New("下载源必须使用完整域名")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("下载源域名无效")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("下载源域名无效")
			}
		}
	}
	return host, nil
}

func normalizePackageHosts(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 128 {
		return nil, errors.New("请提供 1–128 个下载源域名")
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "*.ec2.archive.ubuntu.com" {
			if !slices.Contains(result, value) {
				result = append(result, value)
			}
			continue
		}
		host, err := packageHost(value)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(result, host) {
			result = append(result, host)
		}
	}
	return result, nil
}

func allowedPackageHost(host string, allowed []string) bool {
	for _, rule := range allowed {
		if host == rule || strings.HasPrefix(rule, "*.") && strings.HasSuffix(host, rule[1:]) && host != rule[2:] {
			return true
		}
	}
	return false
}

// Reject special-use ranges beyond IsPrivate (CGNAT, documentation, benchmark,
// multicast/reserved and IPv6 transition addresses can also reach local services).
var packageBlockedNetworks = func() []netip.Prefix {
	values := []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16"}
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}()

func publicPackageIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, blocked := range packageBlockedNetworks {
		if blocked.Contains(ip) {
			return false
		}
	}
	return true
}

func (p *packageDownloads) target(ctx context.Context, target string, allowed []string) ([]string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || port != "80" && port != "443" {
		return nil, errors.New("下载仅允许域名的 80 或 443 端口")
	}
	host, err = packageHost(host)
	if err != nil || !allowedPackageHost(host, allowed) {
		return nil, errors.New("下载源不在允许列表")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := p.lookup(lookupCtx, host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("下载源 DNS 解析失败")
	}
	addresses := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !publicPackageIP(ip) {
			return nil, errors.New("下载源解析到非公网地址，已拒绝")
		}
		addresses = append(addresses, net.JoinHostPort(ip.Unmap().String(), port))
	}
	return addresses, nil
}

func (p *packageDownloads) revokeLocked(token string) {
	lease := p.leases[token]
	if lease == nil {
		return
	}
	delete(p.leases, token)
	if lease.timer != nil {
		lease.timer.Stop()
	}
	for stream := range lease.streams {
		stream.close()
	}
}

func (p *packageDownloads) revokeOwner(owner *agentConfigConnection) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for token, lease := range p.leases {
		if lease.owner == owner {
			p.revokeLocked(token)
		}
	}
}

func (p *packageDownloads) disableLocked() {
	p.enabled = false
	p.expires = time.Time{}
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	for token := range p.leases {
		p.revokeLocked(token)
	}
}

func (p *packageDownloads) disable() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.disableLocked()
}

func (p *packageDownloads) enableLocked(until time.Time) {
	p.enabled, p.expires = true, until
	p.timer = time.AfterFunc(time.Until(until), func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.expires.Equal(until) {
			p.disableLocked()
		}
	})
}

func (p *packageDownloads) expireLocked() {
	now := time.Now()
	if p.enabled && !now.Before(p.expires) {
		p.disableLocked()
	}
	for token, lease := range p.leases {
		if !now.Before(lease.expires) {
			p.revokeLocked(token)
		}
	}
}

func (p *packageDownloads) statusLocked() packageDownloadStatus {
	p.expireLocked()
	result := packageDownloadStatus{Enabled: p.enabled, WindowMinutes: p.window, AllowedHosts: slices.Clone(p.hosts), ActiveSessions: len(p.leases), ActiveConnections: p.connections, BytesTransferred: p.bytes, LastError: p.lastError}
	if p.enabled {
		until := p.expires
		result.ExpiresAt = &until
	}
	return result
}

func (s *Server) getPackageDownloads(w http.ResponseWriter, r *http.Request) {
	p := s.packages
	p.mu.Lock()
	status := p.statusLocked()
	p.mu.Unlock()
	writeJSON(w, 200, status)
}

func (s *Server) savePackageDownloads(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled       *bool     `json:"enabled"`
		WindowMinutes *int      `json:"window_minutes"`
		AllowedHosts  *[]string `json:"allowed_hosts"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Enabled == nil {
		fail(w, 400, "请提供 enabled 下载开关")
		return
	}
	p := s.packages
	p.mu.Lock()
	defer p.mu.Unlock()
	window, hosts := p.window, slices.Clone(p.hosts)
	if body.WindowMinutes != nil {
		window = *body.WindowMinutes
	}
	if window < 1 || window > packageMaxWindow {
		fail(w, 400, "下载窗口必须为 1–60 分钟")
		return
	}
	if body.AllowedHosts != nil {
		var err error
		hosts, err = normalizePackageHosts(*body.AllowedHosts)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	raw, _ := json.Marshal(hosts)
	if _, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO package_download_settings(id,window_minutes,allowed_hosts) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET window_minutes=excluded.window_minutes,allowed_hosts=excluded.allowed_hosts`, window, string(raw)); err != nil {
		// Closing remains effective even if the database is temporarily unavailable.
		if !*body.Enabled {
			p.disableLocked()
		}
		s.respond(w, nil, err)
		return
	}
	// Saving or changing allowed origins revokes every previous lease, so a
	// removed origin cannot keep an already established tunnel alive.
	p.disableLocked()
	p.window, p.hosts, p.lastError = window, hosts, ""
	if *body.Enabled {
		p.enableLocked(time.Now().Add(time.Duration(window) * time.Minute))
	}
	s.Logger.Info("package download window changed", "enabled", p.enabled, "window_minutes", p.window)
	writeJSON(w, 200, p.statusLocked())
}

func (s *Server) packageSession(peer *agentConfigConnection, frame agentConfigFrame) (agentConfigFrame, error) {
	ip, err := normalizeIP(frame.IP)
	if err != nil {
		return agentConfigFrame{}, errors.New("Agent 身份无效")
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	owner := s.configAgents[ip]
	if owner == nil || owner.source != peer.source || len(frame.Token) != 64 || len(owner.downloadToken) != 64 || subtle.ConstantTimeCompare([]byte(frame.Token), []byte(owner.downloadToken)) != 1 {
		return agentConfigFrame{}, errors.New("下载会话认证失败")
	}
	// A hello can register presence, but it cannot grant proxy access. Only an
	// administrator-assigned, nonempty configuration authorizes installation.
	var revision string
	if err := s.Store.DB.QueryRow(`SELECT revision FROM agent_config_deliveries WHERE machine_ip=? AND revision<>'' AND ciphertext<>''`, ip).Scan(&revision); err != nil {
		return agentConfigFrame{}, errors.New("该 Agent 尚未获管理员分配配置，禁止下载")
	}
	p := s.packages
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked()
	if !p.enabled {
		return agentConfigFrame{}, errors.New("主控软件下载已关闭，请管理员临时开启")
	}
	for token, lease := range p.leases {
		if lease.owner == owner {
			p.revokeLocked(token)
		}
	}
	if len(p.leases) >= packageMaxSessions {
		return agentConfigFrame{}, errors.New("下载会话已达上限")
	}
	token, err := packageToken()
	if err != nil {
		return agentConfigFrame{}, errors.New("下载会话创建失败")
	}
	until := time.Now().Add(packageLeaseDuration)
	if p.expires.Before(until) {
		until = p.expires
	}
	lease := &packageLease{token: token, owner: owner, expires: until, streams: map[*packageStream]struct{}{}}
	p.leases[token] = lease
	lease.timer = time.AfterFunc(time.Until(until), func() { p.mu.Lock(); defer p.mu.Unlock(); p.revokeLocked(token) })
	return agentConfigFrame{Version: 1, Type: "package_session", Token: token, ExpiresAt: until.UTC().Format(time.RFC3339)}, nil
}

// Caller holds configMu before packages.mu. No package state operation acquires
// configMu in the opposite order; ACK and single-connection SQLite remain safe.
func (s *Server) packageLeaseLocked(peer *agentConfigConnection, frame agentConfigFrame) (*packageLease, error) {
	p := s.packages
	p.expireLocked()
	lease := p.leases[frame.Token]
	if !p.enabled || lease == nil || len(frame.Token) != 64 || lease.owner.ip != frame.IP || lease.owner.source != peer.source || s.configAgents[lease.owner.ip] != lease.owner {
		return nil, errors.New("下载会话已关闭、过期或认证失败")
	}
	return lease, nil
}

func (s *Server) closePackageSession(peer *agentConfigConnection, frame agentConfigFrame) error {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	p := s.packages
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := s.packageLeaseLocked(peer, frame); err != nil {
		return err
	}
	p.revokeLocked(frame.Token)
	return nil
}

func (s *Server) servePackageConnection(ctx context.Context, peer *agentConfigConnection, reader *bufio.Reader, frame agentConfigFrame) {
	var err error
	switch frame.Type {
	case "package_session":
		var response agentConfigFrame
		response, err = s.packageSession(peer, frame)
		if err == nil {
			_ = writeAgentFrame(peer.conn, response)
		}
	case "package_close":
		err = s.closePackageSession(peer, frame)
		if err == nil {
			_ = writeAgentFrame(peer.conn, agentConfigFrame{Version: 1, Type: "package_closed"})
		}
	case "package_relay":
		err = s.relayPackage(ctx, peer, reader, frame)
	default:
		err = errors.New("不支持的下载操作")
	}
	if err != nil {
		p := s.packages
		p.mu.Lock()
		p.lastError = err.Error()
		p.mu.Unlock()
		_ = writeAgentFrame(peer.conn, agentConfigFrame{Version: 1, Type: "error", Error: err.Error()})
	}
}

func (s *Server) relayPackage(ctx context.Context, peer *agentConfigConnection, reader *bufio.Reader, frame agentConfigFrame) error {
	p := s.packages
	s.configMu.Lock()
	p.mu.Lock()
	lease, err := s.packageLeaseLocked(peer, frame)
	if err == nil && (p.connections >= packageMaxConnections || len(lease.streams) >= packageMaxAgentConnections || lease.bytes >= packageMaxLeaseBytes) {
		err = errors.New("下载并发或流量已达上限")
	}
	if err != nil {
		p.mu.Unlock()
		s.configMu.Unlock()
		return err
	}
	streamCtx, cancel := context.WithDeadline(ctx, lease.expires)
	stream := &packageStream{client: peer.conn, cancel: cancel, expires: lease.expires, idleTimeout: p.idleTimeout}
	lease.streams[stream] = struct{}{}
	p.connections++
	allowed := slices.Clone(p.hosts)
	p.mu.Unlock()
	s.configMu.Unlock()
	defer func() {
		p.mu.Lock()
		stream.cancel()
		if stream.upstream != nil {
			_ = stream.upstream.Close()
		}
		delete(lease.streams, stream)
		p.connections--
		p.mu.Unlock()
	}()
	addresses, err := p.target(streamCtx, frame.Target, allowed)
	if err != nil {
		return err
	}
	dialCtx, dialCancel := context.WithTimeout(streamCtx, 10*time.Second)
	defer dialCancel()
	var upstream net.Conn
	for _, address := range addresses {
		upstream, err = p.dial(dialCtx, "tcp", address)
		if err == nil {
			break
		}
	}
	if err != nil {
		return errors.New("主控连接下载源失败")
	}
	p.mu.Lock()
	if p.leases[lease.token] != lease || streamCtx.Err() != nil {
		p.mu.Unlock()
		_ = upstream.Close()
		return errors.New("下载会话已关闭或过期")
	}
	stream.upstream = upstream
	p.mu.Unlock()
	if err = writeAgentFrame(peer.conn, agentConfigFrame{Version: 1, Type: "package_ready"}); err != nil {
		return err
	}
	// Replace the JSON handshake deadlines with one shared idle deadline, keeping
	// reader's already buffered bytes and the absolute lease deadline.
	stream.touch()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(&packageWriter{p, lease, upstream, stream}, io.LimitReader(&packageReader{reader, stream}, packageMaxStreamBytes))
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(&packageWriter{p, lease, peer.conn, stream}, io.LimitReader(&packageReader{upstream, stream}, packageMaxStreamBytes))
		done <- struct{}{}
	}()
	completed := 0
	select {
	case <-done:
		completed++
	case <-streamCtx.Done():
	}
	p.mu.Lock()
	stream.close()
	p.mu.Unlock()
	// Join both copies before releasing tracking, including on administrative close.
	for completed < 2 {
		<-done
		completed++
	}
	return nil
}

type packageReader struct {
	reader io.Reader
	stream *packageStream
}

func (r *packageReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	if n > 0 {
		r.stream.touch()
	}
	return n, err
}

type packageWriter struct {
	downloads *packageDownloads
	lease     *packageLease
	conn      net.Conn
	stream    *packageStream
}

func (w *packageWriter) Write(buffer []byte) (int, error) {
	p := w.downloads
	p.mu.Lock()
	remaining := int64(packageMaxLeaseBytes) - w.lease.bytes
	if p.leases[w.lease.token] != w.lease || remaining <= 0 {
		p.mu.Unlock()
		return 0, net.ErrClosed
	}
	if int64(len(buffer)) > remaining {
		buffer = buffer[:int(remaining)]
	}
	w.lease.bytes += int64(len(buffer)) // Reserve across concurrent streams.
	p.mu.Unlock()
	n, err := w.conn.Write(buffer)
	if n > 0 && w.stream != nil {
		w.stream.touch()
	}
	p.mu.Lock()
	w.lease.bytes -= int64(len(buffer) - n)
	p.bytes += int64(n)
	p.mu.Unlock()
	if err == nil && n == 0 {
		err = io.ErrShortWrite
	}
	return n, err
}
