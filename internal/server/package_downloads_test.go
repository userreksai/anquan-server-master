package server

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const packageSettingsPath = "/api/settings/package-downloads"

func TestPackageDownloadsSettingsAuthenticationValidationAndRestart(t *testing.T) {
	if validator := New(nil, false, nil); validator.packages.enabled || validator.SetPublicOrigin("http://localhost:10111") != nil {
		t.Fatal("pre-database origin validation failed")
	}
	store, dir := testStore(t)
	s := testServer(store)
	requireStatus(t, testRequest(t, s, "GET", packageSettingsPath, nil, nil, nil), 401)
	requireStatus(t, testRequest(t, s, "PUT", packageSettingsPath, map[string]any{"enabled": true}, nil, nil), 401)
	cookie := testLogin(t, s, DefaultPassword)
	initial := jsonResult[packageDownloadStatus](t, testRequest(t, s, "GET", packageSettingsPath, nil, cookie, nil))
	if initial.Enabled || initial.ExpiresAt != nil || initial.WindowMinutes != 15 || !reflect.DeepEqual(initial.AllowedHosts, defaultPackageHosts) {
		t.Fatalf("unsafe initial settings: %+v", initial)
	}
	body := map[string]any{"enabled": true, "window_minutes": 30, "allowed_hosts": []string{"archive.ubuntu.com", "custom.example.org"}}
	requireStatus(t, testRequest(t, s, "PUT", packageSettingsPath, body, cookie, map[string]string{"Origin": "https://attacker.test"}), 403)
	for _, invalid := range []map[string]any{
		{}, {"enabled": true, "window_minutes": 0}, {"enabled": true, "window_minutes": 61},
		{"enabled": true, "allowed_hosts": []string{}}, {"enabled": true, "allowed_hosts": []string{"*.example.org"}},
		{"enabled": true, "allowed_hosts": []string{"127.0.0.1"}}, {"enabled": true, "allowed_hosts": []string{"https://example.org"}},
		{"enabled": true, "unknown": true},
	} {
		requireStatus(t, testRequest(t, s, "PUT", packageSettingsPath, invalid, cookie, nil), 400)
	}
	w := testRequest(t, s, "PUT", packageSettingsPath, body, cookie, nil)
	requireStatus(t, w, 200)
	opened := jsonResult[packageDownloadStatus](t, w)
	if !opened.Enabled || opened.ExpiresAt == nil || time.Until(*opened.ExpiresAt) < 29*time.Minute {
		t.Fatalf("window not enabled: %+v", opened)
	}
	s.packages.disable()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	afterRestart := testServer(reopened)
	afterRestart.packages.mu.Lock()
	got := afterRestart.packages.statusLocked()
	afterRestart.packages.mu.Unlock()
	if got.Enabled || got.ExpiresAt != nil || got.WindowMinutes != 30 || !reflect.DeepEqual(got.AllowedHosts, []string{"archive.ubuntu.com", "custom.example.org"}) {
		t.Fatalf("restart restored access or lost settings: %+v", got)
	}
}

func TestPackageTargetRejectsSSRFPortsHostnamesAndDNSRebinding(t *testing.T) {
	public := netip.MustParseAddr("185.125.190.83")
	lookupCalls := 0
	p := &packageDownloads{lookup: func(context.Context, string) ([]netip.Addr, error) { lookupCalls++; return []netip.Addr{public}, nil }}
	allowed := []string{"archive.ubuntu.com", "*.ec2.archive.ubuntu.com"}
	for _, target := range []string{"127.0.0.1:80", "169.254.169.254:80", "[::1]:443", "archive.ubuntu.com:22", "archive.ubuntu.com:55557", "archive.ubuntu.com:0443", "archive.ubuntu.com", "archive.ubuntu.com.evil.test:443", "user@archive.ubuntu.com:443", "https://archive.ubuntu.com:443", "evil.test:80"} {
		if _, err := p.target(context.Background(), target, allowed); err == nil {
			t.Errorf("accepted target %q", target)
		}
	}
	if lookupCalls != 0 {
		t.Fatalf("disallowed target triggered DNS: %d", lookupCalls)
	}
	for _, host := range []string{"archive.ubuntu.com", "ap-southeast-1.ec2.archive.ubuntu.com"} {
		addresses, err := p.target(context.Background(), host+":443", allowed)
		if err != nil || !reflect.DeepEqual(addresses, []string{"185.125.190.83:443"}) {
			t.Fatalf("valid target %s: %v %v", host, addresses, err)
		}
	}
	for _, ip := range []string{"0.0.0.0", "10.0.0.1", "172.22.0.27", "192.168.0.1", "127.0.0.1", "169.254.169.254", "100.100.100.200", "198.18.0.1", "192.0.2.1", "224.0.0.1", "255.255.255.255", "::1", "fc00::1", "fe80::1", "::ffff:172.22.0.27", "64:ff9b::a9fe:a9fe", "2001:db8::1", "2002:a9fe:a9fe::1"} {
		p.lookup = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{public, netip.MustParseAddr(ip)}, nil
		}
		if _, err := p.target(context.Background(), "archive.ubuntu.com:80", allowed); err == nil {
			t.Errorf("accepted mixed DNS response with %s", ip)
		}
	}
	if !publicPackageIP(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Error("ordinary public IPv6 was blocked")
	}
}

func packageControlPeer(t *testing.T, s *Server, endpoint, ip string) (net.Conn, *bufio.Reader, agentConfigFrame) {
	t.Helper()
	if err := s.Store.touchConfigAgent(context.Background(), ip, "relay-agent", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.assignAgentConfig(context.Background(), map[string]bool{ip: true}, "test-ciphertext", strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := writeAgentFrame(conn, agentConfigFrame{Version: 1, Type: "hello", IP: ip, Host: "relay-agent", DownloadRelay: true}); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	identity := receiveConfigFrame(t, conn, reader)
	if identity.Type != "identity" || identity.IP != ip || len(identity.DownloadToken) != 64 {
		t.Fatalf("missing control token: type=%s ip=%s token_length=%d", identity.Type, identity.IP, len(identity.DownloadToken))
	}
	if config := receiveConfigFrame(t, conn, reader); config.Type != "config" {
		t.Fatalf("expected config after identity, got %s", config.Type)
	}
	return conn, reader, identity
}

func packageRequest(t *testing.T, endpoint string, frame agentConfigFrame) agentConfigFrame {
	t.Helper()
	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeAgentFrame(conn, frame); err != nil {
		t.Fatal(err)
	}
	return receiveConfigFrame(t, conn, bufio.NewReader(conn))
}

func enablePackageWindow(t *testing.T, s *Server, duration time.Duration) {
	t.Helper()
	p := s.packages
	p.mu.Lock()
	p.disableLocked()
	p.enableLocked(time.Now().Add(duration))
	p.mu.Unlock()
	t.Cleanup(p.disable)
}

func packageSessionForTest(t *testing.T, endpoint string, identity agentConfigFrame) agentConfigFrame {
	t.Helper()
	response := packageRequest(t, endpoint, agentConfigFrame{Version: 1, Type: "package_session", IP: identity.IP, Token: identity.DownloadToken})
	if response.Type != "package_session" || len(response.Token) != 64 {
		t.Fatalf("session failed: type=%s error=%s", response.Type, response.Error)
	}
	return response
}

func fakePackageUpstream(s *Server) {
	p := s.packages
	p.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("185.125.190.83")}, nil
	}
	p.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "185.125.190.83:443" {
			return nil, &net.AddrError{Err: "unvalidated address", Addr: address}
		}
		local, remote := net.Pipe()
		go func() { defer remote.Close(); _, _ = io.Copy(remote, remote) }()
		return local, nil
	}
}

func packageStreamForTest(t *testing.T, endpoint string, identity, session agentConfigFrame) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	frame := agentConfigFrame{Version: 1, Type: "package_relay", IP: identity.IP, Token: session.Token, Target: "archive.ubuntu.com:443"}
	data, _ := json.Marshal(frame)
	// Raw bytes may be coalesced with the JSON first frame by TCP. Losing bufio's
	// read-ahead would corrupt the very first TLS record or HTTP package request.
	if _, err = conn.Write(append(append(data, '\n'), []byte("buffered-package-bytes")...)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	if response := receiveConfigFrame(t, conn, reader); response.Type != "package_ready" {
		t.Fatalf("relay failed: %s %s", response.Type, response.Error)
	}
	buffer := make([]byte, len("buffered-package-bytes"))
	if _, err := io.ReadFull(reader, buffer); err != nil || string(buffer) != "buffered-package-bytes" {
		t.Fatalf("lost buffered stream bytes: %q %v", buffer, err)
	}
	return conn, reader
}

func TestPackageTCPAuthenticationAndIndependentStreams(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	fakePackageUpstream(s)
	endpoint := startConfigTCP(t, s)
	control, reader, identity := packageControlPeer(t, s, endpoint, "172.22.0.11")
	request := agentConfigFrame{Version: 1, Type: "package_session", IP: identity.IP, Token: identity.DownloadToken}
	if got := packageRequest(t, endpoint, request); got.Type != "error" || !strings.Contains(got.Error, "关闭") {
		t.Fatalf("disabled relay accepted session: %+v", got)
	}
	enablePackageWindow(t, s, time.Minute)
	if _, err := s.Store.DB.Exec(`DELETE FROM agent_config_deliveries WHERE machine_ip=?`, identity.IP); err != nil {
		t.Fatal(err)
	}
	if got := packageRequest(t, endpoint, request); got.Type != "error" || !strings.Contains(got.Error, "尚未") {
		t.Fatal("unassigned Agent authorized a download")
	}
	if err := s.Store.assignAgentConfig(context.Background(), map[string]bool{identity.IP: true}, "test-ciphertext", strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	wrong := request
	wrong.Token = strings.Repeat("0", 64)
	if got := packageRequest(t, endpoint, wrong); got.Type != "error" {
		t.Fatal("invalid control token accepted")
	}
	wrong = request
	wrong.IP = "172.22.0.12"
	if got := packageRequest(t, endpoint, wrong); got.Type != "error" {
		t.Fatal("wrong Agent IP accepted")
	}
	if _, err := s.packageSession(&agentConfigConnection{source: "172.22.0.99"}, request); err == nil {
		t.Fatal("control token replayed from different source")
	}
	session := packageSessionForTest(t, endpoint, identity)
	until, err := time.Parse(time.RFC3339, session.ExpiresAt)
	if err != nil || time.Until(until) > time.Minute {
		t.Fatalf("lease exceeded admin window: %s", session.ExpiresAt)
	}
	relay, _ := packageStreamForTest(t, endpoint, identity, session)
	if err := writeAgentFrame(control, agentConfigFrame{Version: 1, Type: "ping"}); err != nil {
		t.Fatal(err)
	}
	if got := receiveConfigFrame(t, control, reader); got.Type != "pong" {
		t.Fatalf("download blocked config keepalive: %s", got.Type)
	}
	s.packages.mu.Lock()
	status := s.packages.statusLocked()
	s.packages.mu.Unlock()
	if status.ActiveSessions != 1 || status.ActiveConnections != 1 || status.BytesTransferred < int64(2*len("buffered-package-bytes")) {
		t.Fatalf("incorrect accounting: %+v", status)
	}
	_ = relay.Close()
	if got := packageRequest(t, endpoint, agentConfigFrame{Version: 1, Type: "package_relay", IP: identity.IP, Token: identity.DownloadToken, Target: "archive.ubuntu.com:443"}); got.Type != "error" {
		t.Fatal("control token accepted as lease")
	}
	if got := packageRequest(t, endpoint, agentConfigFrame{Version: 1, Type: "package_relay", IP: identity.IP, Token: session.Token, Target: "169.254.169.254:80"}); got.Type != "error" {
		t.Fatal("SSRF accepted through TCP listener")
	}
}

func TestPackageTCPRevocationClosesStreams(t *testing.T) {
	for _, cause := range []string{"admin_disable", "window_expiry", "control_disconnect", "control_replace", "config_change", "agent_done"} {
		t.Run(cause, func(t *testing.T) {
			store, _ := testStore(t)
			s := testServer(store)
			fakePackageUpstream(s)
			endpoint := startConfigTCP(t, s)
			control, _, identity := packageControlPeer(t, s, endpoint, "172.22.0.11")
			enablePackageWindow(t, s, time.Minute)
			session := packageSessionForTest(t, endpoint, identity)
			relay, reader := packageStreamForTest(t, endpoint, identity, session)
			switch cause {
			case "admin_disable":
				cookie := testLogin(t, s, DefaultPassword)
				requireStatus(t, testRequest(t, s, "PUT", packageSettingsPath, map[string]any{"enabled": false}, cookie, nil), 200)
			case "window_expiry":
				p := s.packages
				p.mu.Lock()
				p.timer.Stop()
				p.enableLocked(time.Now().Add(20 * time.Millisecond))
				p.mu.Unlock()
			case "control_disconnect":
				_ = control.Close()
			case "control_replace":
				_, _, _ = packageControlPeer(t, s, endpoint, identity.IP)
			case "config_change":
				cookie := testLogin(t, s, DefaultPassword)
				requireStatus(t, testRequest(t, s, "POST", agentDeliveryPath, map[string]any{"yaml": "server: []\n", "machine_ips": []string{identity.IP}}, cookie, nil), 200)
			case "agent_done":
				got := packageRequest(t, endpoint, agentConfigFrame{Version: 1, Type: "package_close", IP: identity.IP, Token: session.Token})
				if got.Type != "package_closed" {
					t.Fatalf("close failed: %s %s", got.Type, got.Error)
				}
			}
			_ = relay.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := reader.ReadByte(); err == nil {
				t.Fatal("revoked tunnel stayed open")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("revocation failed to close stream proactively")
			}
			if got := packageRequest(t, endpoint, agentConfigFrame{Version: 1, Type: "package_relay", IP: identity.IP, Token: session.Token, Target: "archive.ubuntu.com:443"}); got.Type != "error" {
				t.Fatal("revoked lease reused")
			}
		})
	}
}

func TestPackageLeaseExpiryAndLimits(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	fakePackageUpstream(s)
	endpoint := startConfigTCP(t, s)
	_, _, identity := packageControlPeer(t, s, endpoint, "172.22.0.11")
	enablePackageWindow(t, s, time.Hour)
	session := packageSessionForTest(t, endpoint, identity)
	until, _ := time.Parse(time.RFC3339, session.ExpiresAt)
	if time.Until(until) > packageLeaseDuration {
		t.Fatal("lease longer than maximum")
	}
	p := s.packages
	for _, limit := range []string{"global_connections", "lease_bytes", "lease_expired"} {
		p.mu.Lock()
		lease := p.leases[session.Token]
		switch limit {
		case "global_connections":
			p.connections = packageMaxConnections
		case "lease_bytes":
			p.connections = 0
			lease.bytes = packageMaxLeaseBytes
		case "lease_expired":
			lease.bytes = 0
			lease.expires = time.Now().Add(-time.Second)
		}
		p.mu.Unlock()
		got := packageRequest(t, endpoint, agentConfigFrame{Version: 1, Type: "package_relay", IP: identity.IP, Token: session.Token, Target: "archive.ubuntu.com:443"})
		if got.Type != "error" {
			t.Fatalf("limit %s ignored", limit)
		}
	}
}

func TestPackagePerAgentConcurrencyLimit(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	fakePackageUpstream(s)
	endpoint := startConfigTCP(t, s)
	_, _, identity := packageControlPeer(t, s, endpoint, "172.22.0.11")
	enablePackageWindow(t, s, time.Minute)
	session := packageSessionForTest(t, endpoint, identity)
	for range packageMaxAgentConnections {
		_, _ = packageStreamForTest(t, endpoint, identity, session)
	}
	got := packageRequest(t, endpoint, agentConfigFrame{Version: 1, Type: "package_relay", IP: identity.IP, Token: session.Token, Target: "archive.ubuntu.com:443"})
	if got.Type != "error" || !strings.Contains(got.Error, "上限") {
		t.Fatalf("per-Agent connection limit ignored: type=%s error=%s", got.Type, got.Error)
	}
}

func TestPackageByteQuotaReservesBeforeWriting(t *testing.T) {
	lease := &packageLease{token: "test", expires: time.Now().Add(time.Minute), bytes: packageMaxLeaseBytes - 3}
	p := &packageDownloads{leases: map[string]*packageLease{lease.token: lease}}
	client, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()
	read := make(chan string, 1)
	go func() { data := make([]byte, 3); _, _ = io.ReadFull(upstream, data); read <- string(data) }()
	writer := &packageWriter{p, lease, client, nil}
	if n, err := writer.Write([]byte("abcdef")); n != 3 || err != nil {
		t.Fatalf("quota write: %d %v", n, err)
	}
	if data := <-read; data != "abc" {
		t.Fatalf("wrote beyond quota: %q", data)
	}
	if n, err := writer.Write([]byte("extra")); n != 0 || err == nil {
		t.Fatal("exhausted quota allowed another write")
	}
	if p.bytes != 3 || lease.bytes != packageMaxLeaseBytes {
		t.Fatal("incorrect quota/transfer accounting")
	}
}

func TestPackageSharedIdleDeadlineAllowsContinuousOneWayDownload(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	p := s.packages
	p.idleTimeout = 80 * time.Millisecond
	p.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("185.125.190.83")}, nil
	}
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			defer remote.Close()
			// Only upstream -> Agent sends data. Its opposite copy stays blocked
			// for several idle periods, as it does after an HTTP GET or TLS write.
			for range 15 {
				time.Sleep(20 * time.Millisecond)
				if _, err := remote.Write([]byte("x")); err != nil {
					return
				}
			}
			var buffer [1]byte
			_, _ = remote.Read(buffer[:]) // Keep open until the true idle timeout.
		}()
		return local, nil
	}
	endpoint := startConfigTCP(t, s)
	_, _, identity := packageControlPeer(t, s, endpoint, "172.22.0.11")
	enablePackageWindow(t, s, time.Minute)
	session := packageSessionForTest(t, endpoint, identity)
	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeAgentFrame(conn, agentConfigFrame{Version: 1, Type: "package_relay", IP: identity.IP, Token: session.Token, Target: "archive.ubuntu.com:443"}); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	if response := receiveConfigFrame(t, conn, reader); response.Type != "package_ready" {
		t.Fatalf("relay not ready: %s", response.Type)
	}
	data := make([]byte, 15)
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != strings.Repeat("x", 15) {
		t.Fatalf("active one-way download was interrupted by idle timeout: bytes=%q err=%v", data, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("fully idle stream did not close")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("shared idle timeout did not close stream")
	}
}

func TestLargeAgentFailureAcknowledgementIsStoredWithoutDisconnect(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	ip := "172.22.0.11"
	ctx := context.Background()
	if err := store.touchConfigAgent(ctx, ip, "test", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	revision := strings.Repeat("a", 64)
	if err := store.assignAgentConfig(ctx, map[string]bool{ip: true}, "ciphertext", revision); err != nil {
		t.Fatal(err)
	}
	endpoint := startConfigTCP(t, s)
	conn, reader := configPeer(t, endpoint, ip)
	if frame := receiveConfigFrame(t, conn, reader); frame.Revision != revision {
		t.Fatal("missing assigned config")
	}
	errorText := strings.Repeat("安装失败", 1500)
	if err := writeAgentFrame(conn, agentConfigFrame{Version: 1, Type: "ack", Revision: revision, Error: errorText}); err != nil {
		t.Fatal(err)
	}
	status := waitConfigStatus(t, s, ip, "failed", true)
	if len(status.Error) > 4096 || !utf8.ValidString(status.Error) || !strings.HasSuffix(status.Error, "[truncated]") {
		t.Fatalf("unsafe failure truncation: bytes=%d valid=%t", len(status.Error), utf8.ValidString(status.Error))
	}
	if err := writeAgentFrame(conn, agentConfigFrame{Version: 1, Type: "ping"}); err != nil {
		t.Fatal(err)
	}
	if got := receiveConfigFrame(t, conn, reader); got.Type != "pong" {
		t.Fatal("long failure disconnected configuration connection")
	}
}
