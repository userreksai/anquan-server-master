package server

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"
)

type observedSourceConn struct{ net.Conn }

func (c observedSourceConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("49.7.214.217"), Port: 32123}
}

func TestAutomaticDiscoveryRegistersNATSourceAndReturnsIdentityBeforeConfig(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	left, right := net.Pipe()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agent := &agentConfigConnection{conn: observedSourceConn{left}, updates: make(chan struct{}, 1), done: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); s.serveConfigAgent(ctx, agent) }()
	defer func() {
		cancel()
		_ = right.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("discovery connection did not stop")
		}
	}()
	// Preserve the older discovery protocol: a stale claimed private IP must
	// not override the observed source when discovery is explicitly requested.
	if err := writeAgentFrame(right, agentConfigFrame{Version: 1, Type: "hello", DiscoverIP: true, IP: "10.0.0.28", Host: "boce"}); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(right)
	identity := receiveConfigFrame(t, right, reader)
	if identity.Type != "identity" || identity.IP != "49.7.214.217" {
		t.Fatalf("NAT source not returned first: %+v", identity)
	}
	if config := receiveConfigFrame(t, right, reader); config.Type != "config" {
		t.Fatal("discovery blocked configuration delivery")
	}
	waitConfigStatus(t, s, "49.7.214.217", "unassigned", true)
	var count int
	if err := store.DB.QueryRow(`SELECT COUNT(*) FROM machines WHERE ip='10.0.0.28'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("discovery registered the stale private IP")
	}
}

type relaySourceConn struct{ net.Conn }

func (c relaySourceConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("172.22.240.6"), Port: 32123}
}

func reportedLocalPeer(t *testing.T, s *Server, hello agentConfigFrame, expectedIP string) (net.Conn, *bufio.Reader) {
	t.Helper()
	left, right := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	agent := &agentConfigConnection{conn: relaySourceConn{left}, updates: make(chan struct{}, 1), done: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); s.serveConfigAgent(ctx, agent) }()
	t.Cleanup(func() {
		cancel()
		_ = right.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("reported identity connection did not stop")
		}
	})
	if err := writeAgentFrame(right, hello); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(right)
	identity := receiveConfigFrame(t, right, reader)
	if identity.Type != "identity" || identity.IP != expectedIP {
		t.Fatalf("reported identity not confirmed before config: %+v", identity)
	}
	if config := receiveConfigFrame(t, right, reader); config.Type != "config" || config.Revision != "" {
		t.Fatalf("unexpected initial assignment: %+v", config)
	}
	waitConfigStatus(t, s, expectedIP, "unassigned", true)
	return right, reader
}

func TestReportedLocalIPsKeepAgentsBehindOneRelaySeparate(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	firstIP, secondIP := "172.22.0.27", "172.22.0.28"
	first, firstReader := reportedLocalPeer(t, s, agentConfigFrame{
		Version: 1, Type: "hello", IP: firstIP, ReportedIP: firstIP, Host: "ip-172-22-0-27",
	}, firstIP)
	second, secondReader := reportedLocalPeer(t, s, agentConfigFrame{
		Version: 1, Type: "hello", IP: secondIP, ReportedIP: secondIP, Host: "ip-172-22-0-28",
	}, secondIP)
	for _, ip := range []string{firstIP, secondIP} {
		machine, err := store.Machine(context.Background(), ip)
		if err != nil || machine.SourceIP != "172.22.240.6" || machine.ReportedIP != ip {
			t.Fatalf("local identity lost relay source: %+v %v", machine, err)
		}
		waitConfigStatus(t, s, ip, "unassigned", true)
	}
	if countRows(t, store, "machines") != 2 {
		t.Fatal("shared relay merged agents or registered a relay identity")
	}
	cookie := testLogin(t, s, DefaultPassword)
	deliver := func(ip, yaml string, conn net.Conn, reader *bufio.Reader) agentConfigFrame {
		t.Helper()
		requireStatus(t, testRequest(t, s, "POST", agentDeliveryPath,
			map[string]any{"yaml": yaml, "machine_ips": []string{ip}}, cookie, nil), 200)
		config := receiveConfigFrame(t, conn, reader)
		if config.Type != "config" || config.Revision == "" || config.Ciphertext == "" {
			t.Fatalf("missing independent assignment for %s: %+v", ip, config)
		}
		return config
	}
	firstConfig := deliver(firstIP, "server: []\n", first, firstReader)
	// The second connection must still be alive and must not receive the first
	// node's update. A ping also makes an accidental extra config observable.
	if err := writeAgentFrame(second, agentConfigFrame{Version: 1, Type: "ping"}); err != nil {
		t.Fatal(err)
	}
	if pong := receiveConfigFrame(t, second, secondReader); pong.Type != "pong" {
		t.Fatalf("one relay routed an assignment to the other node: %+v", pong)
	}
	secondConfig := deliver(secondIP, "server: []\ninterval: 60\n", second, secondReader)
	if firstConfig.Revision == secondConfig.Revision {
		t.Fatal("independent configurations reused one revision")
	}
	if err := writeAgentFrame(first, agentConfigFrame{Version: 1, Type: "ack", Revision: firstConfig.Revision}); err != nil {
		t.Fatal(err)
	}
	waitConfigStatus(t, s, firstIP, "applied", true)
	waitConfigStatus(t, s, secondIP, "pending", true)
	if err := writeAgentFrame(second, agentConfigFrame{Version: 1, Type: "ack", Revision: secondConfig.Revision}); err != nil {
		t.Fatal(err)
	}
	waitConfigStatus(t, s, secondIP, "applied", true)
	waitConfigStatus(t, s, firstIP, "applied", true)
	for _, ip := range []string{firstIP, secondIP} {
		requireIngest(t, store, testPacket(t, "heartbeat", "heartbeat", ip, time.Now(), map[string]int{"interval_seconds": 30}), "172.22.240.6", true)
		requireIngest(t, store, testPacket(t, "same-event-id", "alert", ip, time.Now(), testAlert()), "172.22.240.6", true)
		machine, err := store.Machine(context.Background(), ip)
		if err != nil || machine.SourceIP != "172.22.240.6" || machine.ReportedIP != ip || machine.EventCount != 1 {
			t.Fatalf("UDP did not retain independent local identity: %+v %v", machine, err)
		}
	}
	if countRows(t, store, "machines") != 2 || countRows(t, store, "events") != 2 {
		t.Fatal("UDP reports merged agents behind the relay")
	}
}

func TestReportedLocalIPCanonicalization(t *testing.T) {
	for _, test := range []struct{ name, ip, reported, expected string }{
		{"mapped reported", "172.22.0.27", "::ffff:172.22.0.27", "172.22.0.27"},
		{"mapped legacy", "::ffff:172.22.0.27", "172.22.0.27", "172.22.0.27"},
		{"reported only", "", "172.22.0.27", "172.22.0.27"},
		{"IPv6", "2001:0db8::27", "2001:db8::27", "2001:db8::27"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, _ := testStore(t)
			s := testServer(store)
			reportedLocalPeer(t, s, agentConfigFrame{
				Version: 1, Type: "hello", IP: test.ip, ReportedIP: test.reported, Host: "node",
			}, test.expected)
			machine, err := store.Machine(context.Background(), test.expected)
			if err != nil || machine.ReportedIP != test.expected || machine.SourceIP != "172.22.240.6" {
				t.Fatalf("canonical identity mismatch: %+v %v", machine, err)
			}
		})
	}
}

func TestInvalidReportedLocalIPCannotRegisterOrFallBackToRelay(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	endpoint := startConfigTCP(t, s)
	var cases []agentConfigFrame
	for _, ip := range []string{
		"invalid", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255",
		"127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.1.2", "fe80::27", "fe80::27%eth0",
	} {
		cases = append(cases, agentConfigFrame{Version: 1, Type: "hello", IP: ip, ReportedIP: ip, Host: "node"})
	}
	cases = append(cases,
		agentConfigFrame{Version: 1, Type: "hello", IP: "172.22.0.28", ReportedIP: "172.22.0.27", Host: "node"},
		agentConfigFrame{Version: 1, Type: "hello", IP: "invalid", ReportedIP: "172.22.0.27", Host: "node"},
		agentConfigFrame{Version: 1, Type: "hello", IP: "172.22.0.27", ReportedIP: "172.22.0.27", DiscoverIP: true, Host: "node"},
	)
	for _, hello := range cases {
		conn, err := net.Dial("tcp", endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeAgentFrame(conn, hello); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Errorf("invalid reported local identity accepted: %+v", hello)
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Errorf("invalid reported local identity remained open: %+v", hello)
		}
		_ = conn.Close()
	}
	if countRows(t, store, "machines") != 0 {
		t.Fatal("invalid reported identity registered a machine or fell back to relay")
	}
}
