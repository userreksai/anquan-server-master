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
	// Even a stale claimed private IP cannot override the observed source when
	// the new Agent requests automatic identity discovery.
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
