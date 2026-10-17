package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"filippo.io/age/armor"
)

const agentDeliveryPath = "/api/settings/agent-config-deliveries"

func startConfigTCP(t *testing.T, s *Server) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.ServeAgentTCP(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("TCP receiver did not close connections on cancellation")
		}
	})
	return listener.Addr().String()
}

func configPeer(t *testing.T, endpoint, ip string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := writeAgentFrame(conn, agentConfigFrame{Version: 1, Type: "hello", IP: ip, Host: "node-a", AgentVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	return conn, bufio.NewReader(conn)
}

func receiveConfigFrame(t *testing.T, conn net.Conn, reader *bufio.Reader) agentConfigFrame {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	frame, err := readAgentFrame(reader, maxAgentTCPFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func waitConfigStatus(t *testing.T, s *Server, ip, status string, connected bool) AgentConfigDelivery {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		result, err := s.agentConfigDeliveries(context.Background(), map[string]bool{ip: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Items) == 1 && result.Items[0].Status == status && result.Items[0].Connected == connected {
			return result.Items[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivery %s did not become %s connected=%t: %+v", ip, status, connected, result)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAgentDeliveryHTTPValidatesAndPersistsAtomicSelection(t *testing.T) {
	store, dir := testStore(t)
	s := testServer(store)
	config := "# 保留注释\nserver: []\n"
	body := map[string]any{"yaml": config, "machine_ips": []string{"10.0.0.1"}}
	requireStatus(t, testRequest(t, s, "GET", agentDeliveryPath, nil, nil, nil), 401)
	requireStatus(t, testRequest(t, s, "POST", agentDeliveryPath, body, nil, nil), 401)
	cookie := testLogin(t, s, DefaultPassword)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		requireIngest(t, store, testPacket(t, ip, "heartbeat", ip, time.Now(), map[string]int{"interval_seconds": 30}), "127.0.0.1", true)
	}
	initial := jsonResult[agentDeliveryResult](t, testRequest(t, s, "GET", agentDeliveryPath, nil, cookie, nil))
	if len(initial.Items) != 2 || initial.Items[0].Status != "unassigned" || initial.Items[0].UpdatedAt != nil {
		t.Fatalf("unexpected initial deliveries: %+v", initial)
	}
	requireStatus(t, testRequest(t, s, "POST", agentDeliveryPath, body, cookie, map[string]string{"Origin": "https://other.test"}), 403)
	for _, ips := range [][]string{nil, {}, {"invalid"}, {"10.0.0.1", "10.0.0.9"}} {
		body["machine_ips"] = ips
		requireStatus(t, testRequest(t, s, "POST", agentDeliveryPath, body, cookie, nil), 400)
		if countRows(t, store, "agent_config_deliveries") != 0 {
			t.Fatal("invalid batch partially persisted")
		}
	}
	body["machine_ips"] = []string{"10.0.0.2", "10.0.0.1", "::ffff:10.0.0.1"}
	for _, config := range []string{"", "scalar", "a: 1\na: 2", "a: 1\n---\nb: 2", strings.Repeat("x", maxAgentYAMLBytes+1)} {
		body["yaml"] = config
		requireStatus(t, testRequest(t, s, "POST", agentDeliveryPath, body, cookie, nil), 400)
	}
	body["yaml"] = config
	w := testRequest(t, s, "POST", agentDeliveryPath, body, cookie, nil)
	requireStatus(t, w, 200)
	if strings.Contains(w.Body.String(), "ciphertext") || strings.Contains(w.Body.String(), "server:") {
		t.Fatal("configuration content exposed in delivery metadata")
	}
	result := jsonResult[agentDeliveryResult](t, w)
	if len(result.Items) != 2 || result.Items[0].Revision != result.Items[1].Revision || result.Items[0].Status != "pending" || result.Items[0].Connected {
		t.Fatalf("deduplicated batch mismatch: %+v", result)
	}
	var ciphertext string
	if err := store.DB.QueryRow(`SELECT ciphertext FROM agent_config_deliveries WHERE machine_ip='10.0.0.1'`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(ciphertext))
	if result.Items[0].Revision != hex.EncodeToString(sum[:]) || strings.Contains(ciphertext, "server:") {
		t.Fatal("revision or encryption mismatch")
	}
	data, err := io.ReadAll(armor.NewReader(strings.NewReader(ciphertext)))
	if err != nil || !strings.HasPrefix(string(data), "age-encryption.org/v1\n") {
		t.Fatalf("invalid age ciphertext: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reloaded := jsonResult[agentDeliveryResult](t, testRequest(t, testServer(reopened), "GET", agentDeliveryPath, nil, cookie, nil))
	if len(reloaded.Items) != 2 || reloaded.Items[0].Revision != result.Items[0].Revision || reloaded.Items[0].Status != "pending" {
		t.Fatal("queued assignments did not survive restart")
	}
}

func TestAgentTCPPushAckFailureStaleAckReconnectAndDeletion(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	endpoint := startConfigTCP(t, s)
	conn, reader := configPeer(t, endpoint, "10.0.0.1")
	initial := receiveConfigFrame(t, conn, reader)
	if initial.Type != "config" || initial.Revision != "" || initial.Ciphertext != "" {
		t.Fatalf("unknown assignment must send explicit empty config: %+v", initial)
	}
	waitConfigStatus(t, s, "10.0.0.1", "unassigned", true)
	cookie := testLogin(t, s, DefaultPassword)
	deliver := func(yaml string) agentConfigFrame {
		t.Helper()
		w := testRequest(t, s, "POST", agentDeliveryPath, map[string]any{"yaml": yaml, "machine_ips": []string{"10.0.0.1"}}, cookie, nil)
		requireStatus(t, w, 200)
		frame := receiveConfigFrame(t, conn, reader)
		if frame.Type != "config" || frame.Revision == "" || frame.Ciphertext == "" {
			t.Fatalf("invalid push: %+v", frame)
		}
		return frame
	}
	first := deliver("server: []\n")
	if err := writeAgentFrame(conn, agentConfigFrame{Version: 1, Type: "ack", Revision: first.Revision}); err != nil {
		t.Fatal(err)
	}
	item := waitConfigStatus(t, s, "10.0.0.1", "applied", true)
	if item.AppliedAt == nil || item.Error != "" {
		t.Fatal("successful ACK timestamp missing")
	}
	second := deliver("server: []\ninterval: 60\n")
	if second.Revision == first.Revision {
		t.Fatal("revisions reused")
	}
	for _, frame := range []agentConfigFrame{
		{Version: 1, Type: "ack", Revision: first.Revision},
		{Version: 1, Type: "ping"},
	} {
		if err := writeAgentFrame(conn, frame); err != nil {
			t.Fatal(err)
		}
	}
	if pong := receiveConfigFrame(t, conn, reader); pong.Type != "pong" {
		t.Fatal("missing heartbeat response")
	}
	item = waitConfigStatus(t, s, "10.0.0.1", "pending", true)
	if item.AppliedAt != nil || item.Revision != second.Revision {
		t.Fatal("stale ACK applied new revision")
	}
	if err := writeAgentFrame(conn, agentConfigFrame{Version: 1, Type: "ack", Revision: second.Revision, Error: "invalid target path"}); err != nil {
		t.Fatal(err)
	}
	item = waitConfigStatus(t, s, "10.0.0.1", "failed", true)
	if item.Error != "invalid target path" || item.AppliedAt != nil {
		t.Fatal("failed ACK not persisted")
	}
	_ = conn.Close()
	waitConfigStatus(t, s, "10.0.0.1", "failed", false)
	conn, reader = configPeer(t, endpoint, "10.0.0.1")
	retry := receiveConfigFrame(t, conn, reader)
	if retry.Revision != second.Revision || retry.Ciphertext != second.Ciphertext {
		t.Fatal("reconnection did not retry persisted assignment")
	}
	waitConfigStatus(t, s, "10.0.0.1", "pending", true)
	if err := writeAgentFrame(conn, agentConfigFrame{Version: 1, Type: "ack", Revision: retry.Revision}); err != nil {
		t.Fatal(err)
	}
	waitConfigStatus(t, s, "10.0.0.1", "applied", true)
	requireStatus(t, testRequest(t, s, "DELETE", "/api/machines/10.0.0.1", nil, cookie, nil), 200)
	if countRows(t, store, "agent_config_deliveries") != 0 {
		t.Fatal("machine deletion retained config")
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := readAgentFrame(reader, 65536); err == nil {
		t.Fatal("deleted machine connection remained open")
	}
}

func TestAgentTCPRejectsInvalidAndOversizedHello(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	endpoint := startConfigTCP(t, s)
	for _, payload := range []string{
		`{"version":2,"type":"hello","ip":"10.0.0.1","host":"node"}` + "\n",
		`{"version":1,"type":"ping"}` + "\n",
		`{"version":1,"type":"hello","ip":"invalid","host":"node"}` + "\n",
		`{"version":1,"type":"hello","ip":"10.0.0.1","host":""}` + "\n",
		strings.Repeat("x", 4097),
	} {
		conn, err := net.Dial("tcp", endpoint)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.WriteString(conn, payload)
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("invalid hello accepted")
		}
		_ = conn.Close()
	}
	if countRows(t, store, "machines") != 0 {
		t.Fatal("invalid hello registered a machine")
	}
}

func TestAgentTCPReplacementCannotAcknowledgeOrResetNewConnection(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	endpoint := startConfigTCP(t, s)
	first, firstReader := configPeer(t, endpoint, "10.0.0.1")
	receiveConfigFrame(t, first, firstReader)
	cookie := testLogin(t, s, DefaultPassword)
	requireStatus(t, testRequest(t, s, "POST", agentDeliveryPath,
		map[string]any{"yaml": "server: []\n", "machine_ips": []string{"10.0.0.1"}}, cookie, nil), 200)
	frame := receiveConfigFrame(t, first, firstReader)
	s.configMu.Lock()
	previous := s.configAgents["10.0.0.1"]
	s.configMu.Unlock()
	second, secondReader := configPeer(t, endpoint, "10.0.0.1")
	currentFrame := receiveConfigFrame(t, second, secondReader)
	if currentFrame.Revision != frame.Revision {
		t.Fatal("replacement connection did not receive current revision")
	}
	_ = first.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("replaced connection was not closed")
	}
	if err := writeAgentFrame(second, agentConfigFrame{Version: 1, Type: "ack", Revision: currentFrame.Revision}); err != nil {
		t.Fatal(err)
	}
	waitConfigStatus(t, s, "10.0.0.1", "applied", true)
	// A frame already decoded on the replaced connection can finish after the
	// new connection applied the same revision. It must not alter that result.
	if err := s.ackAgentConfig(context.Background(), previous,
		agentConfigFrame{Version: 1, Type: "ack", Revision: frame.Revision, Error: "stale failure"}); err != nil {
		t.Fatal(err)
	}
	if err := s.sendCurrentAgentConfig(context.Background(), previous); err == nil {
		t.Fatal("replaced writer could reset the current delivery to pending")
	}
	item := waitConfigStatus(t, s, "10.0.0.1", "applied", true)
	if item.Error != "" {
		t.Fatal("replaced ACK overwrote the active connection")
	}
}

func TestAgentTCPShutdownClosesConnectedAndHandshakingPeers(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeAgentTCP(ctx, listener) }()
	established, reader := configPeer(t, listener.Addr().String(), "10.0.0.1")
	receiveConfigFrame(t, established, reader)
	partial, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer partial.Close()
	_, _ = io.WriteString(partial, `{"version":1`)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown waited for peer handshake timeout")
	}
	for _, conn := range []net.Conn{established, partial} {
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("shutdown retained an open peer")
		}
	}
}

func TestAgentTCPFrameBoundFitsMaximumYAMLAndExplicitEmptyAssignment(t *testing.T) {
	config := "#" + strings.Repeat("x", maxAgentYAMLBytes-7) + "\na: 1\n"
	if len(config) != maxAgentYAMLBytes || validateAgentYAML(config) != nil {
		t.Fatal("test configuration limit mismatch")
	}
	ciphertext, err := encryptedAgentYAML(config)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	written := make(chan error, 1)
	go func() {
		written <- writeAgentFrame(left, agentConfigFrame{Version: 1, Type: "config", Revision: strings.Repeat("a", 64), Ciphertext: ciphertext})
	}()
	_ = right.SetReadDeadline(time.Now().Add(5 * time.Second))
	frame, err := readAgentFrame(bufio.NewReader(right), maxAgentTCPFrameBytes)
	if err != nil || frame.Ciphertext != ciphertext {
		t.Fatalf("maximum config does not fit protocol frame: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	go func() { written <- writeAgentFrame(left, agentConfigFrame{Version: 1, Type: "config"}) }()
	data, err := bufio.NewReader(right).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || string(fields["revision"]) != `""` || string(fields["ciphertext"]) != `""` {
		t.Fatalf("empty assignment omitted fallback fields: %s", data)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestV5MigrationAddsConfigAssignmentsWithoutLosingData(t *testing.T) {
	store, dir := testStore(t)
	requireIngest(t, store, testPacket(t, "saved", "alert", "10.0.0.1", time.Now(), testAlert()), "127.0.0.1", true)
	if _, err := store.DB.Exec(`DROP TABLE agent_config_deliveries; PRAGMA user_version=5;`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var version int
	if err := reopened.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 9 {
		t.Fatalf("migration version=%d err=%v", version, err)
	}
	if countRows(t, reopened, "machines") != 1 || countRows(t, reopened, "events") != 1 || countRows(t, reopened, "agent_config_deliveries") != 0 {
		t.Fatal("v5 migration did not preserve existing data")
	}
}
