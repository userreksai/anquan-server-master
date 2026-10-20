package server

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const agentUpdatesPath = "/api/settings/agent-updates"

func updateSource(t *testing.T, s *Server) []byte {
	t.Helper()
	dir := t.TempDir()
	s.agentUpdates.sourceDir = dir
	data := make([]byte, 256)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], 2)
	binary.LittleEndian.PutUint16(data[18:], 62)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint16(data[52:], 64)
	if err := os.WriteFile(filepath.Join(dir, "anquan"), data, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	manifest := map[string]any{"version": "0.7.4", "goos": "linux", "goarch": "amd64", "sha256": hex.EncodeToString(sum[:]), "size": len(data)}
	raw, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "anquan.update.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return data
}

func updatePeer(t *testing.T, endpoint, ip, version string, supported bool, extra *agentConfigFrame) (net.Conn, *bufio.Reader, agentConfigFrame) {
	t.Helper()
	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	hello := agentConfigFrame{Version: 1, Type: "hello", IP: ip, Host: "node-update", AgentVersion: version, SelfUpdate: supported, GOOS: "linux", GOARCH: "amd64"}
	if extra != nil {
		hello.UpdateJobID = extra.UpdateJobID
		hello.UpdateBinarySHA256 = extra.UpdateBinarySHA256
		hello.UpdateResult = extra.UpdateResult
	}
	if err := writeAgentFrame(conn, hello); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	var identity agentConfigFrame
	if supported {
		identity = receiveConfigFrame(t, conn, reader)
		if identity.Type != "identity" || identity.UpdatePublicKey == "" {
			t.Fatalf("missing signing identity: %+v", identity)
		}
	}
	if frame := receiveConfigFrame(t, conn, reader); frame.Type != "config" {
		t.Fatalf("expected config: %+v", frame)
	}
	return conn, reader, identity
}

func waitUpdateStatus(t *testing.T, s *Server, ip, status string) agentUpdateItem {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for {
		view, err := s.agentUpdatesView(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range view.Items {
			if item.MachineIP == ip && item.Status == status {
				return item
			}
		}
		if time.Now().After(until) {
			t.Fatalf("status did not become %s: %+v", status, view)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAgentUpdatePackageValidatesManifestAndProducesRestrictedPersistentArchive(t *testing.T) {
	store, dir := testStore(t)
	s := testServer(store)
	data := updateSource(t, s)
	cookie := testLogin(t, s, DefaultPassword)
	requireStatus(t, testRequest(t, s, "GET", agentUpdatesPath, nil, nil, nil), 401)
	requireStatus(t, testRequest(t, s, "POST", agentUpdatesPath+"/package", nil, nil, nil), 401)
	requireStatus(t, testRequest(t, s, "POST", agentUpdatesPath+"/package", map[string]any{"unexpected": true}, cookie, nil), 400)
	requireStatus(t, testRequest(t, s, "POST", agentUpdatesPath+"/package", nil, cookie, map[string]string{"Origin": "https://attacker.test"}), 403)
	view := jsonResult[agentUpdatesView](t, testRequest(t, s, "POST", agentUpdatesPath+"/package", nil, cookie, nil))
	if view.Release == nil || view.Release.Version != "0.7.4" {
		t.Fatalf("missing package: %+v", view)
	}
	f, err := os.Open(filepath.Join(s.agentUpdates.storeDir, view.Release.SHA256+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	tr := tar.NewReader(z)
	header, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	if header.Name != "anquan" || header.Typeflag != tar.TypeReg || header.Mode != 0755 || !bytes.Equal(got, data) {
		t.Fatalf("unsafe archive: %+v", header)
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Fatalf("unexpected additional entry: %v", err)
	}
	key := s.agentUpdates.publicKey()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after := testServer(reopened)
	if after.agentUpdates.publicKey() != key || after.agentUpdates.release == nil || after.agentUpdates.release.SHA256 != view.Release.SHA256 {
		t.Fatal("restart lost signing identity or release")
	}
}

func TestAgentUpdateRejectsTamperedMissingWrongPlatformAndSymlinkSources(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	data := updateSource(t, s)
	path := filepath.Join(s.agentUpdates.sourceDir, "anquan")
	data[200] = 1
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.agentUpdates.buildPackage(context.Background(), store); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("accepted tampered source: %v", err)
	}
	updateSource(t, s)
	path = filepath.Join(s.agentUpdates.sourceDir, "anquan")
	data[200] = 0
	binary.LittleEndian.PutUint16(data[18:], 183)
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.agentUpdates.buildPackage(context.Background(), store); err == nil || !strings.Contains(err.Error(), "ELF") {
		t.Fatalf("accepted wrong ELF platform: %v", err)
	}
	updateSource(t, s)
	manifest := filepath.Join(s.agentUpdates.sourceDir, "anquan.update.json")
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if err := s.agentUpdates.buildPackage(context.Background(), store); err == nil || !strings.Contains(err.Error(), "重新编译") {
		t.Fatalf("missing manifest was accepted: %v", err)
	}
	if _, _, err := regularUpdateFile(s.agentUpdates.sourceDir); err == nil {
		t.Fatal("directory source accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(filepath.Join(s.agentUpdates.sourceDir, "anquan"), link); err == nil {
		if _, _, err := regularUpdateFile(link); err == nil {
			t.Fatal("symlink source accepted")
		}
	}
}

func TestAgentUpdateSelectionIsAtomicAndOnlySupportsNewerMatchingOnlineAgents(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	updateSource(t, s)
	if err := s.agentUpdates.buildPackage(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	endpoint := startConfigTCP(t, s)
	_, _, _ = updatePeer(t, endpoint, "10.0.0.1", "0.7.3", true, nil)
	_, _, _ = updatePeer(t, endpoint, "10.0.0.2", "0.7.2", false, nil)
	digest := s.agentUpdates.release.SHA256
	for _, selected := range [][]string{{"10.0.0.1", "10.0.0.2"}, {"10.0.0.9"}, {"bad"}, {}} {
		if err := s.queueAgentUpdates(context.Background(), selected, digest); err == nil {
			t.Fatalf("accepted invalid selection: %v", selected)
		}
	}
	if countRows(t, store, "agent_update_jobs") != 0 {
		t.Fatal("partial job survived atomic validation")
	}
	if err := s.queueAgentUpdates(context.Background(), []string{"10.0.0.1"}, strings.Repeat("e", 64)); err == nil {
		t.Fatal("accepted stale release digest")
	}
	s.configMu.Lock()
	s.configAgents["10.0.0.1"].goarch = "arm64"
	s.configMu.Unlock()
	if err := s.queueAgentUpdates(context.Background(), []string{"10.0.0.1"}, digest); err == nil {
		t.Fatal("accepted incompatible platform")
	}
	s.configMu.Lock()
	s.configAgents["10.0.0.1"].goarch = "amd64"
	s.configAgents["10.0.0.1"].agentVersion = "0.7.4"
	s.configMu.Unlock()
	if err := s.queueAgentUpdates(context.Background(), []string{"10.0.0.1"}, digest); err == nil {
		t.Fatal("accepted same version")
	}
	for _, pair := range [][2]string{{"0.7.4", "0.7.3"}, {"v1.0.0", "0.99.99"}} {
		if !newerAgentVersion(pair[0], pair[1]) {
			t.Fatalf("version ordering rejected %v", pair)
		}
	}
	for _, pair := range [][2]string{{"0.7.3", "0.7.4"}, {"0.7.4-rc1", "0.7.3"}, {"0.7.4", "unknown"}, {"00.7.4", "0.7.3"}} {
		if newerAgentVersion(pair[0], pair[1]) {
			t.Fatalf("unsafe version ordering %v", pair)
		}
	}
}

func TestAgentUpdateSignedDownloadPreservesControlAndRequiresExactReconnectionProof(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	updateSource(t, s)
	if err := s.agentUpdates.buildPackage(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	endpoint := startConfigTCP(t, s)
	ip := "10.0.0.1"
	control, reader, identity := updatePeer(t, endpoint, ip, "0.7.3", true, nil)
	if err := s.queueAgentUpdates(context.Background(), []string{ip}, s.agentUpdates.release.SHA256); err != nil {
		t.Fatal(err)
	}
	offer := receiveConfigFrame(t, control, reader)
	if offer.Type != "update_offer" || offer.Update == nil {
		t.Fatalf("missing offer: %+v", offer)
	}
	descriptor := *offer.Update
	signature, err := base64.StdEncoding.DecodeString(descriptor.Signature)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Signature = ""
	raw, _ := json.Marshal(descriptor)
	key, _ := base64.StdEncoding.DecodeString(identity.UpdatePublicKey)
	if !ed25519.Verify(ed25519.PublicKey(key), raw, signature) {
		t.Fatal("signature does not match canonical descriptor")
	}
	for _, hello := range []agentConfigFrame{{Version: 1, Type: "update_download", IP: ip, Token: strings.Repeat("f", 64), JobID: descriptor.JobID}, {Version: 1, Type: "update_download", IP: "10.0.0.2", Token: descriptor.Token, JobID: descriptor.JobID}} {
		if response := packageRequest(t, endpoint, hello); response.Type != "error" {
			t.Fatalf("unauthorized download accepted: %+v", response)
		}
	}
	transfer, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer transfer.Close()
	if err := writeAgentFrame(transfer, agentConfigFrame{Version: 1, Type: "update_download", IP: ip, Token: descriptor.Token, JobID: descriptor.JobID}); err != nil {
		t.Fatal(err)
	}
	tr := bufio.NewReader(transfer)
	ready := receiveConfigFrame(t, transfer, tr)
	if ready.Type != "update_ready" || ready.Size != descriptor.Size {
		t.Fatalf("invalid ready: %+v", ready)
	}
	data, err := io.ReadAll(io.LimitReader(tr, ready.Size))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != descriptor.SHA256 {
		t.Fatal("download corrupted")
	}
	if s.packages.enabled {
		t.Fatal("update enabled public software proxy")
	}
	if err := writeAgentFrame(control, agentConfigFrame{Version: 1, Type: "ping"}); err != nil {
		t.Fatal(err)
	}
	if response := receiveConfigFrame(t, control, reader); response.Type != "pong" {
		t.Fatal("update blocked control ping")
	}
	if err := writeAgentFrame(control, agentConfigFrame{Version: 1, Type: "update_status", JobID: descriptor.JobID, Status: "applied"}); err != nil {
		t.Fatal(err)
	}
	waitUpdateStatus(t, s, ip, "downloading")
	if err := writeAgentFrame(control, agentConfigFrame{Version: 1, Type: "update_status", UpdateJobID: descriptor.JobID, UpdateResult: &agentUpdateResult{JobID: descriptor.JobID, Status: "restarting"}}); err != nil {
		t.Fatal(err)
	}
	waitUpdateStatus(t, s, ip, "restarting")
	control.Close()
	wrong, wrongReader, _ := updatePeer(t, endpoint, ip, "0.7.4", true, &agentConfigFrame{UpdateJobID: descriptor.JobID, UpdateBinarySHA256: strings.Repeat("0", 64)})
	resultFrame := agentConfigFrame{Version: 1, Type: "update_result", AgentVersion: "0.7.4", GOOS: "linux", GOARCH: "amd64", UpdateBinarySHA256: descriptor.BinarySHA256, UpdateResult: &agentUpdateResult{JobID: descriptor.JobID, Status: "applied"}}
	if err := writeAgentFrame(wrong, resultFrame); err != nil {
		t.Fatal(err)
	}
	if err := writeAgentFrame(wrong, agentConfigFrame{Version: 1, Type: "ping"}); err != nil {
		t.Fatal(err)
	}
	receiveConfigFrame(t, wrong, wrongReader)
	waitUpdateStatus(t, s, ip, "restarting")
	wrong.Close()
	next, nextReader, _ := updatePeer(t, endpoint, ip, "0.7.4", true, &agentConfigFrame{UpdateJobID: descriptor.JobID, UpdateBinarySHA256: descriptor.BinarySHA256})
	waitUpdateStatus(t, s, ip, "restarting")
	if err := writeAgentFrame(next, resultFrame); err != nil {
		t.Fatal(err)
	}
	applied := waitUpdateStatus(t, s, ip, "applied")
	if applied.CompletedAt == nil {
		t.Fatal("applied result missing completion")
	}
	if err := writeAgentFrame(next, agentConfigFrame{Version: 1, Type: "ping"}); err != nil {
		t.Fatal(err)
	}
	receiveConfigFrame(t, next, nextReader)
}

func TestAgentUpdateExpiryAndMasterRestartNeverClaimSuccess(t *testing.T) {
	store, dir := testStore(t)
	s := testServer(store)
	updateSource(t, s)
	if err := s.agentUpdates.buildPackage(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	endpoint := startConfigTCP(t, s)
	ip := "10.0.0.1"
	control, reader, _ := updatePeer(t, endpoint, ip, "0.7.3", true, nil)
	if err := s.queueAgentUpdates(context.Background(), []string{ip}, s.agentUpdates.release.SHA256); err != nil {
		t.Fatal(err)
	}
	offer := receiveConfigFrame(t, control, reader)
	if _, err := store.DB.Exec(`UPDATE agent_update_jobs SET expires_at=?`, stamp(time.Now().Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	if response := packageRequest(t, endpoint, agentConfigFrame{Version: 1, Type: "update_download", IP: ip, Token: offer.Update.Token, JobID: offer.Update.JobID}); response.Type != "error" {
		t.Fatal("expired download accepted")
	}
	waitUpdateStatus(t, s, ip, "failed")
	if err := s.queueAgentUpdates(context.Background(), []string{ip}, s.agentUpdates.release.SHA256); err != nil {
		t.Fatal(err)
	}
	receiveConfigFrame(t, control, reader)
	// Simulate process restart through a second Store, before orderly socket
	// teardown has an opportunity to write a terminal result.
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after := testServer(reopened)
	view, err := after.agentUpdatesView(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Items) != 1 || view.Items[0].Status != "failed" {
		t.Fatalf("restart claimed update success: %+v", view)
	}
}

func TestAgentUpdateDownloadRejectsWrongSourceBusyStreamsAndCorruptSnapshot(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	updateSource(t, s)
	if err := s.agentUpdates.buildPackage(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	endpoint := startConfigTCP(t, s)
	ip := "10.0.0.1"
	control, reader, _ := updatePeer(t, endpoint, ip, "0.7.3", true, nil)
	if err := s.queueAgentUpdates(context.Background(), []string{ip}, s.agentUpdates.release.SHA256); err != nil {
		t.Fatal(err)
	}
	offer := receiveConfigFrame(t, control, reader)
	hello := agentConfigFrame{Version: 1, Type: "update_download", IP: ip, Token: offer.Update.Token, JobID: offer.Update.JobID}
	s.configMu.Lock()
	owner := s.configAgents[ip]
	owner.source = "127.0.0.2"
	s.configMu.Unlock()
	if frame := packageRequest(t, endpoint, hello); frame.Type != "error" {
		t.Fatal("accepted wrong source")
	}
	s.configMu.Lock()
	owner.source = "127.0.0.1"
	s.configMu.Unlock()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	s.agentUpdates.mu.Lock()
	s.agentUpdates.streams[ip] = left
	s.agentUpdates.mu.Unlock()
	if frame := packageRequest(t, endpoint, hello); frame.Type != "error" {
		t.Fatal("accepted concurrent same-machine stream")
	}
	s.agentUpdates.mu.Lock()
	delete(s.agentUpdates.streams, ip)
	s.agentUpdates.mu.Unlock()
	path := filepath.Join(s.agentUpdates.storeDir, offer.Update.SHA256+".tar.gz")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if frame := packageRequest(t, endpoint, hello); frame.Type != "error" || !strings.Contains(frame.Error, "SHA-256") {
		t.Fatalf("accepted corrupt stored package: %+v", frame)
	}
	// Rebuilding the same content repairs a corrupted snapshot.
	if err = s.agentUpdates.buildPackage(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != offer.Update.SHA256 {
		t.Fatal("rebuild did not repair stored snapshot")
	}
}

func TestAgentUpdateNinthConcurrentDownloadWaitsWithoutRejectingBatch(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	updateSource(t, s)
	if err := s.agentUpdates.buildPackage(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	endpoint := startConfigTCP(t, s)
	var ips []string
	var controls []net.Conn
	var readers []*bufio.Reader
	for i := 1; i <= 9; i++ {
		ip := "10.0.0." + strconv.Itoa(i)
		ips = append(ips, ip)
		control, reader, _ := updatePeer(t, endpoint, ip, "0.7.3", true, nil)
		controls = append(controls, control)
		readers = append(readers, reader)
	}
	if err := s.queueAgentUpdates(context.Background(), ips, s.agentUpdates.release.SHA256); err != nil {
		t.Fatal(err)
	}
	var clients []net.Conn
	var results []chan error
	for i := 0; i < 9; i++ {
		offer := receiveConfigFrame(t, controls[i], readers[i])
		left, right := net.Pipe()
		t.Cleanup(func() { left.Close(); right.Close() })
		clients = append(clients, right)
		result := make(chan error, 1)
		results = append(results, result)
		transfer := &agentConfigConnection{conn: left, source: "127.0.0.1"}
		hello := agentConfigFrame{Version: 1, Type: "update_download", IP: ips[i], Token: offer.Update.Token, JobID: offer.Update.JobID}
		go func() { result <- s.transferAgentUpdate(context.Background(), transfer, hello) }()
		if i < 8 {
			until := time.Now().Add(3 * time.Second)
			for {
				s.agentUpdates.mu.Lock()
				count := len(s.agentUpdates.streams)
				s.agentUpdates.mu.Unlock()
				if count == i+1 {
					break
				}
				if time.Now().After(until) {
					t.Fatal("initial streams did not start")
				}
				time.Sleep(time.Millisecond)
			}
		}
	}
	select {
	case err := <-results[8]:
		t.Fatalf("ninth download rejected immediately: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	// Releasing any active stream makes room for the waiting authorized peer.
	for i := 0; i < 9; i++ {
		reader := bufio.NewReader(clients[i])
		frame := receiveConfigFrame(t, clients[i], reader)
		if frame.Type != "update_ready" {
			t.Fatalf("unexpected transfer response: %+v", frame)
		}
		if _, err := io.CopyN(io.Discard, reader, frame.Size); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-results[i]:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("queued transfer did not complete")
		}
	}
}

func TestAgentUpdateSlotQueueCancelsOnPeerDisconnectContextAndExpiry(t *testing.T) {
	for _, reason := range []string{"peer", "context", "expiry"} {
		t.Run(reason, func(t *testing.T) {
			u := newAgentUpdates(nil, nil)
			for i := 0; i < 8; i++ {
				u.slots <- struct{}{}
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			deadline := time.Now().Add(time.Second)
			if reason == "expiry" {
				deadline = time.Now().Add(25 * time.Millisecond)
			}
			done := make(chan error, 1)
			go func() { done <- u.waitForSlot(ctx, left, deadline) }()
			if reason == "peer" {
				right.Close()
			}
			if reason == "context" {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled queued transfer was authorized")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("queue did not cancel")
			}
			if len(u.slots) != 8 {
				t.Fatal("cancelled waiter consumed a slot")
			}
		})
	}
}

func TestAgentUpdatePrefixedVersionIsNormalizedAndOldSnapshotsStayForActiveJobs(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	updateSource(t, s)
	manifest := filepath.Join(s.agentUpdates.sourceDir, "anquan.update.json")
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"version":"0.7.4"`), []byte(`"version":"v0.7.4"`), 1)
	if err = os.WriteFile(manifest, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.agentUpdates.buildPackage(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if s.agentUpdates.release.Version != "0.7.4" {
		t.Fatalf("version prefix not normalized: %s", s.agentUpdates.release.Version)
	}
	oldDigest := s.agentUpdates.release.SHA256
	oldPath := filepath.Join(s.agentUpdates.storeDir, oldDigest+".tar.gz")
	endpoint := startConfigTCP(t, s)
	control, reader, _ := updatePeer(t, endpoint, "10.0.0.1", "0.7.3", true, nil)
	if err = s.queueAgentUpdates(context.Background(), []string{"10.0.0.1"}, oldDigest); err != nil {
		t.Fatal(err)
	}
	receiveConfigFrame(t, control, reader)
	// Build another valid binary/release while the first is still authorized.
	binaryPath := filepath.Join(s.agentUpdates.sourceDir, "anquan")
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] = 7
	if err = os.WriteFile(binaryPath, data, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	next, _ := json.Marshal(map[string]any{"version": "0.7.5", "goos": "linux", "goarch": "amd64", "sha256": hex.EncodeToString(sum[:]), "size": len(data)})
	if err = os.WriteFile(manifest, next, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.agentUpdates.buildPackage(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(oldPath); err != nil {
		t.Fatal("active job lost old snapshot")
	}
	if err = writeAgentFrame(control, agentConfigFrame{Version: 1, Type: "update_status", UpdateJobID: waitUpdateStatus(t, s, "10.0.0.1", "pending").JobID, UpdateResult: &agentUpdateResult{JobID: waitUpdateStatus(t, s, "10.0.0.1", "pending").JobID, Status: "failed", Error: "cancelled"}}); err != nil {
		t.Fatal(err)
	}
	waitUpdateStatus(t, s, "10.0.0.1", "failed")
	if err = s.agentUpdates.buildPackage(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("unused snapshot not removed: %v", err)
	}
}

func TestAgentUpdateRecoveryReportsRollbackAndFailureWithoutSuccess(t *testing.T) {
	for _, status := range []string{"rolled_back", "failed"} {
		t.Run(status, func(t *testing.T) {
			store, _ := testStore(t)
			s := testServer(store)
			updateSource(t, s)
			if err := s.agentUpdates.buildPackage(context.Background(), store); err != nil {
				t.Fatal(err)
			}
			endpoint := startConfigTCP(t, s)
			ip := "10.0.0.1"
			control, reader, _ := updatePeer(t, endpoint, ip, "0.7.3", true, nil)
			if err := s.queueAgentUpdates(context.Background(), []string{ip}, s.agentUpdates.release.SHA256); err != nil {
				t.Fatal(err)
			}
			offer := receiveConfigFrame(t, control, reader)
			if err := writeAgentFrame(control, agentConfigFrame{Version: 1, Type: "update_status", UpdateJobID: offer.Update.JobID, UpdateResult: &agentUpdateResult{JobID: offer.Update.JobID, Status: "restarting"}}); err != nil {
				t.Fatal(err)
			}
			waitUpdateStatus(t, s, ip, "restarting")
			control.Close()
			_, _, _ = updatePeer(t, endpoint, ip, "0.7.3", true, &agentConfigFrame{UpdateJobID: offer.Update.JobID, UpdateBinarySHA256: strings.Repeat("a", 64), UpdateResult: &agentUpdateResult{JobID: offer.Update.JobID, Status: status, Error: "health check failed"}})
			result := waitUpdateStatus(t, s, ip, status)
			if result.Error != "health check failed" || result.CompletedAt == nil {
				t.Fatalf("recovery evidence lost: %+v", result)
			}
		})
	}
}
