package server

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxAgentUpdateBytes = 256 << 20
const maxAgentUpdateArchiveBytes = 128 << 20
const agentUpdateTTL = 10 * time.Minute

// This order is part of the signed wire protocol. Never add omitempty or sign
// a map: Agent re-encodes these same fields before verifying the signature.
type agentUpdateDescriptor struct {
	JobID        string `json:"job_id"`
	Version      string `json:"version"`
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	BinarySHA256 string `json:"binary_sha256"`
	BinarySize   int64  `json:"binary_size"`
	ExpiresAt    string `json:"expires_at"`
	Token        string `json:"token"`
	Signature    string `json:"signature,omitempty"`
}

type agentUpdateResult struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type agentUpdateRelease struct {
	Version      string    `json:"version"`
	GOOS         string    `json:"goos"`
	GOARCH       string    `json:"goarch"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	BinarySHA256 string    `json:"binary_sha256"`
	BinarySize   int64     `json:"binary_size"`
	CreatedAt    time.Time `json:"created_at"`
}

type agentUpdateItem struct {
	MachineIP     string     `json:"machine_ip"`
	Host          string     `json:"host"`
	Alias         string     `json:"alias"`
	Connected     bool       `json:"connected"`
	Supported     bool       `json:"supported"`
	AgentVersion  string     `json:"agent_version"`
	GOOS          string     `json:"goos"`
	GOARCH        string     `json:"goarch"`
	JobID         string     `json:"job_id"`
	TargetVersion string     `json:"target_version"`
	Status        string     `json:"status"`
	Error         string     `json:"error"`
	UpdatedAt     *time.Time `json:"updated_at"`
	CompletedAt   *time.Time `json:"completed_at"`
}

type agentUpdatesView struct {
	SourceDir   string              `json:"source_dir"`
	Release     *agentUpdateRelease `json:"release"`
	SourceError string              `json:"source_error"`
	Items       []agentUpdateItem   `json:"items"`
}

type agentUpdates struct {
	mu        sync.Mutex
	sourceDir string
	storeDir  string
	key       ed25519.PrivateKey
	release   *agentUpdateRelease
	err       string
	owners    map[string]*agentConfigConnection
	streams   map[string]net.Conn
	slots     chan struct{}
	waiting   map[string]map[net.Conn]struct{}
}

func newAgentUpdates(store *Store, logger *slog.Logger) *agentUpdates {
	u := &agentUpdates{sourceDir: os.Getenv("ANQUAN_AGENT_DIST_DIR"), owners: map[string]*agentConfigConnection{}, streams: map[string]net.Conn{}, slots: make(chan struct{}, 8), waiting: map[string]map[net.Conn]struct{}{}}
	if u.sourceDir == "" {
		u.sourceDir = "/usr/local/anquan-agent/dist"
	}
	if store == nil {
		return u
	}
	u.storeDir = filepath.Join(store.DataDir, "agent-updates")
	var key []byte
	var release string
	err := store.DB.QueryRow(`SELECT signing_key,release_json FROM agent_update_state WHERE id=1`).Scan(&key, &release)
	if errors.Is(err, sql.ErrNoRows) {
		_, u.key, err = ed25519.GenerateKey(rand.Reader)
		if err == nil {
			_, err = store.DB.Exec(`INSERT INTO agent_update_state(id,signing_key) VALUES(1,?)`, []byte(u.key))
		}
	} else if err == nil {
		if len(key) != ed25519.PrivateKeySize {
			err = errors.New("invalid stored update signing key")
		} else {
			u.key = ed25519.PrivateKey(key)
		}
		if err == nil && release != "" {
			var saved agentUpdateRelease
			if err = json.Unmarshal([]byte(release), &saved); err == nil {
				u.release = &saved
			}
		}
	}
	if err == nil {
		err = os.MkdirAll(u.storeDir, 0700)
	}
	if err == nil {
		// A restarted Master has no authenticated owner for transfers in flight.
		// A restarting job may still be confirmed by the new binary and its journal.
		_, err = store.DB.Exec(`UPDATE agent_update_jobs SET status='failed',error='主控重启，原下载授权已失效，请重新下发',updated_at=?,completed_at=? WHERE status IN ('pending','downloading')`, stamp(time.Now()), stamp(time.Now()))
	}
	if err != nil {
		u.err = "Agent 更新初始化失败：" + err.Error()
		if logger != nil {
			logger.Error("initialize agent updates", "error", err)
		}
	}
	return u
}

func (u *agentUpdates) publicKey() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.key) != ed25519.PrivateKeySize || u.err != "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString(u.key.Public().(ed25519.PublicKey))
}

var agentReleaseVersion = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func parseAgentVersion(value string) ([3]uint64, bool) {
	var result [3]uint64
	matches := agentReleaseVersion.FindStringSubmatch(value)
	if matches == nil {
		return result, false
	}
	for i := range result {
		v, err := strconv.ParseUint(matches[i+1], 10, 64)
		if err != nil {
			return result, false
		}
		result[i] = v
	}
	return result, true
}

func newerAgentVersion(next, current string) bool {
	n, ok := parseAgentVersion(next)
	if !ok {
		return false
	}
	c, ok := parseAgentVersion(current)
	if !ok {
		return false
	}
	for i := range n {
		if n[i] != c[i] {
			return n[i] > c[i]
		}
	}
	return false
}

func regularUpdateFile(path string) (*os.File, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return nil, nil, errors.New("发布文件必须是非空普通文件，不能使用符号链接")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		f.Close()
		return nil, nil, errors.New("发布文件在读取时被替换，请重新打包")
	}
	return f, actual, nil
}

func (u *agentUpdates) buildPackage(ctx context.Context, store *Store) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.err != "" {
		return errors.New(u.err)
	}
	manifest, _, err := regularUpdateFile(filepath.Join(u.sourceDir, "anquan.update.json"))
	if err != nil {
		return fmt.Errorf("缺少可读取的 anquan.update.json，请使用新版 anqu-build 重新编译：%w", err)
	}
	defer manifest.Close()
	var source struct {
		Version string `json:"version"`
		GOOS    string `json:"goos"`
		GOARCH  string `json:"goarch"`
		SHA256  string `json:"sha256"`
		Size    int64  `json:"size"`
	}
	decoder := json.NewDecoder(io.LimitReader(manifest, 8193))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&source); err != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("发布清单无效，请使用新版 anqu-build 重新编译")
	}
	if _, ok := parseAgentVersion(source.Version); !ok {
		return errors.New("发布版本必须是正式三段版本号，例如 0.7.4")
	}
	source.Version = strings.TrimPrefix(source.Version, "v")
	if source.GOOS != "linux" || source.GOARCH != "amd64" && source.GOARCH != "arm64" {
		return errors.New("更新仅支持 linux/amd64 和 linux/arm64")
	}
	if source.Size <= 0 || source.Size > maxAgentUpdateBytes {
		return errors.New("Agent 发布文件大小无效或超过 256 MiB")
	}
	if raw, e := hex.DecodeString(source.SHA256); e != nil || len(raw) != sha256.Size || strings.ToLower(source.SHA256) != source.SHA256 {
		return errors.New("发布清单 SHA-256 无效")
	}
	binary, info, err := regularUpdateFile(filepath.Join(u.sourceDir, "anquan"))
	if err != nil {
		return fmt.Errorf("读取 anquan：%w", err)
	}
	defer binary.Close()
	if info.Size() != source.Size {
		return errors.New("anquan 大小与清单不一致，请重新编译")
	}
	elfFile, err := elf.NewFile(binary)
	if err != nil {
		return errors.New("anquan 不是有效的 Linux ELF 程序")
	}
	wantMachine := elf.EM_X86_64
	if source.GOARCH == "arm64" {
		wantMachine = elf.EM_AARCH64
	}
	if elfFile.Machine != wantMachine || elfFile.Class != elf.ELFCLASS64 || elfFile.Data != elf.ELFDATA2LSB || (elfFile.OSABI != elf.ELFOSABI_NONE && elfFile.OSABI != elf.ELFOSABI_LINUX) || (elfFile.Type != elf.ET_EXEC && elfFile.Type != elf.ET_DYN) {
		return errors.New("anquan ELF 平台与清单不一致")
	}
	if _, err = binary.Seek(0, io.SeekStart); err != nil {
		return err
	}
	file, err := os.CreateTemp(u.storeDir, ".package-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	sum := sha256.New()
	binarySum := sha256.New()
	zipper := gzip.NewWriter(io.MultiWriter(file, sum))
	zipper.Header.ModTime = time.Unix(0, 0)
	archive := tar.NewWriter(zipper)
	err = archive.WriteHeader(&tar.Header{Name: "anquan", Mode: 0755, Size: source.Size, Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)})
	if err == nil {
		_, err = io.CopyN(archive, io.TeeReader(binary, binarySum), source.Size)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && hex.EncodeToString(binarySum.Sum(nil)) != source.SHA256 {
		err = errors.New("anquan SHA-256 与清单不一致，请重新编译")
	}
	if e := archive.Close(); err == nil {
		err = e
	}
	if e := zipper.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = file.Sync()
	}
	stat, statErr := file.Stat()
	if err == nil {
		err = statErr
	}
	if e := file.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	if stat.Size() > maxAgentUpdateArchiveBytes {
		return errors.New("压缩更新包超过大小限制")
	}
	release := &agentUpdateRelease{Version: source.Version, GOOS: source.GOOS, GOARCH: source.GOARCH, SHA256: hex.EncodeToString(sum.Sum(nil)), Size: stat.Size(), BinarySHA256: source.SHA256, BinarySize: source.Size, CreatedAt: time.Now().UTC()}
	dest := filepath.Join(u.storeDir, release.SHA256+".tar.gz")
	if _, err = os.Stat(dest); err == nil {
		// The new temporary archive is fully verified. Replace a possibly
		// corrupted previous snapshot, including on Windows where Rename cannot
		// overwrite an existing destination.
		var existing *os.File
		existing, _, err = regularUpdateFile(dest)
		if err == nil {
			err = existing.Close()
		}
		if err == nil {
			err = os.Remove(dest)
		}
	}
	if err == nil || errors.Is(err, os.ErrNotExist) {
		err = os.Rename(name, dest)
	}
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(release)
	if _, err = store.DB.ExecContext(ctx, `UPDATE agent_update_state SET release_json=? WHERE id=1`, string(raw)); err != nil {
		return err
	}
	u.release = release
	u.cleanupPackages(store)
	return nil
}

// Keep the current release and every still-authorized job snapshot. Cleanup is
// limited to filenames generated by this service, never source build artifacts.
func (u *agentUpdates) cleanupPackages(store *Store) {
	keep := map[string]bool{u.release.SHA256: true}
	rows, err := store.DB.Query(`SELECT release_json FROM agent_update_jobs WHERE status IN ('pending','downloading','restarting') AND expires_at>?`, stamp(time.Now()))
	if err != nil {
		return
	}
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			break
		}
		var release agentUpdateRelease
		if err = json.Unmarshal([]byte(raw), &release); err != nil {
			break
		}
		keep[release.SHA256] = true
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return
	}
	files, err := os.ReadDir(u.storeDir)
	if err != nil {
		return
	}
	for _, file := range files {
		name := file.Name()
		if file.IsDir() || !strings.HasSuffix(name, ".tar.gz") {
			continue
		}
		digest := strings.TrimSuffix(name, ".tar.gz")
		decoded, err := hex.DecodeString(digest)
		if err == nil && len(decoded) == sha256.Size && strings.ToLower(digest) == digest && !keep[digest] {
			_ = os.Remove(filepath.Join(u.storeDir, name))
		}
	}
}

func (s *Server) agentUpdatesView(ctx context.Context) (agentUpdatesView, error) {
	u := s.agentUpdates
	result := agentUpdatesView{SourceDir: u.sourceDir, Items: []agentUpdateItem{}}
	s.configMu.Lock()
	connections := make(map[string]agentUpdateItem, len(s.configAgents))
	for ip, agent := range s.configAgents {
		connections[ip] = agentUpdateItem{Connected: true, Supported: agent.selfUpdate, AgentVersion: agent.agentVersion, GOOS: agent.goos, GOARCH: agent.goarch}
	}
	s.configMu.Unlock()
	u.mu.Lock()
	if u.release != nil {
		copy := *u.release
		result.Release = &copy
	}
	result.SourceError = u.err
	u.mu.Unlock()
	if result.SourceError == "" {
		for _, name := range []string{"anquan.update.json", "anquan"} {
			f, _, err := regularUpdateFile(filepath.Join(u.sourceDir, name))
			if err != nil {
				result.SourceError = "发布源暂不可读取，请确认目录权限并使用新版 anqu-build 重新编译：" + err.Error()
				break
			}
			_ = f.Close()
		}
	}
	if _, err := s.Store.DB.ExecContext(ctx, `UPDATE agent_update_jobs SET status='failed',error='更新授权已过期，请重新下发',updated_at=?,completed_at=? WHERE status IN ('pending','downloading','restarting') AND expires_at<=?`, stamp(time.Now()), stamp(time.Now()), stamp(time.Now())); err != nil {
		return result, err
	}
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT m.ip,m.host,m.alias,COALESCE(j.job_id,''),COALESCE(j.release_json,''),COALESCE(j.status,'idle'),COALESCE(j.error,''),j.updated_at,j.completed_at FROM machines m LEFT JOIN agent_update_jobs j ON j.machine_ip=m.ip ORDER BY m.ip`)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var item agentUpdateItem
		var raw string
		var updated, completed sql.NullInt64
		if err := rows.Scan(&item.MachineIP, &item.Host, &item.Alias, &item.JobID, &raw, &item.Status, &item.Error, &updated, &completed); err != nil {
			return result, err
		}
		connected := connections[item.MachineIP]
		item.Connected, item.Supported, item.AgentVersion, item.GOOS, item.GOARCH = connected.Connected, connected.Supported, connected.AgentVersion, connected.GOOS, connected.GOARCH
		if raw != "" {
			var release agentUpdateRelease
			if err := json.Unmarshal([]byte(raw), &release); err != nil {
				return result, err
			}
			item.TargetVersion = release.Version
		}
		if updated.Valid {
			t := unstamp(updated.Int64)
			item.UpdatedAt = &t
		}
		if completed.Valid {
			t := unstamp(completed.Int64)
			item.CompletedAt = &t
		}
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}

func (s *Server) getAgentUpdates(w http.ResponseWriter, r *http.Request) {
	value, err := s.agentUpdatesView(r.Context())
	s.respond(w, value, err)
}

func (s *Server) packageAgentUpdate(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength != 0 {
		var empty struct{}
		if !decode(w, r, &empty) {
			return
		}
	}
	if err := s.agentUpdates.buildPackage(r.Context(), s.Store); err != nil {
		fail(w, 400, err.Error())
		return
	}
	value, err := s.agentUpdatesView(r.Context())
	s.respond(w, value, err)
}

func (s *Server) startAgentUpdates(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MachineIPs    []string `json:"machine_ips"`
		ReleaseSHA256 string   `json:"release_sha256"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.queueAgentUpdates(r.Context(), body.MachineIPs, body.ReleaseSHA256); err != nil {
		fail(w, 400, err.Error())
		return
	}
	value, err := s.agentUpdatesView(r.Context())
	s.respond(w, value, err)
}

// Lock order is configMu, updates.mu, SQLite; no open query rows wait on locks.
func (s *Server) queueAgentUpdates(ctx context.Context, ips []string, digest string) error {
	if len(ips) == 0 || len(ips) > 10000 {
		return errors.New("请选择 1–10000 台机器")
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	u := s.agentUpdates
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.err != "" {
		return errors.New(u.err)
	}
	if u.release == nil || u.release.SHA256 != digest {
		return errors.New("发布包已变化或未准备好，请重新确认版本")
	}
	selected := map[string]*agentConfigConnection{}
	for _, value := range ips {
		ip, err := normalizeIP(value)
		if err != nil {
			return errors.New("机器 IP 无效")
		}
		agent := s.configAgents[ip]
		if agent == nil {
			return fmt.Errorf("%s 当前未连接主控", ip)
		}
		if !agent.selfUpdate {
			return fmt.Errorf("%s 的 Agent 不支持远程更新，请先手动安装新版", ip)
		}
		if agent.goos != u.release.GOOS || agent.goarch != u.release.GOARCH {
			return fmt.Errorf("%s 的系统架构与发布包不匹配", ip)
		}
		if !newerAgentVersion(u.release.Version, agent.agentVersion) {
			return fmt.Errorf("%s 的目标版本必须高于当前正式版本", ip)
		}
		selected[ip] = agent
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	owners := map[string]*agentConfigConnection{}
	raw, _ := json.Marshal(u.release)
	for ip, agent := range selected {
		var status string
		var expires int64
		err := tx.QueryRowContext(ctx, `SELECT status,expires_at FROM agent_update_jobs WHERE machine_ip=?`, ip).Scan(&status, &expires)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && expires > stamp(time.Now()) && (status == "pending" || status == "downloading" || status == "restarting") {
			return fmt.Errorf("%s 已有进行中的更新", ip)
		}
		jobID, err := packageToken()
		if err != nil {
			return err
		}
		token, err := packageToken()
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO agent_update_jobs(machine_ip,job_id,release_json,token,previous_version,expires_at,status,updated_at) VALUES(?,?,?,?,?,?,'pending',?) ON CONFLICT(machine_ip) DO UPDATE SET job_id=excluded.job_id,release_json=excluded.release_json,token=excluded.token,previous_version=excluded.previous_version,expires_at=excluded.expires_at,status='pending',error='',updated_at=excluded.updated_at,completed_at=NULL`, ip, jobID, string(raw), token, agent.agentVersion, stamp(time.Now().Add(agentUpdateTTL)), stamp(time.Now())); err != nil {
			return err
		}
		owners[jobID] = agent
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	for oldJobID, owner := range u.owners {
		if selected[owner.ip] != nil {
			delete(u.owners, oldJobID)
			for conn := range u.waiting[oldJobID] {
				_ = conn.Close()
			}
			if stream := u.streams[owner.ip]; stream != nil {
				_ = stream.Close()
			}
		}
	}
	for jobID, owner := range owners {
		u.owners[jobID] = owner
		owner.requestSelfUpdate()
	}
	return nil
}

func (s *Server) sendAgentUpdate(ctx context.Context, agent *agentConfigConnection) error {
	agent.writeMu.Lock()
	defer agent.writeMu.Unlock()
	descriptor, err := s.prepareAgentUpdate(ctx, agent)
	if err != nil || descriptor == nil {
		return err
	}
	return writeAgentFrame(agent.conn, agentConfigFrame{Version: 1, Type: "update_offer", Update: descriptor})
}

func (s *Server) prepareAgentUpdate(ctx context.Context, agent *agentConfigConnection) (*agentUpdateDescriptor, error) {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	u := s.agentUpdates
	u.mu.Lock()
	defer u.mu.Unlock()
	if s.configAgents[agent.ip] != agent {
		return nil, net.ErrClosed
	}
	var descriptor agentUpdateDescriptor
	var raw, status string
	var expires int64
	err := s.Store.DB.QueryRowContext(ctx, `SELECT job_id,release_json,token,expires_at,status FROM agent_update_jobs WHERE machine_ip=?`, agent.ip).Scan(&descriptor.JobID, &raw, &descriptor.Token, &expires, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if status != "pending" || expires <= stamp(time.Now()) || u.owners[descriptor.JobID] != agent {
		return nil, nil
	}
	var release agentUpdateRelease
	if err := json.Unmarshal([]byte(raw), &release); err != nil {
		return nil, err
	}
	descriptor.Version, descriptor.GOOS, descriptor.GOARCH, descriptor.SHA256, descriptor.Size, descriptor.BinarySHA256, descriptor.BinarySize = release.Version, release.GOOS, release.GOARCH, release.SHA256, release.Size, release.BinarySHA256, release.BinarySize
	descriptor.ExpiresAt = unstamp(expires).UTC().Format(time.RFC3339)
	unsigned, _ := json.Marshal(descriptor)
	descriptor.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(u.key, unsigned))
	return &descriptor, nil
}

func (s *Server) serveAgentUpdateDownload(ctx context.Context, transfer *agentConfigConnection, hello agentConfigFrame) {
	err := s.transferAgentUpdate(ctx, transfer, hello)
	if err != nil {
		_ = writeAgentFrame(transfer.conn, agentConfigFrame{Version: 1, Type: "error", Error: truncateAgentError(err.Error())})
	}
}

func (s *Server) transferAgentUpdate(ctx context.Context, transfer *agentConfigConnection, hello agentConfigFrame) error {
	u := s.agentUpdates
	// Validate before waiting so arbitrary connections cannot occupy the queue.
	s.configMu.Lock()
	u.mu.Lock()
	_, expires, err := s.authorizeAgentUpdateLocked(ctx, transfer, hello)
	if err == nil {
		if u.waiting[hello.JobID] == nil {
			u.waiting[hello.JobID] = map[net.Conn]struct{}{}
		}
		u.waiting[hello.JobID][transfer.conn] = struct{}{}
	}
	u.mu.Unlock()
	s.configMu.Unlock()
	if err != nil {
		return err
	}
	defer func() {
		u.mu.Lock()
		delete(u.waiting[hello.JobID], transfer.conn)
		if len(u.waiting[hello.JobID]) == 0 {
			delete(u.waiting, hello.JobID)
		}
		u.mu.Unlock()
	}()
	deadline := time.Now().Add(2 * time.Minute)
	if unstamp(expires).Before(deadline) {
		deadline = unstamp(expires)
	}
	if err = u.waitForSlot(ctx, transfer.conn, deadline); err != nil {
		return err
	}
	defer func() { <-u.slots }()
	// A queued job may expire, disconnect, be replaced or fail while waiting.
	s.configMu.Lock()
	u.mu.Lock()
	release, expires, err := s.authorizeAgentUpdateLocked(ctx, transfer, hello)
	if err != nil {
		u.mu.Unlock()
		s.configMu.Unlock()
		return err
	}
	file, info, err := regularUpdateFile(filepath.Join(u.storeDir, release.SHA256+".tar.gz"))
	if err == nil && info.Size() != release.Size {
		file.Close()
		err = errors.New("更新快照大小变化")
	}
	if err == nil {
		sum := sha256.New()
		_, err = io.Copy(sum, io.LimitReader(file, maxAgentUpdateArchiveBytes+1))
		if err == nil && hex.EncodeToString(sum.Sum(nil)) != release.SHA256 {
			err = errors.New("更新快照 SHA-256 校验失败，请重新打包")
		}
		if err == nil {
			_, err = file.Seek(0, io.SeekStart)
		}
	}
	if err == nil {
		_, err = s.Store.DB.ExecContext(ctx, `UPDATE agent_update_jobs SET status='downloading',updated_at=? WHERE job_id=?`, stamp(time.Now()), hello.JobID)
	}
	if err != nil {
		if file != nil {
			file.Close()
		}
		u.mu.Unlock()
		s.configMu.Unlock()
		return err
	}
	u.streams[hello.IP] = transfer.conn
	u.mu.Unlock()
	s.configMu.Unlock()
	defer file.Close()
	defer func() {
		u.mu.Lock()
		if u.streams[hello.IP] == transfer.conn {
			delete(u.streams, hello.IP)
		}
		u.mu.Unlock()
	}()
	if err := writeAgentFrame(transfer.conn, agentConfigFrame{Version: 1, Type: "update_ready", Size: release.Size}); err != nil {
		return err
	}
	deadline = time.Now().Add(2 * time.Minute)
	if unstamp(expires).Before(deadline) {
		deadline = unstamp(expires)
	}
	_ = transfer.conn.SetDeadline(deadline)
	_, err = io.CopyN(transfer.conn, file, release.Size)
	// Once raw bytes begin, errors close the connection rather than append JSON.
	if err != nil {
		_ = transfer.conn.Close()
	}
	return nil
}

func (s *Server) authorizeAgentUpdateLocked(ctx context.Context, transfer *agentConfigConnection, hello agentConfigFrame) (agentUpdateRelease, int64, error) {
	u := s.agentUpdates
	var release agentUpdateRelease
	owner := s.configAgents[hello.IP]
	if owner == nil || owner.source != transfer.source || u.owners[hello.JobID] != owner || len(hello.Token) != 64 || u.streams[hello.IP] != nil {
		return release, 0, errors.New("更新下载未授权或该机器已有下载")
	}
	var token, raw, status, jobID string
	var expires int64
	err := s.Store.DB.QueryRowContext(ctx, `SELECT job_id,token,release_json,expires_at,status FROM agent_update_jobs WHERE machine_ip=?`, hello.IP).Scan(&jobID, &token, &raw, &expires, &status)
	if err != nil || jobID != hello.JobID || subtle.ConstantTimeCompare([]byte(token), []byte(hello.Token)) != 1 || expires <= stamp(time.Now()) || (status != "pending" && status != "downloading") {
		return release, 0, errors.New("更新下载授权无效或已过期")
	}
	if err = json.Unmarshal([]byte(raw), &release); err != nil {
		return release, 0, err
	}
	return release, expires, nil
}

func (u *agentUpdates) waitForSlot(ctx context.Context, conn net.Conn, deadline time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(deadline) {
		return errors.New("更新下载排队超时")
	}
	select {
	case u.slots <- struct{}{}:
		return nil
	default:
	}
	// Reading is only for disconnect detection while no server bytes have been
	// sent. Stop it with a read deadline before sending ready/raw bytes.
	if err := conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	type peerRead struct {
		n   int
		err error
	}
	done := make(chan peerRead, 1)
	go func() { var data [1]byte; n, err := conn.Read(data[:]); done <- peerRead{n, err} }()
	stop := func() peerRead {
		_ = conn.SetReadDeadline(time.Now())
		result := <-done
		_ = conn.SetReadDeadline(time.Time{})
		return result
	}
	select {
	case u.slots <- struct{}{}:
		result := stop()
		var network net.Error
		if result.n != 0 || !errors.As(result.err, &network) || !network.Timeout() || !time.Now().Before(deadline) || ctx.Err() != nil {
			<-u.slots
			return errors.New("更新下载排队已取消或连接断开")
		}
		return nil
	case <-ctx.Done():
		stop()
		return ctx.Err()
	case result := <-done:
		_ = conn.SetReadDeadline(time.Time{})
		return fmt.Errorf("更新下载排队已取消或超时：%v", result.err)
	}
}

func (s *Server) agentUpdateStatus(ctx context.Context, agent *agentConfigConnection, frame agentConfigFrame) error {
	if frame.UpdateResult != nil {
		if frame.UpdateJobID != "" && frame.UpdateJobID != frame.UpdateResult.JobID || frame.JobID != "" && frame.JobID != frame.UpdateResult.JobID {
			return errors.New("inconsistent update job identity")
		}
		frame.JobID, frame.Status, frame.Error = frame.UpdateResult.JobID, frame.UpdateResult.Status, frame.UpdateResult.Error
	}
	if len(frame.JobID) > 64 || len(frame.Error) > 65536 {
		return errors.New("invalid update status")
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	u := s.agentUpdates
	u.mu.Lock()
	defer u.mu.Unlock()
	if s.configAgents[agent.ip] != agent || u.owners[frame.JobID] != agent {
		return nil
	}
	var current string
	var expires int64
	if err := s.Store.DB.QueryRowContext(ctx, `SELECT status,expires_at FROM agent_update_jobs WHERE machine_ip=? AND job_id=?`, agent.ip, frame.JobID).Scan(&current, &expires); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	if expires <= stamp(time.Now()) || current == "failed" || current == "applied" || current == "rolled_back" {
		return nil
	}
	status := frame.Status
	if status != "downloading" && status != "restarting" && status != "failed" && status != "rolled_back" {
		return nil
	}
	// A late downloading frame must not move a replacement already restarting.
	if current == "restarting" && status == "downloading" {
		return nil
	}
	var completed any
	if status == "failed" || status == "rolled_back" {
		completed = stamp(time.Now())
	}
	_, err := s.Store.DB.ExecContext(ctx, `UPDATE agent_update_jobs SET status=?,error=?,updated_at=?,completed_at=? WHERE job_id=?`, status, truncateAgentError(frame.Error), stamp(time.Now()), completed, frame.JobID)
	if err == nil && completed != nil {
		delete(u.owners, frame.JobID)
		for conn := range u.waiting[frame.JobID] {
			_ = conn.Close()
		}
		if stream := u.streams[agent.ip]; stream != nil {
			_ = stream.Close()
		}
	}
	return err
}

func (s *Server) resumeAgentUpdate(ctx context.Context, agent *agentConfigConnection, hello agentConfigFrame) error {
	if hello.UpdateJobID == "" {
		return nil
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	u := s.agentUpdates
	u.mu.Lock()
	defer u.mu.Unlock()
	if s.configAgents[agent.ip] != agent {
		return nil
	}
	var raw, status, previous string
	var expires int64
	err := s.Store.DB.QueryRowContext(ctx, `SELECT release_json,status,expires_at,previous_version FROM agent_update_jobs WHERE machine_ip=? AND job_id=?`, agent.ip, hello.UpdateJobID).Scan(&raw, &status, &expires, &previous)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if status != "restarting" || expires <= stamp(time.Now()) {
		return nil
	}
	var release agentUpdateRelease
	if err = json.Unmarshal([]byte(raw), &release); err != nil {
		return err
	}
	if hello.UpdateResult != nil && hello.UpdateResult.JobID == hello.UpdateJobID && (hello.UpdateResult.Status == "rolled_back" || hello.UpdateResult.Status == "failed") && agent.goos == release.GOOS && agent.goarch == release.GOARCH && (agent.agentVersion == previous || agent.agentVersion == release.Version) {
		_, err = s.Store.DB.ExecContext(ctx, `UPDATE agent_update_jobs SET status=?,error=?,updated_at=?,completed_at=? WHERE job_id=?`, hello.UpdateResult.Status, truncateAgentError(hello.UpdateResult.Error), stamp(time.Now()), stamp(time.Now()), hello.UpdateJobID)
		return err
	}
	if agent.agentVersion != release.Version || agent.goos != release.GOOS || agent.goarch != release.GOARCH || hello.UpdateBinarySHA256 != release.BinarySHA256 {
		return nil
	}
	agent.updateJobID = hello.UpdateJobID
	agent.updateBinarySHA256 = hello.UpdateBinarySHA256
	u.owners[hello.UpdateJobID] = agent
	return nil
}

func (s *Server) finishAgentUpdate(ctx context.Context, agent *agentConfigConnection, frame agentConfigFrame) error {
	result := frame.UpdateResult
	if result == nil || result.Status != "applied" || result.Error != "" || result.JobID != agent.updateJobID || frame.UpdateBinarySHA256 != agent.updateBinarySHA256 || frame.AgentVersion != agent.agentVersion || frame.GOOS != agent.goos || frame.GOARCH != agent.goarch {
		return nil
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	u := s.agentUpdates
	u.mu.Lock()
	defer u.mu.Unlock()
	if s.configAgents[agent.ip] != agent || u.owners[result.JobID] != agent {
		return nil
	}
	_, err := s.Store.DB.ExecContext(ctx, `UPDATE agent_update_jobs SET status='applied',error='',updated_at=?,completed_at=? WHERE machine_ip=? AND job_id=? AND status='restarting' AND expires_at>?`, stamp(time.Now()), stamp(time.Now()), agent.ip, result.JobID, stamp(time.Now()))
	return err
}

func (s *Server) disconnectAgentUpdate(agent *agentConfigConnection) {
	u := s.agentUpdates
	u.mu.Lock()
	defer u.mu.Unlock()
	for jobID, owner := range u.owners {
		if owner == agent {
			delete(u.owners, jobID)
			for conn := range u.waiting[jobID] {
				_ = conn.Close()
			}
			if stream := u.streams[agent.ip]; stream != nil {
				_ = stream.Close()
			}
			if s.Store != nil {
				_, _ = s.Store.DB.Exec(`UPDATE agent_update_jobs SET status='failed',error='Agent 连接断开，原下载授权已失效，请重新下发',updated_at=?,completed_at=? WHERE job_id=? AND status IN ('pending','downloading')`, stamp(time.Now()), stamp(time.Now()), jobID)
			}
		}
	}
}
