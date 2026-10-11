package server

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const maxAgentTCPFrameBytes = 8 << 20
const maxAgentTCPConnections = 1024

// Frames are newline-delimited JSON. Ciphertext is armored age encrypted to
// the fixed agent recipient; revision is its lowercase SHA-256 digest.
type agentConfigFrame struct {
	Version      int    `json:"version"`
	Type         string `json:"type"`
	IP           string `json:"ip,omitempty"`
	Host         string `json:"host,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
	Revision     string `json:"revision,omitempty"`
	Ciphertext   string `json:"ciphertext,omitempty"`
	Error        string `json:"error,omitempty"`
}

type agentConfigConnection struct {
	conn         net.Conn
	ip           string
	updates      chan struct{}
	done         chan struct{}
	writeMu      sync.Mutex
	lastRevision string
}

func (c *agentConfigConnection) requestConfig() {
	select {
	case c.updates <- struct{}{}:
	default:
	}
}

// ServeAgentTCP owns the listener and closes all established and handshaking
// connections on cancellation. Agents always initiate these connections.
func (s *Server) ServeAgentTCP(ctx context.Context, listener net.Listener) error {
	var workers sync.WaitGroup
	stop := make(chan struct{})
	closeConnections := func() {
		_ = listener.Close()
		s.configMu.Lock()
		for agent := range s.configAll {
			_ = agent.conn.Close()
		}
		s.configMu.Unlock()
	}
	go func() {
		select {
		case <-ctx.Done():
			closeConnections()
		case <-stop:
		}
	}()
	defer func() { close(stop); closeConnections(); workers.Wait() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		agent := &agentConfigConnection{conn: conn, updates: make(chan struct{}, 1), done: make(chan struct{})}
		s.configMu.Lock()
		if ctx.Err() != nil || len(s.configAll) >= maxAgentTCPConnections {
			s.configMu.Unlock()
			_ = conn.Close()
			continue
		}
		s.configAll[agent] = struct{}{}
		s.configMu.Unlock()
		workers.Add(1)
		go func() { defer workers.Done(); s.serveConfigAgent(ctx, agent) }()
	}
}

// ReadSlice keeps memory bounded even before a peer sends its newline. Hello,
// ACK and ping have tighter limits than the large master-to-agent config frame.
func readAgentFrame(reader *bufio.Reader, limit int) (agentConfigFrame, error) {
	var frame agentConfigFrame
	var data []byte
	for {
		part, err := reader.ReadSlice('\n')
		if len(data)+len(part) > limit {
			return frame, errors.New("agent frame exceeds limit")
		}
		data = append(data, part...)
		if err == bufio.ErrBufferFull {
			if len(data) >= limit {
				return frame, errors.New("agent frame exceeds limit")
			}
			continue
		}
		if err != nil {
			return frame, err
		}
		break
	}
	if err := json.Unmarshal(data, &frame); err != nil || frame.Version != 1 {
		return frame, errors.New("invalid agent frame")
	}
	return frame, nil
}

func (s *Server) serveConfigAgent(ctx context.Context, agent *agentConfigConnection) {
	defer func() {
		_ = agent.conn.Close()
		s.configMu.Lock()
		if s.configAgents[agent.ip] == agent {
			delete(s.configAgents, agent.ip)
		}
		delete(s.configAll, agent)
		s.configMu.Unlock()
	}()
	reader := bufio.NewReader(agent.conn)
	_ = agent.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	hello, err := readAgentFrame(reader, 4096)
	if err != nil || hello.Type != "hello" || strings.TrimSpace(hello.Host) == "" || len(hello.Host) > 255 || len(hello.AgentVersion) > 255 {
		return
	}
	source, _, err := net.SplitHostPort(agent.conn.RemoteAddr().String())
	if err != nil {
		return
	}
	source, err = normalizeIP(source)
	if err != nil {
		return
	}
	ip := hello.IP
	if ip == "" {
		ip = source
	}
	agent.ip, err = normalizeIP(ip)
	if err != nil {
		return
	}
	if err = s.Store.touchConfigAgent(ctx, agent.ip, hello.Host, source); err != nil {
		return
	}
	s.configMu.Lock()
	previous := s.configAgents[agent.ip]
	s.configAgents[agent.ip] = agent
	s.configMu.Unlock()
	if previous != nil {
		_ = previous.conn.Close()
	}
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case <-agent.done:
				return
			case <-agent.updates:
				if err := s.sendCurrentAgentConfig(ctx, agent); err != nil {
					_ = agent.conn.Close()
					return
				}
			}
		}
	}()
	defer func() { close(agent.done); _ = agent.conn.Close(); <-writerDone }()
	agent.requestConfig()
	for {
		_ = agent.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		frame, err := readAgentFrame(reader, 65536)
		if err != nil {
			return
		}
		switch frame.Type {
		case "ping":
			if err := s.Store.touchConfigAgent(ctx, agent.ip, "", ""); err != nil {
				return
			}
			agent.writeMu.Lock()
			err = writeAgentFrame(agent.conn, agentConfigFrame{Version: 1, Type: "pong"})
			agent.writeMu.Unlock()
			if err != nil {
				return
			}
		case "ack":
			if err := s.ackAgentConfig(ctx, agent, frame); err != nil {
				return
			}
		default:
			return
		}
	}
}

func (s *Server) ackAgentConfig(ctx context.Context, agent *agentConfigConnection, frame agentConfigFrame) error {
	if len(frame.Error) > 4096 || len(frame.Revision) > 64 {
		return errors.New("invalid agent acknowledgement")
	}
	agent.writeMu.Lock()
	defer agent.writeMu.Unlock()
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if s.configAgents[agent.ip] != agent || frame.Revision == "" || frame.Revision != agent.lastRevision {
		return nil
	}
	status := "applied"
	var applied any = stamp(time.Now())
	if frame.Error != "" {
		status, applied = "failed", nil
	}
	_, err := s.Store.DB.ExecContext(ctx, `UPDATE agent_config_deliveries SET status=?,error=?,applied_at=? WHERE machine_ip=? AND revision=?`, status, frame.Error, applied, agent.ip, frame.Revision)
	return err
}

func writeAgentFrame(conn net.Conn, frame agentConfigFrame) error {
	var payload any = frame
	if frame.Type == "config" {
		payload = struct {
			Version    int    `json:"version"`
			Type       string `json:"type"`
			Revision   string `json:"revision"`
			Ciphertext string `json:"ciphertext"`
		}{frame.Version, frame.Type, frame.Revision, frame.Ciphertext}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(data)+1 > maxAgentTCPFrameBytes {
		return errors.New("agent frame exceeds limit")
	}
	data = append(data, '\n')
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (s *Server) sendCurrentAgentConfig(ctx context.Context, agent *agentConfigConnection) error {
	agent.writeMu.Lock()
	defer agent.writeMu.Unlock()
	s.configMu.Lock()
	if s.configAgents[agent.ip] != agent {
		s.configMu.Unlock()
		return net.ErrClosed
	}
	frame := agentConfigFrame{Version: 1, Type: "config"}
	err := s.Store.DB.QueryRowContext(ctx, `SELECT revision,ciphertext FROM agent_config_deliveries WHERE machine_ip=?`, agent.ip).Scan(&frame.Revision, &frame.Ciphertext)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.configMu.Unlock()
		return err
	}
	if frame.Revision != "" {
		if _, err := s.Store.DB.ExecContext(ctx, `UPDATE agent_config_deliveries SET status='pending',error='',applied_at=NULL WHERE machine_ip=? AND revision=?`, agent.ip, frame.Revision); err != nil {
			s.configMu.Unlock()
			return err
		}
	}
	s.configMu.Unlock()
	if err := writeAgentFrame(agent.conn, frame); err != nil {
		return err
	}
	agent.lastRevision = frame.Revision
	return nil
}

func (s *Server) disconnectConfigAgent(ip string) {
	s.configMu.Lock()
	if agent := s.configAgents[ip]; agent != nil {
		_ = agent.conn.Close()
	}
	s.configMu.Unlock()
}

func (s *Store) touchConfigAgent(ctx context.Context, ip, host, source string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := stamp(time.Now())
	if host != "" {
		_, err = tx.ExecContext(ctx, `INSERT INTO machines(ip,host,source_ip,reported_ip,first_seen,last_seen,last_event_at,last_agent_at)
 VALUES(?,?,?,?,?,?,0,?) ON CONFLICT(ip) DO UPDATE SET host=excluded.host,source_ip=excluded.source_ip,
 reported_ip=excluded.reported_ip,last_seen=MAX(machines.last_seen,excluded.last_seen),last_agent_at=MAX(machines.last_agent_at,excluded.last_agent_at)`, ip, host, source, ip, now, now, now)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE machines SET last_seen=MAX(last_seen,?) WHERE ip=?`, now, ip)
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM machine_offline_state WHERE machine_ip=?`, ip); err != nil {
		return err
	}
	return tx.Commit()
}
