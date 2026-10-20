package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type AgentConfigDelivery struct {
	MachineIP string     `json:"machine_ip"`
	Host      string     `json:"host"`
	Alias     string     `json:"alias"`
	Connected bool       `json:"connected"`
	Revision  string     `json:"revision"`
	Status    string     `json:"status"`
	Error     string     `json:"error"`
	UpdatedAt *time.Time `json:"updated_at"`
	AppliedAt *time.Time `json:"applied_at"`
}

type agentDeliveryResult struct {
	Items []AgentConfigDelivery `json:"items"`
}

func (s *Server) agentConfigDeliveries(ctx context.Context, selected map[string]bool) (agentDeliveryResult, error) {
	result := agentDeliveryResult{Items: []AgentConfigDelivery{}}
	// Snapshot before opening rows: the sole SQLite connection must never be
	// held while waiting for configMu, because ACK uses that lock to guard
	// connection replacement throughout its database update.
	s.configMu.Lock()
	connected := make(map[string]bool, len(s.configAgents))
	for ip := range s.configAgents {
		connected[ip] = true
	}
	s.configMu.Unlock()
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT m.ip,m.host,m.alias,COALESCE(d.revision,''),
 COALESCE(d.status,'unassigned'),COALESCE(d.error,''),d.updated_at,d.applied_at
 FROM machines m LEFT JOIN agent_config_deliveries d ON d.machine_ip=m.ip ORDER BY m.ip`)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var item AgentConfigDelivery
		var updated, applied sql.NullInt64
		if err := rows.Scan(&item.MachineIP, &item.Host, &item.Alias, &item.Revision, &item.Status, &item.Error, &updated, &applied); err != nil {
			return result, err
		}
		if selected != nil && !selected[item.MachineIP] {
			continue
		}
		if updated.Valid {
			at := unstamp(updated.Int64)
			item.UpdatedAt = &at
		}
		if applied.Valid {
			at := unstamp(applied.Int64)
			item.AppliedAt = &at
		}
		item.Connected = connected[item.MachineIP]
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}

func (s *Server) getAgentConfigDeliveries(w http.ResponseWriter, r *http.Request) {
	result, err := s.agentConfigDeliveries(r.Context(), nil)
	s.respond(w, result, err)
}

func (s *Server) saveAgentConfigDeliveries(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML       string   `json:"yaml"`
		MachineIPs []string `json:"machine_ips"`
	}
	// YAML can expand sixfold when JSON escaped; also bound the machine list.
	r.Body = http.MaxBytesReader(w, r.Body, 6*maxAgentYAMLBytes+(1<<20))
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		fail(w, 400, "配置下发请求无效或超过大小限制")
		return
	}
	if decoder.Decode(new(any)) != io.EOF {
		fail(w, 400, "请求只能包含一个 JSON 对象")
		return
	}
	if err := validateAgentYAML(body.YAML); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if len(body.MachineIPs) == 0 || len(body.MachineIPs) > 10000 {
		fail(w, 400, "请选择 1–10000 台已登记机器")
		return
	}
	selected := make(map[string]bool, len(body.MachineIPs))
	for _, value := range body.MachineIPs {
		ip, err := normalizeIP(value)
		if err != nil {
			fail(w, 400, "选择的机器 IP 无效")
			return
		}
		selected[ip] = true
	}
	ciphertext, err := encryptedAgentYAML(body.YAML)
	if err != nil {
		fail(w, 500, "配置加密失败，请重试")
		return
	}
	sum := sha256.Sum256([]byte(ciphertext))
	revision := hex.EncodeToString(sum[:])
	if err := s.Store.assignAgentConfig(r.Context(), selected, ciphertext, revision); err != nil {
		var invalid *unregisteredConfigMachine
		if errors.As(err, &invalid) {
			fail(w, 400, "只能向已登记机器下发配置，请刷新机器列表")
		} else {
			s.respond(w, nil, err)
		}
		return
	}
	// Persist every selection before queuing writes. Each connection coalesces
	// queued updates and reads the latest revision, so slow peers never block HTTP.
	s.configMu.Lock()
	for ip := range selected {
		if agent := s.configAgents[ip]; agent != nil {
			s.packages.revokeOwner(agent)
			agent.requestConfig()
		}
	}
	s.configMu.Unlock()
	result, err := s.agentConfigDeliveries(r.Context(), selected)
	s.respond(w, result, err)
}

type unregisteredConfigMachine struct{ ip string }

func (e *unregisteredConfigMachine) Error() string {
	return fmt.Sprintf("unregistered machine %s", e.ip)
}

func (s *Store) assignAgentConfig(ctx context.Context, selected map[string]bool, ciphertext, revision string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for ip := range selected {
		var exists int
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM machines WHERE ip=?`, ip).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return &unregisteredConfigMachine{ip}
		}
		if err != nil {
			return err
		}
	}
	now := stamp(time.Now())
	for ip := range selected {
		if _, err = tx.ExecContext(ctx, `INSERT INTO agent_config_deliveries(machine_ip,ciphertext,revision,status,updated_at)
 VALUES(?,?,?,'pending',?) ON CONFLICT(machine_ip) DO UPDATE SET ciphertext=excluded.ciphertext,
 revision=excluded.revision,status='pending',error='',updated_at=excluded.updated_at,applied_at=NULL`, ip, ciphertext, revision, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}
