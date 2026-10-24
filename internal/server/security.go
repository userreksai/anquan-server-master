package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func validateSecurityEvent(data json.RawMessage) (string, error) {
	var event struct {
		Source   string `json:"source"`
		Kind     string `json:"kind"`
		Severity string `json:"severity"`
		Message  string `json:"message"`
	}
	if json.Unmarshal(data, &event) != nil || strings.TrimSpace(event.Source) == "" || len(event.Source) > 128 || strings.TrimSpace(event.Kind) == "" || len(event.Kind) > 128 || strings.TrimSpace(event.Message) == "" || len(event.Message) > 16384 {
		return "", fmt.Errorf("invalid security event")
	}
	switch event.Severity {
	case "debug", "info", "notice", "warning", "error", "critical":
		return event.Severity, nil
	default:
		return "", fmt.Errorf("invalid security severity")
	}
}

func validateComponentStatus(data json.RawMessage) error {
	var report struct {
		Components []struct {
			Name       string     `json:"name"`
			Enabled    bool       `json:"enabled"`
			Installed  bool       `json:"installed"`
			Running    bool       `json:"running"`
			State      string     `json:"state"`
			Version    string     `json:"version"`
			ConfigHash string     `json:"config_hash"`
			AppliedAt  *time.Time `json:"applied_at"`
			PolicyMode string     `json:"policy_mode"`
			CheckedAt  *time.Time `json:"checked_at"`
			Error      string     `json:"error"`
			Message    string     `json:"message"`
		} `json:"components"`
	}
	if json.Unmarshal(data, &report) != nil || report.Components == nil || len(report.Components) > 32 {
		return fmt.Errorf("invalid component status")
	}
	names := map[string]bool{}
	for _, component := range report.Components {
		if component.PolicyMode != "" && component.PolicyMode != "audit" && component.PolicyMode != "enforce" {
			return fmt.Errorf("invalid policy mode in component status")
		}
		if strings.TrimSpace(component.Name) == "" || len(component.Name) > 64 || names[component.Name] || len(component.State) > 128 || len(component.Version) > 256 || len(component.ConfigHash) > 128 || len(component.Error) > 4096 || len(component.Message) > 4096 {
			return fmt.Errorf("invalid component status entry")
		}
		names[component.Name] = true
	}
	return validateSSHAccountsInventory(data)
}

type SecurityStatus struct {
	MachineIP  string          `json:"machine_ip"`
	Host       string          `json:"host"`
	Time       time.Time       `json:"time"`
	ReceivedAt time.Time       `json:"received_at"`
	Data       json.RawMessage `json:"data"`
}

func (s *Store) SecurityStatuses(ctx context.Context, machineIP string) ([]SecurityStatus, error) {
	items := []SecurityStatus{}
	query := `SELECT machine_ip,host,time,received_at,data FROM machine_security_status`
	args := []any{}
	if machineIP != "" {
		query += ` WHERE machine_ip=?`
		args = append(args, machineIP)
	}
	rows, err := s.DB.QueryContext(ctx, query+` ORDER BY received_at DESC,machine_ip`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var status SecurityStatus
		var at, received int64
		var data string
		if err := rows.Scan(&status.MachineIP, &status.Host, &at, &received, &data); err != nil {
			return nil, err
		}
		status.Time, status.ReceivedAt, status.Data = unstamp(at), unstamp(received), json.RawMessage(data)
		items = append(items, status)
	}
	return items, rows.Err()
}

func (s *Server) securityStatus(w http.ResponseWriter, r *http.Request) {
	machineIP := r.URL.Query().Get("machine_ip")
	if machineIP != "" {
		var err error
		machineIP, err = normalizeIP(machineIP)
		if err != nil {
			fail(w, 400, "机器 IP 无效")
			return
		}
	}
	items, err := s.Store.SecurityStatuses(r.Context(), machineIP)
	s.respond(w, map[string]any{"items": items}, err)
}
