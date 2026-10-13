package server

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
)

type agentConfigTemplate struct {
	YAML *string `json:"yaml"`
}

func (s *Server) getAgentConfigTemplate(w http.ResponseWriter, r *http.Request) {
	var config string
	err := s.Store.DB.QueryRowContext(r.Context(), `SELECT yaml FROM agent_config_template WHERE id=1`).Scan(&config)
	if errors.Is(err, sql.ErrNoRows) {
		// No saved template yet; the frontend supplies its built-in example.
		s.respond(w, agentConfigTemplate{}, nil)
		return
	}
	s.respond(w, agentConfigTemplate{YAML: &config}, err)
}

func (s *Server) saveAgentConfigTemplate(w http.ResponseWriter, r *http.Request) {
	config, ok := readAgentYAML(w, r)
	if !ok {
		return
	}
	err := s.Store.SaveAgentConfigTemplate(r.Context(), config)
	s.respond(w, agentConfigTemplate{YAML: &config}, err)
}

// ReadAgentTemplateYAML limits stdin before decoding, sharing the HTTP YAML
// validation while preserving the exact content, including comments/newlines.
func ReadAgentTemplateYAML(input io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(input, maxAgentYAMLBytes+1))
	if err != nil {
		return "", err
	}
	config := string(data)
	if err = validateAgentYAML(config); err != nil {
		return "", err
	}
	return config, nil
}

// SaveAgentConfigTemplate stores one shared template atomically. Both the local
// CLI and authenticated HTTP handlers use this operation; it sends no traffic.
func (s *Store) SaveAgentConfigTemplate(ctx context.Context, config string) error {
	if err := validateAgentYAML(config); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO agent_config_template(id,yaml) VALUES(1,?)
ON CONFLICT(id) DO UPDATE SET yaml=excluded.yaml`, config)
	return err
}
