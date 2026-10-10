package server

import (
	"database/sql"
	"errors"
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
	// A single atomic upsert preserves the exact YAML, including comments.
	_, err := s.Store.DB.ExecContext(r.Context(), `INSERT INTO agent_config_template(id,yaml) VALUES(1,?)
ON CONFLICT(id) DO UPDATE SET yaml=excluded.yaml`, config)
	s.respond(w, agentConfigTemplate{YAML: &config}, err)
}
