package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"go.yaml.in/yaml/v3"
)

const maxAgentYAMLBytes = 4 << 20

func (s *Server) agentEncryptionSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"filename": "config.age",
	})
}

func (s *Server) encryptAgentConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML string `json:"yaml"`
	}
	// JSON escaping can expand the plaintext size; enforce both limits.
	r.Body = http.MaxBytesReader(w, r.Body, 6*maxAgentYAMLBytes+4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&body); err != nil {
		fail(w, 400, "加密请求无效或超过大小限制")
		return
	}
	if err := d.Decode(new(any)); err != io.EOF {
		fail(w, 400, "请求只能包含一个 JSON 对象")
		return
	}
	if len(body.YAML) > maxAgentYAMLBytes || strings.TrimSpace(body.YAML) == "" {
		fail(w, 400, "请填写 YAML 配置，最大 4 MiB")
		return
	}
	// Validate a single mapping without resolving file paths on the master.
	// Agent performs its complete schema and target-platform validation on load.
	decoder := yaml.NewDecoder(strings.NewReader(body.YAML))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		fail(w, 400, "YAML 格式错误：配置必须为一个键值映射")
		return
	}
	var mapping map[string]any
	if err := document.Decode(&mapping); err != nil {
		fail(w, 400, "YAML 无效，请检查重复字段和数据类型")
		return
	}
	if err := decoder.Decode(new(yaml.Node)); err != io.EOF {
		fail(w, 400, "只允许一份 YAML 配置，不支持多个文档")
		return
	}
	recipient, err := age.ParseX25519Recipient(agentAgeRecipient)
	if err != nil {
		fail(w, 500, "加密服务配置异常")
		return
	}
	var encrypted bytes.Buffer
	armored := armor.NewWriter(&encrypted)
	writer, err := age.Encrypt(armored, recipient)
	if err == nil {
		_, err = io.WriteString(writer, body.YAML)
	}
	if err == nil {
		err = writer.Close()
	}
	if err == nil {
		err = armored.Close()
	}
	if err != nil {
		fail(w, 500, "配置加密失败，请重试")
		return
	}
	// Neither request plaintext nor ciphertext is persisted or logged.
	writeJSON(w, 200, map[string]string{
		"ciphertext": encrypted.String(), "filename": "config.age",
	})
}
