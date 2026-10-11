package server

import (
	"bytes"
	"encoding/json"
	"errors"
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

func readAgentYAML(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body struct {
		YAML string `json:"yaml"`
	}
	// JSON escaping can expand the plaintext size; enforce both limits.
	r.Body = http.MaxBytesReader(w, r.Body, 6*maxAgentYAMLBytes+4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&body); err != nil {
		fail(w, 400, "配置请求无效或超过大小限制")
		return "", false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		fail(w, 400, "请求只能包含一个 JSON 对象")
		return "", false
	}
	if err := validateAgentYAML(body.YAML); err != nil {
		fail(w, 400, err.Error())
		return "", false
	}
	return body.YAML, true
}

func validateAgentYAML(config string) error {
	if len(config) > maxAgentYAMLBytes || strings.TrimSpace(config) == "" {
		return errors.New("请填写 YAML 配置，最大 4 MiB")
	}
	// Validate a single mapping without resolving file paths on the master.
	// Agent performs its complete schema and target-platform validation on load.
	decoder := yaml.NewDecoder(strings.NewReader(config))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("YAML 格式错误：配置必须为一个键值映射")
	}
	var mapping map[string]any
	if err := document.Decode(&mapping); err != nil {
		return errors.New("YAML 无效，请检查重复字段和数据类型")
	}
	if err := decoder.Decode(new(yaml.Node)); err != io.EOF {
		return errors.New("只允许一份 YAML 配置，不支持多个文档")
	}
	return nil
}

func (s *Server) encryptAgentConfig(w http.ResponseWriter, r *http.Request) {
	config, ok := readAgentYAML(w, r)
	if !ok {
		return
	}
	ciphertext, err := encryptedAgentYAML(config)
	if err != nil {
		fail(w, 500, "配置加密失败，请重试")
		return
	}
	// This download endpoint does not persist or log configuration content.
	writeJSON(w, 200, map[string]string{
		"ciphertext": ciphertext, "filename": "config.age",
	})
}

func encryptedAgentYAML(config string) (string, error) {
	recipient, err := age.ParseX25519Recipient(agentAgeRecipient)
	if err != nil {
		return "", err
	}
	var encrypted bytes.Buffer
	armored := armor.NewWriter(&encrypted)
	writer, err := age.Encrypt(armored, recipient)
	if err == nil {
		_, err = io.WriteString(writer, config)
	}
	if err == nil {
		err = writer.Close()
	}
	if err == nil {
		err = armored.Close()
	}
	if err != nil {
		return "", err
	}
	return encrypted.String(), nil
}
