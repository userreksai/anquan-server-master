package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The master checks shape and spelling while the agent validates target-host
// support, exact limits and privileged changes. Unknown existing YAML nodes are
// retained; unknown submitted profile fields produce an explicit error.
type profileField struct {
	kind    string
	fields  map[string]profileField
	choices string
	minimum float64
	maximum float64
}

func profileObject(fields map[string]profileField) profileField {
	return profileField{kind: "object", fields: fields}
}

var securityProfileSchema = profileObject(map[string]profileField{
	"enabled": {kind: "bool"}, "install_missing": {kind: "bool"},
	"poll_interval_seconds": {kind: "int"}, "status_interval_seconds": {kind: "int"}, "max_queue_events": {kind: "int"},
	"auditd":   profileObject(map[string]profileField{"enabled": {kind: "bool"}, "audit_exec": {kind: "bool"}, "watch_paths": {kind: "strings"}, "rules": {kind: "strings"}}),
	"tetragon": profileObject(map[string]profileField{"enabled": {kind: "bool"}, "version": {kind: "string"}, "download_url": {kind: "string"}, "sha256": {kind: "string"}, "config": {kind: "string"}, "tracing_policy": {kind: "string"}}),
	"sudo": profileObject(map[string]profileField{
		"enabled": {kind: "bool"}, "io_logging": {kind: "bool"}, "upload_io": {kind: "bool"}, "max_session_bytes": {kind: "int"},
		"grants": {kind: "objects", maximum: 128, fields: map[string]profileField{"user": {kind: "string"}, "run_as": {kind: "string"}, "commands": {kind: "strings"}, "nopasswd": {kind: "bool"}}},
	}),
	"native_fim": profileObject(map[string]profileField{"enabled": {kind: "bool"}, "paths": {kind: "strings"}, "poll_interval_seconds": {kind: "int"}, "report_changes": {kind: "bool"}, "max_diff_bytes": {kind: "int"}}),
	"ssh_auth":   profileObject(map[string]profileField{"enabled": {kind: "bool"}, "poll_interval_seconds": {kind: "int", minimum: 1, maximum: 300}, "initial_lookback_seconds": {kind: "int", minimum: 1, maximum: 86400}, "alert_threshold": {kind: "int", minimum: 1, maximum: 1000}, "window_seconds": {kind: "int", minimum: 10, maximum: 86400}}),
	"policies": profileObject(map[string]profileField{
		"mode":   {kind: "string", choices: "audit|enforce"},
		"ssh":    profileObject(map[string]profileField{"enabled": {kind: "bool"}, "password_authentication": {kind: "string", choices: "yes|no"}, "permit_root_login": {kind: "string", choices: "yes|no|prohibit-password"}, "allow_users": {kind: "strings"}, "allow_sources": {kind: "strings"}}),
		"sysctl": {kind: "stringmap"}, "session_timeout_seconds": {kind: "int"}, "disable_ctrl_alt_del": {kind: "bool"},
		"grub": profileObject(map[string]profileField{"enabled": {kind: "bool"}, "password_hash": {kind: "string"}}),
	}),
})

func validateProfileValue(value any, field profileField, path string) error {
	invalid := func() error { return fmt.Errorf("%s 数据类型或值无效", path) }
	switch field.kind {
	case "bool":
		if _, ok := value.(bool); !ok {
			return invalid()
		}
	case "int":
		v, ok := value.(float64)
		maximum := field.maximum
		if maximum == 0 {
			maximum = 1 << 30
		}
		if !ok || v < field.minimum || v > maximum || math.Trunc(v) != v {
			return invalid()
		}
	case "string":
		v, ok := value.(string)
		if !ok || len(v) > 1<<20 {
			return invalid()
		}
		if field.choices != "" {
			valid := false
			for _, choice := range strings.Split(field.choices, "|") {
				valid = valid || v == choice
			}
			if !valid {
				return invalid()
			}
		}
	case "strings":
		v, ok := value.([]any)
		if !ok || len(v) > 4096 {
			return invalid()
		}
		for _, item := range v {
			if str, ok := item.(string); !ok || len(str) > 16384 {
				return invalid()
			}
		}
	case "objects":
		items, ok := value.([]any)
		if !ok || len(items) > int(field.maximum) {
			return invalid()
		}
		for index, item := range items {
			itemPath := fmt.Sprintf("%s[%d]", path, index)
			if err := validateProfileValue(item, profileObject(field.fields), itemPath); err != nil {
				return err
			}
			if path == "security.sudo.grants" {
				if err := validateSudoGrantProfile(item.(map[string]any), itemPath); err != nil {
					return err
				}
			}
		}
	case "stringmap":
		v, ok := value.(map[string]any)
		if !ok || len(v) > 1024 {
			return invalid()
		}
		for key, item := range v {
			if str, ok := item.(string); !ok || key == "" || len(key) > 256 || len(str) > 4096 {
				return invalid()
			}
		}
	case "object":
		v, ok := value.(map[string]any)
		if !ok {
			return invalid()
		}
		for key, item := range v {
			child, exists := field.fields[key]
			if !exists {
				return fmt.Errorf("%s.%s 是未知配置字段", path, key)
			}
			if err := validateProfileValue(item, child, path+"."+key); err != nil {
				return err
			}
		}
	}
	return nil
}

var sudoAccountName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$`)

func validateSudoGrantProfile(grant map[string]any, path string) error {
	user, ok := grant["user"].(string)
	if !ok || user == "ALL" || len(user) > 256 || !sudoAccountName.MatchString(user) {
		return fmt.Errorf("%s.user 必须为本机账户名称", path)
	}
	if raw, present := grant["run_as"]; present {
		runAs, ok := raw.(string)
		if !ok || runAs == "ALL" || len(runAs) > 256 || (runAs != "" && !sudoAccountName.MatchString(runAs)) {
			return fmt.Errorf("%s.run_as 必须为本机账户名称，留空表示 root", path)
		}
	}
	commands, ok := grant["commands"].([]any)
	if !ok || len(commands) == 0 || len(commands) > 64 {
		return fmt.Errorf("%s.commands 必须包含 1–64 项命令", path)
	}
	for _, value := range commands {
		command, ok := value.(string)
		if !ok || !strings.HasPrefix(command, "/") || len(command) > 1024 || strings.ContainsAny(command, "\r\n\x00,:=\\\"'!#*?[]") {
			return fmt.Errorf("%s.commands 必须使用绝对路径及字面参数，不支持 sudoers 元字符和通配符", path)
		}
	}
	return nil
}

// Preserve a future field that is already present in the user's YAML and was
// echoed unchanged by the form, while still catching newly introduced typos.
func validateProfilePatch(value any, field profileField, path string, existing *yaml.Node) error {
	if field.kind != "object" {
		return validateProfileValue(value, field, path)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s 必须为键值映射", path)
	}
	for key, item := range object {
		var previous *yaml.Node
		if existing != nil && existing.Kind == yaml.MappingNode {
			for i := 0; i < len(existing.Content); i += 2 {
				if existing.Content[i].Value == key {
					previous = existing.Content[i+1]
					break
				}
			}
		}
		child, known := field.fields[key]
		if !known {
			var previousValue any
			if previous == nil || previous.Decode(&previousValue) != nil {
				return fmt.Errorf("%s.%s 是未知配置字段", path, key)
			}
			before, err := json.Marshal(previousValue)
			after, afterErr := json.Marshal(item)
			if err != nil || afterErr != nil || !bytes.Equal(before, after) {
				return fmt.Errorf("%s.%s 是未知配置字段，只能原样保留", path, key)
			}
			continue
		}
		if err := validateProfilePatch(item, child, path+"."+key, previous); err != nil {
			return err
		}
	}
	return nil
}

func validateComposeNodes(node *yaml.Node, depth int) error {
	if depth > 64 || node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fmt.Errorf("配置合成不支持 YAML 锚点、别名或超过 64 层的嵌套，请展开后重试")
	}
	if node.Kind == yaml.MappingNode {
		keys := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || keys[key.Value] {
				return fmt.Errorf("YAML 映射键必须为不重复的字符串")
			}
			keys[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := validateComposeNodes(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// Merge mapping nodes in place so comments, scalar styles and unrelated keys in
// the user's template survive editing a single component from the form.
func mergeProfileNode(destination, patch *yaml.Node, path string) {
	for i := 0; i < len(patch.Content); i += 2 {
		key, value := patch.Content[i], patch.Content[i+1]
		found := false
		for j := 0; j < len(destination.Content); j += 2 {
			if destination.Content[j].Value != key.Value {
				continue
			}
			found = true
			existing := destination.Content[j+1]
			if existing.Kind == yaml.MappingNode && value.Kind == yaml.MappingNode && path+"."+key.Value != "security.policies.sysctl" {
				mergeProfileNode(existing, value, path+"."+key.Value)
			} else {
				value.HeadComment, value.LineComment, value.FootComment = existing.HeadComment, existing.LineComment, existing.FootComment
				destination.Content[j+1] = value
			}
			break
		}
		if !found {
			destination.Content = append(destination.Content, key, value)
		}
	}
}

func composeProfile(config string, patch map[string]any) (string, any, error) {
	if err := validateAgentYAML(config); err != nil {
		return "", nil, err
	}
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(config), &document); err != nil {
		return "", nil, err
	}
	if err := validateComposeNodes(&document, 0); err != nil {
		return "", nil, err
	}
	root := document.Content[0]
	var security *yaml.Node
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "security" {
			security = root.Content[i+1]
			break
		}
	}
	if security != nil && security.Kind != yaml.MappingNode {
		return "", nil, fmt.Errorf("security 必须为键值映射")
	}
	if patch != nil {
		if err := validateProfilePatch(patch, securityProfileSchema, "security", security); err != nil {
			return "", nil, err
		}
		var incoming yaml.Node
		if err := incoming.Encode(patch); err != nil {
			return "", nil, err
		}
		if security == nil {
			security = &incoming
			root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "security"}, security)
		} else {
			mergeProfileNode(security, &incoming, "security")
		}
	}
	var profile any
	if security != nil {
		if err := security.Decode(&profile); err != nil {
			return "", nil, err
		}
	}
	// Read-only parsing returns exact original text; composing normalizes indent
	// while retaining YAML nodes rather than round-tripping a restricted struct.
	if patch == nil {
		return config, profile, nil
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return "", nil, err
	}
	if err := encoder.Close(); err != nil {
		return "", nil, err
	}
	if output.Len() > maxAgentYAMLBytes {
		return "", nil, fmt.Errorf("合成配置超过 4 MiB")
	}
	return output.String(), profile, nil
}

func (s *Server) composeSecurityProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		YAML     string          `json:"yaml"`
		Security json.RawMessage `json:"security"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 6*maxAgentYAMLBytes+4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		fail(w, 400, "配置请求无效或超过大小限制")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		fail(w, 400, "请求只能包含一个 JSON 对象")
		return
	}
	var patch map[string]any
	if len(body.Security) > 0 {
		if err := json.Unmarshal(body.Security, &patch); err != nil || patch == nil {
			fail(w, 400, "security 必须为 JSON 对象")
			return
		}
	}
	config, profile, err := composeProfile(body.YAML, patch)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"yaml": config, "security": profile})
}

func (s *Server) securityProfileDefaults(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"security": map[string]any{
		"enabled": true, "install_missing": true, "poll_interval_seconds": 2, "status_interval_seconds": 30, "max_queue_events": 10000,
		"auditd":     map[string]any{"enabled": true, "audit_exec": true, "watch_paths": []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/ssh", "/etc/sudoers", "/etc/sudoers.d", "/etc/crontab", "/etc/cron.d"}, "rules": []string{}},
		"tetragon":   map[string]any{"enabled": false, "version": "v1.7.1", "download_url": "", "sha256": "", "config": "", "tracing_policy": ""},
		"sudo":       map[string]any{"enabled": true, "io_logging": true, "upload_io": false, "max_session_bytes": 20971520, "grants": []any{}},
		"native_fim": map[string]any{"enabled": true, "paths": []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/ssh", "/etc/sudoers", "/etc/sudoers.d", "/etc/crontab", "/etc/cron.d"}, "poll_interval_seconds": 30, "report_changes": false, "max_diff_bytes": 8192},
		"ssh_auth":   map[string]any{"enabled": true, "poll_interval_seconds": 5, "initial_lookback_seconds": 300, "alert_threshold": 5, "window_seconds": 300},
		"policies":   map[string]any{"mode": "audit", "ssh": map[string]any{"enabled": false, "password_authentication": "no", "permit_root_login": "prohibit-password", "allow_users": []string{}, "allow_sources": []string{}}, "sysctl": map[string]string{}, "session_timeout_seconds": 0, "disable_ctrl_alt_del": false, "grub": map[string]any{"enabled": false, "password_hash": ""}},
	}})
}
