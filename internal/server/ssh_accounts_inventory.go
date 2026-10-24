package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxSSHAccountsInventoryBytes = 16 << 10
const maxSSHInventoryUsers = 256

var errSSHAccountsInventory = errors.New("invalid SSH account inventory")

type sshInventoryUser struct {
	Name       string  `json:"name"`
	UID        *uint32 `json:"uid"`
	GID        *uint32 `json:"gid"`
	Shell      *string `json:"shell"`
	LoginShell *bool   `json:"login_shell"`
}

// Only this optional inventory extension has a closed schema. Older reports
// and other inventory extensions retain their existing snapshot semantics.
func validateSSHAccountsInventory(data json.RawMessage) error {
	inventories, err := inventoryObjectFields(data, "inventory")
	if err != nil {
		return errSSHAccountsInventory
	}
	for _, inventory := range inventories {
		accounts, err := inventoryObjectFields(inventory, "ssh_accounts")
		if err != nil {
			return errSSHAccountsInventory
		}
		for _, snapshot := range accounts {
			if err := validateSSHAccountsSnapshot(snapshot); err != nil {
				return err
			}
		}
	}
	return nil
}

// Inspect every occurrence instead of decoding into a map: an overwritten
// duplicate must not hide an unvalidated account object in the retained JSON.
// Non-object legacy inventory values have no SSH account extension to inspect.
func inventoryObjectFields(raw json.RawMessage, name string) ([]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if start != json.Delim('{') {
		return nil, nil
	}
	var values []json.RawMessage
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if field, ok := key.(string); ok && strings.EqualFold(field, name) {
			values = append(values, value)
		}
	}
	_, err = decoder.Token()
	return values, err
}

func validateSSHAccountsSnapshot(raw json.RawMessage) error {
	if len(raw) > maxSSHAccountsInventoryBytes || !utf8.Valid(raw) {
		return errSSHAccountsInventory
	}
	var snapshot struct {
		State     string              `json:"state"`
		Source    string              `json:"source"`
		CheckedAt time.Time           `json:"checked_at"`
		Total     *uint64             `json:"total"`
		Truncated *bool               `json:"truncated"`
		Users     *[]sshInventoryUser `json:"users"`
		Error     json.RawMessage     `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&snapshot) != nil || snapshot.Source != "/etc/passwd" || snapshot.CheckedAt.IsZero() || snapshot.Total == nil || snapshot.Truncated == nil || snapshot.Users == nil || len(*snapshot.Users) > maxSSHInventoryUsers {
		return errSSHAccountsInventory
	}
	if len(snapshot.Error) > 0 {
		var message string
		if bytes.Equal(bytes.TrimSpace(snapshot.Error), []byte("null")) || json.Unmarshal(snapshot.Error, &message) != nil || len(message) > 4096 {
			return errSSHAccountsInventory
		}
	}
	switch snapshot.State {
	case "ready":
		count := uint64(len(*snapshot.Users))
		if *snapshot.Total < count || (!*snapshot.Truncated && *snapshot.Total != count) {
			return errSSHAccountsInventory
		}
	case "error", "unsupported":
		if *snapshot.Total != 0 || *snapshot.Truncated || len(*snapshot.Users) != 0 {
			return errSSHAccountsInventory
		}
	default:
		return errSSHAccountsInventory
	}
	names := map[string]bool{}
	for _, account := range *snapshot.Users {
		if len(account.Name) > 128 || !sudoAccountName.MatchString(account.Name) || names[account.Name] || account.UID == nil || account.GID == nil || account.Shell == nil || len(*account.Shell) > 256 || strings.ContainsFunc(*account.Shell, unicode.IsControl) || account.LoginShell == nil {
			return errSSHAccountsInventory
		}
		names[account.Name] = true
	}
	return nil
}
