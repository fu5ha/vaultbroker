package broker

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	VaultwardenURL    string   `json:"vaultwarden_url"`
	OrganizationID    string   `json:"organization_id"`
	CollectionID      string   `json:"collection_id"`
	RPID              string   `json:"rp_id"`
	WebAuthnUser      string   `json:"webauthn_user"`
	RPOrigin          string   `json:"rp_origin"`
	WebAddr           string   `json:"web_addr"`
	SocketPath        string   `json:"socket_path"`
	HelperURL         string   `json:"helper_url"`
	HelperToken       string   `json:"helper_token"`
	AuditPath         string   `json:"audit_path"`
	CredentialPath    string   `json:"credential_path"`
	ScopePath         string   `json:"scope_path"`
	RegisterTokenPath string   `json:"register_token_path"`
	BWPath            string   `json:"bw_path"`
	AllowedUIDs       []uint32 `json:"allowed_uids"`
}

func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		WebAuthnUser:      "owner",
		WebAddr:           "127.0.0.1:8799",
		SocketPath:        "/run/vaultbroker/broker.sock",
		HelperURL:         "http://127.0.0.1:8795",
		AuditPath:         "/var/lib/vaultbroker/audit.log",
		CredentialPath:    "/var/lib/vaultbroker/credential.json",
		ScopePath:         "/var/lib/vaultbroker/scope.json",
		RegisterTokenPath: "/var/lib/vaultbroker/register-token",
		BWPath:            "/usr/bin/bw",
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	for name, value := range map[string]string{
		"vaultwarden_url": cfg.VaultwardenURL,
		"rp_id":           cfg.RPID,
		"rp_origin":       cfg.RPOrigin,
		"helper_token":    cfg.HelperToken,
	} {
		if value == "" {
			return Config{}, fmt.Errorf("config: %s is required", name)
		}
	}
	if len(cfg.AllowedUIDs) == 0 {
		return Config{}, fmt.Errorf("config: allowed_uids must not be empty")
	}
	return cfg, nil
}

func (c Config) AllowsUID(uid uint32) bool {
	for _, allowed := range c.AllowedUIDs {
		if allowed == uid {
			return true
		}
	}
	return false
}
