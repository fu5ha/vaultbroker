// Package bw is the boundary to the Bitwarden CLI. It parses bw's JSON into
// metadata types here; secret values leave this package only inside
// FillValues, which the broker hands straight to the helper client.
// Passwords reach bw through an environment variable, never argv.
package bw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const passwordEnv = "VAULTBROKER_BW_PASSWORD"

type Client struct {
	path      string
	serverURL string
	home      string // bw's data dir lives under the broker user's $HOME

	mu           sync.RWMutex
	orgID        string
	collectionID string
}

func New(path, serverURL, home string) *Client {
	return &Client{path: path, serverURL: serverURL, home: home}
}

// SetScope pins the organization and collection every search and fill is
// restricted to. The broker calls it once the scope is known: from config,
// from its persisted scope file, or from auto-discovery at first unlock.
func (c *Client) SetScope(orgID, collectionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.orgID, c.collectionID = orgID, collectionID
}

func (c *Client) scope() (string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.orgID, c.collectionID
}

// ItemMeta is everything vault_search may show the agent: names, ids, URIs,
// field names. No values.
type ItemMeta struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	OrganizationID string   `json:"organization_id"`
	CollectionIDs  []string `json:"collection_ids"`
	URIs           []string `json:"uris"`
	HasUsername    bool     `json:"has_username"`
	HasPassword    bool     `json:"has_password"`
	HasTOTP        bool     `json:"has_totp"`
	CustomFields   []string `json:"custom_fields"`
}

// FillValues carries secret values for exactly one approved fill. It never
// crosses the socket API and is never written to disk.
type FillValues struct {
	Username string
	Password string
	TOTP     string
	Custom   map[string]string
}

type rawItem struct {
	ID             string   `json:"id"`
	OrganizationID string   `json:"organizationId"`
	CollectionIDs  []string `json:"collectionIds"`
	Name           string   `json:"name"`
	Type           int      `json:"type"`
	Login          *struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
		URIs     []struct {
			URI string `json:"uri"`
		} `json:"uris"`
	} `json:"login"`
	Fields []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"fields"`
}

const itemTypeLogin = 1

func (c *Client) run(ctx context.Context, session string, env map[string]string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.path, args...)
	// Pin bw's data under the broker user's home. HOME alone is not enough:
	// an inherited XDG_CONFIG_HOME wins over it, so use bw's own override.
	cmd.Env = append(os.Environ(),
		"HOME="+c.home,
		"BITWARDENCLI_APPDATA_DIR="+filepath.Join(c.home, "bw"),
	)
	if session != "" {
		cmd.Env = append(cmd.Env, "BW_SESSION="+session)
	}
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// stderr only, never stdout: for `get item`, stdout carries secret
		// values, and error strings can reach the agent. bw puts its human
		// error text on stderr.
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("bw %s: %v: %s", args[0], err, msg)
	}
	return stdout.Bytes(), nil
}

// AuthState reports bw's own view: "unauthenticated" (never logged in on
// this machine), "locked", or "unlocked". The unlock page uses it to
// show the first-time login form only when login is actually needed.
func (c *Client) AuthState(ctx context.Context) (string, error) {
	out, err := c.run(ctx, "", nil, "status")
	if err != nil {
		return "", err
	}
	var status struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(out, &status); err != nil {
		return "", fmt.Errorf("bw status: parse output: %w", err)
	}
	return status.Status, nil
}

func (c *Client) ConfigureServer(ctx context.Context) error {
	_, err := c.run(ctx, "", nil, "config", "server", c.serverURL)
	return err
}

func (c *Client) Login(ctx context.Context, email, password string) (string, error) {
	if err := c.ConfigureServer(ctx); err != nil {
		return "", err
	}
	out, err := c.run(ctx, "", map[string]string{passwordEnv: password},
		"login", email, "--passwordenv", passwordEnv, "--raw", "--nointeraction")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (c *Client) Unlock(ctx context.Context, password string) (string, error) {
	out, err := c.run(ctx, "", map[string]string{passwordEnv: password},
		"unlock", "--passwordenv", passwordEnv, "--raw", "--nointeraction")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (c *Client) Lock(ctx context.Context, session string) error {
	_, err := c.run(ctx, session, nil, "lock")
	return err
}

func (c *Client) Sync(ctx context.Context, session string) error {
	_, err := c.run(ctx, session, nil, "sync")
	return err
}

func (c *Client) inScope(item rawItem) bool {
	orgID, collectionID := c.scope()
	if item.OrganizationID != orgID {
		return false
	}
	for _, id := range item.CollectionIDs {
		if id == collectionID {
			return true
		}
	}
	return false
}

func (c *Client) Search(ctx context.Context, session, query string) ([]ItemMeta, error) {
	orgID, collectionID := c.scope()
	args := []string{"list", "items",
		"--organizationid", orgID,
		"--collectionid", collectionID}
	if query != "" {
		args = append(args, "--search", query)
	}
	out, err := c.run(ctx, session, nil, args...)
	if err != nil {
		return nil, err
	}
	var raw []rawItem
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("bw list items: parse output: %w", err)
	}
	items := []ItemMeta{}
	for _, item := range raw {
		// bw already filters by org and collection; check again here so a
		// bw behaviour change can't widen the scope silently.
		if item.Type != itemTypeLogin || item.Login == nil || !c.inScope(item) {
			continue
		}
		items = append(items, metaOf(item))
	}
	return items, nil
}

func metaOf(item rawItem) ItemMeta {
	meta := ItemMeta{
		ID:             item.ID,
		Name:           item.Name,
		OrganizationID: item.OrganizationID,
		CollectionIDs:  item.CollectionIDs,
		HasUsername:    item.Login.Username != "",
		HasPassword:    item.Login.Password != "",
		HasTOTP:        item.Login.TOTP != "",
		URIs:           []string{},
		CustomFields:   []string{},
	}
	for _, uri := range item.Login.URIs {
		meta.URIs = append(meta.URIs, uri.URI)
	}
	for _, field := range item.Fields {
		meta.CustomFields = append(meta.CustomFields, field.Name)
	}
	return meta
}

// ItemMeta resolves one item's metadata for request creation, enforcing
// the same scope as Search.
func (c *Client) ItemMeta(ctx context.Context, session, itemID string) (ItemMeta, error) {
	out, err := c.run(ctx, session, nil, "get", "item", itemID)
	if err != nil {
		return ItemMeta{}, err
	}
	var item rawItem
	if err := json.Unmarshal(out, &item); err != nil {
		return ItemMeta{}, fmt.Errorf("bw get item: parse output: %w", err)
	}
	if item.Type != itemTypeLogin || item.Login == nil || !c.inScope(item) {
		return ItemMeta{}, fmt.Errorf("item %s is outside the agent collection", itemID)
	}
	return metaOf(item), nil
}

type OrgInfo struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Collections []CollectionInfo `json:"collections"`
}

type CollectionInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Discover lists organizations and their collections (ids and names only).
// It exists for first-time provisioning: the broker exposes it only while
// no organization/collection is pinned in the config yet.
func (c *Client) Discover(ctx context.Context, session string) ([]OrgInfo, error) {
	out, err := c.run(ctx, session, nil, "list", "organizations")
	if err != nil {
		return nil, err
	}
	var orgs []OrgInfo
	if err := json.Unmarshal(out, &orgs); err != nil {
		return nil, fmt.Errorf("bw list organizations: parse output: %w", err)
	}
	for i := range orgs {
		out, err := c.run(ctx, session, nil, "list", "org-collections", "--organizationid", orgs[i].ID)
		if err != nil {
			return nil, err
		}
		orgs[i].Collections = []CollectionInfo{}
		if err := json.Unmarshal(out, &orgs[i].Collections); err != nil {
			return nil, fmt.Errorf("bw list org-collections: parse output: %w", err)
		}
	}
	return orgs, nil
}

func (c *Client) ValuesForFill(ctx context.Context, session, itemID string, withTOTP bool) (FillValues, error) {
	out, err := c.run(ctx, session, nil, "get", "item", itemID)
	if err != nil {
		return FillValues{}, err
	}
	var item rawItem
	if err := json.Unmarshal(out, &item); err != nil {
		return FillValues{}, fmt.Errorf("bw get item: parse output: %w", err)
	}
	if item.Type != itemTypeLogin || item.Login == nil || !c.inScope(item) {
		return FillValues{}, fmt.Errorf("item %s is outside the agent collection", itemID)
	}
	values := FillValues{
		Username: item.Login.Username,
		Password: item.Login.Password,
		Custom:   map[string]string{},
	}
	for _, field := range item.Fields {
		values.Custom[field.Name] = field.Value
	}
	if withTOTP && item.Login.TOTP != "" {
		code, err := c.run(ctx, session, nil, "get", "totp", itemID)
		if err != nil {
			return FillValues{}, err
		}
		values.TOTP = strings.TrimSpace(string(code))
	}
	return values, nil
}
