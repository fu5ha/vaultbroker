// Package helper talks to browser_helper.py inside the helpers container,
// published on host loopback only. The bearer token gates the two broker
// endpoints; the agent already owns that container, so the token protects
// the endpoints from other local processes, not from the agent. Fill values
// cross this boundary, which is the known weak point of vault_browser_fill:
// the container runs as the agent's user.
package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		// A passkey login waits on the site's ceremony, so the
		// timeout has to cover a slow page, not just helper time.
		http: &http.Client{Timeout: 90 * time.Second},
	}
}

type FillAssignment struct {
	Selector string `json:"selector,omitempty"`
	Ref      string `json:"ref,omitempty"`
	Value    string `json:"value"`
}

type AssignmentResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("helper %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return fmt.Errorf("helper %s %s: %s", method, path, e.Error)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Notify sends the owner a Signal message through the in-container signal-cli.
// It is a wake-up only; the approval link inside approves nothing by itself.
func (c *Client) Notify(ctx context.Context, message string) error {
	return c.call(ctx, http.MethodPost, "/notify", map[string]string{"message": message}, nil)
}

func (c *Client) CurrentOrigin(ctx context.Context, session string) (string, error) {
	var out struct {
		Origin string `json:"origin"`
	}
	if err := c.call(ctx, http.MethodGet, "/services/"+session+"/origin", nil, &out); err != nil {
		return "", err
	}
	return out.Origin, nil
}

// PasskeyCredential is one credential in CDP WebAuthn.addCredential
// shape. PrivateKey crosses this boundary only inside one approved
// Passkey call, like fill values.
type PasskeyCredential struct {
	CredentialID         string `json:"credentialId"`
	IsResidentCredential bool   `json:"isResidentCredential"`
	RPID                 string `json:"rpId"`
	PrivateKey           string `json:"privateKey"`
	UserHandle           string `json:"userHandle,omitempty"`
	SignCount            int    `json:"signCount"`
	BackupEligibility    bool   `json:"backupEligibility"`
	BackupState          bool   `json:"backupState"`
	UserName             string `json:"userName,omitempty"`
	UserDisplayName      string `json:"userDisplayName,omitempty"`
}

type PasskeyTrigger struct {
	Selector string `json:"selector,omitempty"`
	Ref      string `json:"ref,omitempty"`
}

type PasskeyResult struct {
	CeremonyRPID string `json:"ceremony_rp_id"`
}

// Passkey runs one approved passkey login: the helper clicks the
// trigger, catches the site's WebAuthn ceremony, loads the credential
// into a virtual authenticator long enough for that ceremony, and
// removes it before returning.
func (c *Client) Passkey(ctx context.Context, session, expectedOrigin string, trigger PasskeyTrigger, credential PasskeyCredential) (PasskeyResult, error) {
	var out PasskeyResult
	err := c.call(ctx, http.MethodPost, "/services/"+session+"/vault-passkey",
		map[string]any{"expected_origin": expectedOrigin, "trigger": trigger, "credential": credential}, &out)
	return out, err
}

func (c *Client) Fill(ctx context.Context, session, expectedOrigin string, assignments []FillAssignment) ([]AssignmentResult, error) {
	var out struct {
		Results []AssignmentResult `json:"results"`
	}
	err := c.call(ctx, http.MethodPost, "/services/"+session+"/vault-fill",
		map[string]any{"assignments": assignments, "expected_origin": expectedOrigin}, &out)
	return out.Results, err
}
