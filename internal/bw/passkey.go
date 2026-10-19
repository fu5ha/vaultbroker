package bw

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// PasskeyCredential carries one vault passkey in the shape Chrome's
// DevTools Protocol WebAuthn.addCredential consumes. PrivateKey is a
// secret value: it never crosses the socket API, is never written to
// disk, and reaches only the helper, inside one approved request.
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

// Bitwarden stores a login item's passkeys as login.fido2Credentials.
// keyValue is the private key (base64url PKCS#8), credentialId is a
// UUID string or a "b64."-prefixed base64url byte string, counter is a
// decimal string, and discoverable is "true"/"false".
type rawFido2Credential struct {
	CredentialID    string `json:"credentialId"`
	KeyType         string `json:"keyType"`
	KeyAlgorithm    string `json:"keyAlgorithm"`
	KeyCurve        string `json:"keyCurve"`
	KeyValue        string `json:"keyValue"`
	RPID            string `json:"rpId"`
	UserHandle      string `json:"userHandle"`
	UserName        string `json:"userName"`
	Counter         string `json:"counter"`
	UserDisplayName string `json:"userDisplayName"`
	Discoverable    string `json:"discoverable"`
}

// RPIDMatchesHost reports whether a WebAuthn ceremony on host may use a
// credential scoped to rpID: the host is the RP ID or a subdomain of it.
func RPIDMatchesHost(rpID, host string) bool {
	rpID = strings.ToLower(rpID)
	host = strings.ToLower(host)
	return host == rpID || strings.HasSuffix(host, "."+rpID)
}

// PasskeyForAssertion resolves the single passkey for rpID stored on a
// scoped item, converted for the helper.
func (c *Client) PasskeyForAssertion(ctx context.Context, session, itemID, rpID string) (PasskeyCredential, error) {
	out, err := c.run(ctx, session, nil, "get", "item", itemID)
	if err != nil {
		return PasskeyCredential{}, err
	}
	var item rawItem
	if err := json.Unmarshal(out, &item); err != nil {
		return PasskeyCredential{}, fmt.Errorf("bw get item: parse output: %w", err)
	}
	if item.Type != itemTypeLogin || item.Login == nil || !c.inScope(item) {
		return PasskeyCredential{}, fmt.Errorf("item %s is outside the agent collection", itemID)
	}
	var matches []rawFido2Credential
	for _, cred := range item.Login.Fido2Credentials {
		if strings.EqualFold(cred.RPID, rpID) {
			matches = append(matches, cred)
		}
	}
	if len(matches) != 1 {
		return PasskeyCredential{}, fmt.Errorf("item %s holds %d passkeys for rp %s, want exactly 1", itemID, len(matches), rpID)
	}
	return convertPasskey(matches[0])
}

// Error strings in this conversion never quote stored field values:
// they reach the agent through the request result.
func convertPasskey(raw rawFido2Credential) (PasskeyCredential, error) {
	if raw.KeyAlgorithm != "" && raw.KeyAlgorithm != "ECDSA" {
		return PasskeyCredential{}, fmt.Errorf("passkey key algorithm is not supported")
	}
	if raw.KeyCurve != "" && raw.KeyCurve != "P-256" {
		return PasskeyCredential{}, fmt.Errorf("passkey key curve is not supported")
	}
	credID, err := credentialIDBytes(raw.CredentialID)
	if err != nil {
		return PasskeyCredential{}, err
	}
	keyBytes, err := decodeBase64URL(raw.KeyValue)
	if err != nil {
		return PasskeyCredential{}, fmt.Errorf("passkey private key is not base64url")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return PasskeyCredential{}, fmt.Errorf("passkey private key is not PKCS#8")
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || ecKey.Curve != elliptic.P256() {
		return PasskeyCredential{}, fmt.Errorf("passkey private key is not ECDSA P-256")
	}

	cred := PasskeyCredential{
		CredentialID: base64.StdEncoding.EncodeToString(credID),
		RPID:         raw.RPID,
		PrivateKey:   base64.StdEncoding.EncodeToString(keyBytes),
		// CDP encodes "no signature counter" as -1: assertions then
		// always report signCount 0. That is Bitwarden's own counter-0
		// behavior, so 0 stays -1 below; only a legacy stored counter
		// above zero seeds a real, incrementing counter.
		SignCount: -1,
		// A vault-stored passkey is a synced credential; its assertions
		// carry backup eligibility and state.
		BackupEligibility: true,
		BackupState:       true,
		UserName:          raw.UserName,
		UserDisplayName:   raw.UserDisplayName,
	}
	switch strings.ToLower(raw.Discoverable) {
	case "true":
		cred.IsResidentCredential = true
	case "false", "":
	default:
		return PasskeyCredential{}, fmt.Errorf("passkey discoverable flag is not understood")
	}
	if raw.UserHandle != "" {
		handle, err := decodeBase64URL(raw.UserHandle)
		if err != nil {
			return PasskeyCredential{}, fmt.Errorf("passkey user handle is not base64url")
		}
		cred.UserHandle = base64.StdEncoding.EncodeToString(handle)
	}
	if raw.Counter != "" {
		count, err := strconv.ParseUint(raw.Counter, 10, 32)
		if err != nil {
			return PasskeyCredential{}, fmt.Errorf("passkey counter is not a number")
		}
		if count > 0 {
			cred.SignCount = int(count)
		}
	}
	return cred, nil
}

func credentialIDBytes(id string) ([]byte, error) {
	if rest, ok := strings.CutPrefix(id, "b64."); ok {
		b, err := decodeBase64URL(rest)
		if err != nil {
			return nil, fmt.Errorf("passkey credential id is not base64url")
		}
		return b, nil
	}
	// UUID in canonical text form; Bitwarden maps it to the raw 16
	// bytes in the order written.
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return nil, fmt.Errorf("passkey credential id is neither a UUID nor b64.-prefixed")
	}
	b, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil || len(b) != 16 {
		return nil, fmt.Errorf("passkey credential id is not a valid UUID")
	}
	return b, nil
}

func decodeBase64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
