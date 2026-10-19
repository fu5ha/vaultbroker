package broker

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/fu5ha/vaultbroker/internal/bw"
	"github.com/fu5ha/vaultbroker/internal/helper"
)

// CreatePasskey records an approval request for a passkey login. Like
// CreateFill, what the owner approves is broker-observed: the broker
// resolves the item's stored passkey and the page's current origin
// itself, and derives the RP ID the ceremony must use — the stored
// passkey whose RP ID covers the current host. The agent names only
// the item, the session, and the control that starts the ceremony.
func (b *Broker) CreatePasskey(ctx context.Context, in PasskeyParams) (Request, error) {
	if !b.scoped() {
		return Request{}, ErrUnconfigured
	}
	session, err := b.currentSession()
	if err != nil {
		b.notifyUnlockRequested()
		return Request{}, err
	}
	if in.ItemID == "" || in.Session == "" {
		return Request{}, fmt.Errorf("item_id and session are required")
	}
	if (in.Trigger.Selector == "") == (in.Trigger.Ref == "") {
		return Request{}, fmt.Errorf("trigger: exactly one of selector/ref")
	}
	meta, err := b.bw.ItemMeta(ctx, session, in.ItemID)
	if err != nil {
		return Request{}, err
	}
	if !meta.HasPasskey {
		return Request{}, fmt.Errorf("item %s holds no passkey", in.ItemID)
	}
	origin, err := b.helper.CurrentOrigin(ctx, in.Session)
	if err != nil {
		return Request{}, err
	}
	rpID, err := passkeyRPIDForOrigin(meta.PasskeyRPIDs, origin)
	if err != nil {
		return Request{}, err
	}
	in.ItemName = meta.Name
	in.ItemURIs = meta.URIs
	in.Origin = origin
	in.RPID = rpID

	now := time.Now()
	params := in
	req := &Request{
		ID:        newRequestID(),
		Kind:      KindPasskey,
		State:     Pending,
		CreatedAt: now,
		ExpiresAt: now.Add(ApprovalWindow),
		Passkey:   &params,
	}
	req.Hash = requestHash(req)

	b.mu.Lock()
	b.requests[req.ID] = req
	b.mu.Unlock()

	b.auditRequest("request.created", req, "pending")
	go b.notifyApproval(req)
	return *req, nil
}

func passkeyRPIDForOrigin(rpIDs []string, origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("page origin %q has no host", origin)
	}
	var matches []string
	for _, rpID := range rpIDs {
		if bw.RPIDMatchesHost(rpID, u.Hostname()) {
			matches = append(matches, rpID)
		}
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("item holds %d passkeys usable at host %s, want exactly 1", len(matches), u.Hostname())
	}
	return matches[0], nil
}

// executePasskey runs one approved passkey login. The private key
// exists only in this call: from bw into the helper request. The
// helper reports the RP ID the site's ceremony actually asked for;
// it must be the approved one.
func (b *Broker) executePasskey(ctx context.Context, params PasskeyParams) (*PasskeyResult, error) {
	session, err := b.currentSession()
	if err != nil {
		return nil, err
	}
	origin, err := b.helper.CurrentOrigin(ctx, params.Session)
	if err != nil {
		return nil, err
	}
	if origin != params.Origin {
		return nil, fmt.Errorf("page origin changed since approval (%s -> %s)", params.Origin, origin)
	}
	cred, err := b.bw.PasskeyForAssertion(ctx, session, params.ItemID, params.RPID)
	if err != nil {
		return nil, err
	}
	trigger := helper.PasskeyTrigger{Selector: params.Trigger.Selector, Ref: params.Trigger.Ref}
	result, err := b.helper.Passkey(ctx, params.Session, params.Origin, trigger, helperCredential(cred))
	if err != nil {
		return nil, fmt.Errorf("%s", scrubSecrets(err.Error(), cred.PrivateKey, cred.CredentialID))
	}
	if !strings.EqualFold(result.CeremonyRPID, params.RPID) {
		return nil, fmt.Errorf("ceremony RP ID %q does not match the approved %q", result.CeremonyRPID, params.RPID)
	}
	return &PasskeyResult{CeremonyRPID: result.CeremonyRPID}, nil
}

func helperCredential(cred bw.PasskeyCredential) helper.PasskeyCredential {
	return helper.PasskeyCredential{
		CredentialID:         cred.CredentialID,
		IsResidentCredential: cred.IsResidentCredential,
		RPID:                 cred.RPID,
		PrivateKey:           cred.PrivateKey,
		UserHandle:           cred.UserHandle,
		SignCount:            cred.SignCount,
		BackupEligibility:    cred.BackupEligibility,
		BackupState:          cred.BackupState,
		UserName:             cred.UserName,
		UserDisplayName:      cred.UserDisplayName,
	}
}

func (b *Broker) finishPasskey(req *Request, result *PasskeyResult, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	req.PasskeyResult = result
	to := Succeeded
	if err != nil {
		to = Failed
		req.Error = err.Error()
	}
	_ = b.transition(req, to)
	b.auditRequestLocked("request.executed", req, string(to))
}
