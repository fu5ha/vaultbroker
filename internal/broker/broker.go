package broker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fu5ha/vaultbroker/internal/bw"
	"github.com/fu5ha/vaultbroker/internal/helper"
)

type VaultState int

const (
	Locked VaultState = iota
	Unlocked
)

func (s VaultState) String() string {
	if s == Unlocked {
		return "unlocked"
	}
	return "locked"
}

type RequestState string

const (
	Pending   RequestState = "pending"
	Approved  RequestState = "approved"
	Denied    RequestState = "denied"
	Expired   RequestState = "expired"
	Executing RequestState = "executing"
	Succeeded RequestState = "succeeded"
	Failed    RequestState = "failed"
)

var transitions = map[RequestState][]RequestState{
	Pending:   {Approved, Denied, Expired},
	Approved:  {Executing},
	Executing: {Succeeded, Failed},
}

func (s RequestState) Terminal() bool {
	switch s {
	case Denied, Expired, Succeeded, Failed:
		return true
	}
	return false
}

// What the agent asks to fill, and where. Field names only: a Request never
// holds a secret value. Values exist only inside executeFill, in transit
// from bw to the helper.
type FillField struct {
	Field    string `json:"field"`
	Selector string `json:"selector,omitempty"`
	Ref      string `json:"ref,omitempty"`
}

type FillParams struct {
	ItemID        string      `json:"item_id"`
	ItemName      string      `json:"item_name"`
	ItemURIs      []string    `json:"item_uris"`
	Session       string      `json:"session"`
	Origin        string      `json:"origin"`
	Fields        []FillField `json:"fields"`
	NotifySession string      `json:"notify_session,omitempty"`
}

type FieldResult struct {
	Field string `json:"field"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type FillResult struct {
	Fields []FieldResult `json:"fields"`
}

type Request struct {
	ID        string       `json:"id"`
	State     RequestState `json:"state"`
	CreatedAt time.Time    `json:"created_at"`
	ExpiresAt time.Time    `json:"expires_at"`
	Hash      string       `json:"hash"`
	Fill      FillParams   `json:"fill"`
	Result    *FillResult  `json:"result,omitempty"`
	Error     string       `json:"error,omitempty"`
}

type Status struct {
	Vault      string `json:"vault"`
	Configured bool   `json:"configured"`
	Pending    int    `json:"pending"`
}

const ApprovalWindow = 5 * time.Minute

var (
	ErrLocked       = errors.New("vault is locked")
	ErrUnconfigured = errors.New("vault scope not pinned yet; unlock once so the broker can discover it")
)

type Broker struct {
	cfg    Config
	audit  *AuditLog
	bw     *bw.Client
	helper *helper.Client

	mu               sync.Mutex
	vault            VaultState
	session          string // BW_SESSION; memory only, never logged or persisted
	requests         map[string]*Request
	orgID            string
	collectionID     string
	unlockNotifySent bool
}

func New(cfg Config, audit *AuditLog, bwClient *bw.Client, helperClient *helper.Client) *Broker {
	b := &Broker{
		cfg:      cfg,
		audit:    audit,
		bw:       bwClient,
		helper:   helperClient,
		vault:    Locked,
		requests: make(map[string]*Request),
	}
	if cfg.OrganizationID != "" && cfg.CollectionID != "" {
		b.setScope(cfg.OrganizationID, cfg.CollectionID)
	}
	return b
}

func (b *Broker) setScope(orgID, collectionID string) {
	b.mu.Lock()
	b.orgID, b.collectionID = orgID, collectionID
	b.mu.Unlock()
	b.bw.SetScope(orgID, collectionID)
}

func (b *Broker) scoped() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.orgID != "" && b.collectionID != ""
}

func (b *Broker) Config() Config { return b.cfg }

func (b *Broker) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	pending := 0
	for _, req := range b.requests {
		if req.State == Pending {
			pending++
		}
	}
	return Status{
		Vault:      b.vault.String(),
		Configured: b.orgID != "" && b.collectionID != "",
		Pending:    pending,
	}
}

func (b *Broker) transition(req *Request, to RequestState) error {
	for _, allowed := range transitions[req.State] {
		if allowed == to {
			req.State = to
			return nil
		}
	}
	return fmt.Errorf("request %s: %s -> %s is not a valid transition", req.ID, req.State, to)
}

func (b *Broker) setSession(session string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.vault = Unlocked
	b.session = session
	b.unlockNotifySent = false
}

// notifyUnlockRequested Signals the owner that the agent is waiting on an
// unlock, at most once per locked episode. The unlock link is
// passkey-gated; the message is a wake-up, not a credential.
func (b *Broker) notifyUnlockRequested() {
	b.mu.Lock()
	if b.vault == Unlocked || b.unlockNotifySent {
		b.mu.Unlock()
		return
	}
	b.unlockNotifySent = true
	b.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		msg := "Vaultbroker: the agent asked for the vault to be unlocked. Unlock here:\n" + b.cfg.RPOrigin + "/unlock"
		outcome := "sent"
		if err := b.helper.Notify(ctx, msg); err != nil {
			outcome = "failed"
			b.mu.Lock()
			b.unlockNotifySent = false // let a later attempt retry
			b.mu.Unlock()
		}
		b.audit.Write(AuditEvent{Event: "vault.unlock_notify", Outcome: outcome})
	}()
}

// WaitUnlocked blocks until the vault is unlocked or ctx ends. The MCP
// shim uses it to wake its agent session after the owner unlocks, instead of
// the agent polling vault_status. Arming the wait is also the agent's
// signal that it wants the vault unlocked, so the owner gets a Signal.
func (b *Broker) WaitUnlocked(ctx context.Context) error {
	b.notifyUnlockRequested()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := b.currentSession(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (b *Broker) currentSession() (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.vault != Unlocked {
		return "", ErrLocked
	}
	return b.session, nil
}

// Login performs the first-time bw login for the agent account. The owner
// supplies the credentials through the passkey-gated web page; they pass
// straight to bw and are never stored.
func (b *Broker) Login(ctx context.Context, email, password string) error {
	session, err := b.bw.Login(ctx, email, password)
	if err != nil {
		b.audit.Write(AuditEvent{Event: "vault.login", Outcome: "failed"})
		return err
	}
	b.setSession(session)
	b.audit.Write(AuditEvent{Event: "vault.login", Outcome: "unlocked"})
	if err := b.bw.Sync(ctx, session); err != nil {
		return err
	}
	b.pinScope(ctx, session)
	return nil
}

// NeedsLogin reports whether this machine has ever logged in to the agent
// account, per bw's own state. The unlock page shows its first-time login
// form only in that case.
func (b *Broker) NeedsLogin(ctx context.Context) bool {
	state, err := b.bw.AuthState(ctx)
	return err != nil || state == "unauthenticated"
}

func (b *Broker) Unlock(ctx context.Context, password string) error {
	session, err := b.bw.Unlock(ctx, password)
	if err != nil {
		b.audit.Write(AuditEvent{Event: "vault.unlock", Outcome: "failed"})
		return err
	}
	b.setSession(session)
	b.audit.Write(AuditEvent{Event: "vault.unlock", Outcome: "unlocked"})
	if err := b.bw.Sync(ctx, session); err != nil {
		return err
	}
	b.pinScope(ctx, session)
	return nil
}

func (b *Broker) Lock(ctx context.Context) {
	b.mu.Lock()
	session := b.session
	b.vault = Locked
	b.session = ""
	b.mu.Unlock()
	if session != "" {
		_ = b.bw.Lock(ctx, session)
	}
	b.audit.Write(AuditEvent{Event: "vault.locked"})
}

// Discover supports manual provisioning when auto-pinning is ambiguous
// (more than one org or collection). Once a scope is pinned, it refuses.
func (b *Broker) Discover(ctx context.Context) ([]bw.OrgInfo, error) {
	if b.scoped() {
		return nil, errors.New("already configured; discovery disabled")
	}
	session, err := b.currentSession()
	if err != nil {
		return nil, err
	}
	return b.bw.Discover(ctx, session)
}

func (b *Broker) Search(ctx context.Context, query string) ([]bw.ItemMeta, error) {
	if !b.scoped() {
		return nil, ErrUnconfigured
	}
	session, err := b.currentSession()
	if err != nil {
		return nil, err
	}
	return b.bw.Search(ctx, session, query)
}
