package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

type scopeFile struct {
	OrganizationID string `json:"organization_id"`
	CollectionID   string `json:"collection_id"`
}

// LoadScope restores the pinned scope at startup. Config values win over
// the scope file; main calls this only when the config sets neither ID.
func (b *Broker) LoadScope() error {
	if b.scoped() {
		return nil
	}
	raw, err := os.ReadFile(b.cfg.ScopePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var scope scopeFile
	if err := json.Unmarshal(raw, &scope); err != nil {
		return fmt.Errorf("parse %s: %w", b.cfg.ScopePath, err)
	}
	if scope.OrganizationID != "" && scope.CollectionID != "" {
		b.setScope(scope.OrganizationID, scope.CollectionID)
	}
	return nil
}

// pinScope runs after a successful unlock. With exactly one organization
// holding exactly one accessible collection, the scope is unambiguous:
// pin it and persist it, so nobody hand-copies UUIDs into a config file.
// Anything else stays unpinned for manual provisioning via discover.
func (b *Broker) pinScope(ctx context.Context, session string) {
	if b.scoped() {
		return
	}
	orgs, err := b.bw.Discover(ctx, session)
	if err != nil {
		b.audit.Write(AuditEvent{Event: "scope.pin", Outcome: "discovery failed"})
		return
	}
	if len(orgs) != 1 || len(orgs[0].Collections) != 1 {
		b.audit.Write(AuditEvent{Event: "scope.pin", Outcome: fmt.Sprintf("ambiguous: %d orgs", len(orgs))})
		return
	}
	org, collection := orgs[0].ID, orgs[0].Collections[0].ID
	raw, err := json.Marshal(scopeFile{OrganizationID: org, CollectionID: collection})
	if err == nil {
		err = os.WriteFile(b.cfg.ScopePath, raw, 0o600)
	}
	if err != nil {
		b.audit.Write(AuditEvent{Event: "scope.pin", Outcome: "persist failed"})
		return
	}
	b.setScope(org, collection)
	b.audit.Write(AuditEvent{Event: "scope.pin", Outcome: org + "/" + collection})
}
