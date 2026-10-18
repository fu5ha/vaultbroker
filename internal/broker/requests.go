package broker

import (
	"fmt"
	"sort"
	"time"
)

// expireLocked settles a pending request whose approval window has passed.
// Caller holds b.mu.
func (b *Broker) expireLocked(req *Request) {
	if req.State == Pending && time.Now().After(req.ExpiresAt) {
		if err := b.transition(req, Expired); err == nil {
			b.audit.Write(AuditEvent{
				Event: "request.expired", RequestID: req.ID,
				ItemID: req.Fill.ItemID, ItemName: req.Fill.ItemName, Outcome: "expired",
			})
		}
	}
}

func (b *Broker) Request(id string) (Request, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	req, ok := b.requests[id]
	if !ok {
		return Request{}, false
	}
	b.expireLocked(req)
	return *req, true
}

func (b *Broker) Pending() []Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	pending := []Request{}
	for _, req := range b.requests {
		b.expireLocked(req)
		if req.State == Pending {
			pending = append(pending, *req)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].CreatedAt.Before(pending[j].CreatedAt) })
	return pending
}

// Decide records the owner's approval or denial. The web layer authenticates
// the decision (session + CSRF, plus a fresh passkey assertion to approve);
// this method only enforces the lifecycle.
func (b *Broker) Decide(id string, approve bool) (Request, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	req, ok := b.requests[id]
	if !ok {
		return Request{}, fmt.Errorf("unknown request %s", id)
	}
	b.expireLocked(req)
	to := Denied
	event := "request.denied"
	if approve {
		to = Approved
		event = "request.approved"
	}
	if err := b.transition(req, to); err != nil {
		return *req, err
	}
	b.auditFillLocked(event, req, string(to))
	return *req, nil
}

func (b *Broker) Audit(event AuditEvent) { b.audit.Write(event) }
