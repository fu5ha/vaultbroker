package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fu5ha/vaultbroker/internal/helper"
)

// CreateFill records an approval request. The agent supplies the item id,
// browser session, and per-field targets; the broker resolves the item
// metadata and the page's current origin itself, so what the owner approves is
// broker-observed, not agent-asserted. The Signal wake-up is best-effort
// and never blocks creation.
func (b *Broker) CreateFill(ctx context.Context, in FillParams) (Request, error) {
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
	if len(in.Fields) == 0 || len(in.Fields) > 16 {
		return Request{}, fmt.Errorf("fields must list 1-16 entries")
	}
	for _, f := range in.Fields {
		if f.Field == "" {
			return Request{}, fmt.Errorf("each field needs a name")
		}
		if (f.Selector == "") == (f.Ref == "") {
			return Request{}, fmt.Errorf("field %s: exactly one of selector/ref", f.Field)
		}
	}
	meta, err := b.bw.ItemMeta(ctx, session, in.ItemID)
	if err != nil {
		return Request{}, err
	}
	origin, err := b.helper.CurrentOrigin(ctx, in.Session)
	if err != nil {
		return Request{}, err
	}
	in.ItemName = meta.Name
	in.ItemURIs = meta.URIs
	in.Origin = origin

	now := time.Now()
	req := &Request{
		ID:        newRequestID(),
		State:     Pending,
		CreatedAt: now,
		ExpiresAt: now.Add(ApprovalWindow),
		Fill:      in,
	}
	req.Hash = requestHash(req)

	b.mu.Lock()
	b.requests[req.ID] = req
	b.mu.Unlock()

	b.auditFill("request.created", req, "pending")
	go b.notifyApproval(req)
	return *req, nil
}

func (b *Broker) ApprovalURL(req Request) string {
	return b.cfg.RPOrigin + "/approve/" + req.ID
}

func (b *Broker) notifyApproval(req *Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	msg := fmt.Sprintf("Vaultbroker: approve filling %q into browser session %q at %s within 5 minutes:\n%s",
		req.Fill.ItemName, req.Fill.Session, req.Fill.Origin, b.ApprovalURL(*req))
	outcome := "sent"
	if err := b.helper.Notify(ctx, msg); err != nil {
		outcome = "failed"
	}
	b.audit.Write(AuditEvent{Event: "request.notify", RequestID: req.ID, Outcome: outcome})
}

// ExecuteApproved runs one approved fill. Secret values exist only in
// this call: from bw into helper assignments, then gone.
func (b *Broker) ExecuteApproved(ctx context.Context, id string) {
	b.mu.Lock()
	req, ok := b.requests[id]
	if !ok {
		b.mu.Unlock()
		return
	}
	if err := b.transition(req, Executing); err != nil {
		b.mu.Unlock()
		return
	}
	fill := req.Fill
	b.mu.Unlock()

	result, err := b.executeFill(ctx, fill)
	b.finish(req, result, err)
}

func (b *Broker) executeFill(ctx context.Context, fill FillParams) (*FillResult, error) {
	session, err := b.currentSession()
	if err != nil {
		return nil, err
	}
	origin, err := b.helper.CurrentOrigin(ctx, fill.Session)
	if err != nil {
		return nil, err
	}
	if origin != fill.Origin {
		return nil, fmt.Errorf("page origin changed since approval (%s -> %s)", fill.Origin, origin)
	}
	withTOTP := false
	for _, f := range fill.Fields {
		if f.Field == "totp" {
			withTOTP = true
		}
	}
	values, err := b.bw.ValuesForFill(ctx, session, fill.ItemID, withTOTP)
	if err != nil {
		return nil, err
	}
	valueOf := func(field string) (string, bool) {
		switch field {
		case "username":
			return values.Username, values.Username != ""
		case "password":
			return values.Password, values.Password != ""
		case "totp":
			return values.TOTP, values.TOTP != ""
		default:
			v, ok := values.Custom[field]
			return v, ok && v != ""
		}
	}

	results := make([]FieldResult, len(fill.Fields))
	var assignments []helper.FillAssignment
	var sent []int
	for i, f := range fill.Fields {
		results[i].Field = f.Field
		value, ok := valueOf(f.Field)
		if !ok {
			results[i].Error = "item has no value for this field"
			continue
		}
		assignments = append(assignments, helper.FillAssignment{Selector: f.Selector, Ref: f.Ref, Value: value})
		sent = append(sent, i)
	}
	if len(assignments) > 0 {
		filled, err := b.helper.Fill(ctx, fill.Session, fill.Origin, assignments)
		if err != nil {
			return &FillResult{Fields: results}, fmt.Errorf("%s", scrubValues(err.Error(), assignments))
		}
		for j, i := range sent {
			if j < len(filled) {
				results[i].OK = filled[j].OK
				results[i].Error = scrubValues(filled[j].Error, assignments)
			} else {
				results[i].Error = "helper returned no result for this field"
			}
		}
	}
	return &FillResult{Fields: results}, nil
}

// scrubValues removes any filled value from text headed for a result the
// agent can read. The helper already returns generic fill errors; this is
// the broker-side backstop for anything that echoes its inputs.
func scrubValues(text string, assignments []helper.FillAssignment) string {
	for _, a := range assignments {
		if a.Value != "" {
			text = strings.ReplaceAll(text, a.Value, "***")
		}
	}
	return text
}

func (b *Broker) finish(req *Request, result *FillResult, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	req.Result = result
	to := Succeeded
	if err != nil {
		to = Failed
		req.Error = err.Error()
	} else {
		for _, f := range result.Fields {
			if !f.OK {
				to = Failed
				req.Error = "one or more fields failed to fill"
				break
			}
		}
	}
	_ = b.transition(req, to)
	b.auditFillLocked("request.executed", req, string(to))
}

// Wait blocks until the request reaches a terminal state or ctx ends.
// Polling Request() also applies lazy expiry, so an abandoned approval
// settles as expired here without a background reaper.
func (b *Broker) Wait(ctx context.Context, id string) (Request, error) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		req, ok := b.Request(id)
		if !ok {
			return Request{}, fmt.Errorf("unknown request %s", id)
		}
		if req.State.Terminal() {
			return req, nil
		}
		select {
		case <-ctx.Done():
			return req, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (b *Broker) auditFill(event string, req *Request, outcome string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.auditFillLocked(event, req, outcome)
}

func (b *Broker) auditFillLocked(event string, req *Request, outcome string) {
	fields := make([]string, len(req.Fill.Fields))
	for i, f := range req.Fill.Fields {
		fields[i] = f.Field
	}
	b.audit.Write(AuditEvent{
		Event: event, RequestID: req.ID,
		ItemID: req.Fill.ItemID, ItemName: req.Fill.ItemName,
		Fields: fields, Session: req.Fill.Session, Origin: req.Fill.Origin,
		Outcome: outcome,
	})
}

func newRequestID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return "req_" + hex.EncodeToString(buf)
}

// requestHash binds the approval to the exact request the page displays.
func requestHash(req *Request) string {
	canonical, _ := json.Marshal(struct {
		ItemID  string      `json:"item_id"`
		Session string      `json:"session"`
		Origin  string      `json:"origin"`
		Fields  []FillField `json:"fields"`
	}{req.Fill.ItemID, req.Fill.Session, req.Fill.Origin, req.Fill.Fields})
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}
