// Package api is the Unix-socket boundary the MCP shim talks to. One JSON
// object per line in each direction. Responses never contain secret values
// or anything that could approve a request.
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"time"

	"github.com/fu5ha/vaultbroker/internal/broker"
)

const (
	MethodStatus        = "status"
	MethodSearch        = "search"
	MethodLock          = "lock"
	MethodFillCreate    = "fill.create"
	MethodPasskeyCreate = "passkey.create"
	MethodRequestGet    = "request.get"
	MethodRequestWait   = "request.wait"
	MethodWaitUnlocked  = "vault.wait_unlocked"
	MethodDiscover      = "discover" // provisioning only; refuses once configured
)

type Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type Server struct {
	broker   *broker.Broker
	listener net.Listener
}

func Listen(b *broker.Broker, socketPath string) (*Server, error) {
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	// Connecting to a Unix socket requires write permission on the socket
	// file. The service umask gives 0750; the socket must be 0660 so the
	// vaultbroker group (the agent's user) can connect. The directory
	// stays 0750 and the broker still checks the peer uid per connection.
	if err := os.Chmod(socketPath, 0o660); err != nil {
		listener.Close()
		return nil, err
	}
	return &Server{broker: b, listener: listener}, nil
}

func (s *Server) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) Close() error { return s.listener.Close() }

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	if err := checkPeer(s.broker, conn); err != nil {
		writeResponse(conn, Response{Error: err.Error()})
		return
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var req Request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			writeResponse(conn, Response{Error: "malformed request"})
			continue
		}
		timeout := 60 * time.Second
		switch req.Method {
		case MethodRequestWait:
			timeout = broker.ApprovalWindow + 2*time.Minute
		case MethodWaitUnlocked:
			timeout = 30 * time.Minute // shim re-arms on timeout
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		writeResponse(conn, s.dispatch(ctx, req))
		cancel()
	}
}

type searchParams struct {
	Query string `json:"query"`
}

type requestParams struct {
	ID string `json:"id"`
}

type requestCreated struct {
	RequestID   string    `json:"request_id"`
	State       string    `json:"state"`
	ApprovalURL string    `json:"approval_url"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (s *Server) dispatch(ctx context.Context, req Request) Response {
	switch req.Method {
	case MethodStatus:
		return ok(s.broker.Status())
	case MethodLock:
		s.broker.Lock(ctx)
		return ok(s.broker.Status())
	case MethodWaitUnlocked:
		if err := s.broker.WaitUnlocked(ctx); err != nil {
			return Response{Error: err.Error()}
		}
		return ok(s.broker.Status())
	case MethodDiscover:
		orgs, err := s.broker.Discover(ctx)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return ok(orgs)
	case MethodSearch:
		var params searchParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return Response{Error: "search: bad params"}
		}
		items, err := s.broker.Search(ctx, params.Query)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return ok(items)
	case MethodFillCreate:
		var params broker.FillParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return Response{Error: "fill.create: bad params"}
		}
		created, err := s.broker.CreateFill(ctx, params)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return ok(requestCreated{
			RequestID:   created.ID,
			State:       string(created.State),
			ApprovalURL: s.broker.ApprovalURL(created),
			ExpiresAt:   created.ExpiresAt,
		})
	case MethodPasskeyCreate:
		var params broker.PasskeyParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return Response{Error: "passkey.create: bad params"}
		}
		created, err := s.broker.CreatePasskey(ctx, params)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return ok(requestCreated{
			RequestID:   created.ID,
			State:       string(created.State),
			ApprovalURL: s.broker.ApprovalURL(created),
			ExpiresAt:   created.ExpiresAt,
		})
	case MethodRequestGet, MethodRequestWait:
		var params requestParams
		if err := json.Unmarshal(req.Params, &params); err != nil || params.ID == "" {
			return Response{Error: "request id required"}
		}
		if req.Method == MethodRequestWait {
			settled, err := s.broker.Wait(ctx, params.ID)
			if err != nil {
				return Response{Error: err.Error()}
			}
			return ok(settled)
		}
		got, found := s.broker.Request(params.ID)
		if !found {
			return Response{Error: "unknown request " + params.ID}
		}
		return ok(got)
	default:
		return Response{Error: "not implemented yet: " + req.Method}
	}
}

func ok(value any) Response {
	raw, err := json.Marshal(value)
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Result: raw}
}

func writeResponse(conn net.Conn, resp Response) {
	raw, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(raw, '\n'))
}
