// Package web serves the approval and unlock pages on loopback, behind
// whatever private-network TLS proxy the deployment puts in front of it.
// Every page requires a passkey login, and
// each Approve requires a fresh passkey assertion with user verification,
// so possession of an approval link never approves anything.
package web

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/fu5ha/vaultbroker/internal/broker"
)

type Server struct {
	broker   *broker.Broker
	webauthn *webauthn.WebAuthn
	mux      *http.ServeMux

	mu         sync.Mutex
	credential *webauthn.Credential
	sessions   map[string]*session
	ceremonies map[string]*ceremony
}

func New(b *broker.Broker) (*Server, error) {
	cfg := b.Config()
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Vaultbroker",
		RPID:          cfg.RPID,
		RPOrigins:     []string{cfg.RPOrigin},
	})
	if err != nil {
		return nil, err
	}
	s := &Server{
		broker: b, webauthn: wa, mux: http.NewServeMux(),
		sessions: map[string]*session{}, ceremonies: map[string]*ceremony{},
	}
	if err := s.loadCredential(); err != nil {
		return nil, err
	}
	if err := s.ensureRegisterToken(); err != nil {
		return nil, err
	}
	if s.credential == nil {
		log.Printf("no passkey registered; token at %s, register at /register?token=...", cfg.RegisterTokenPath)
	}

	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("GET /{$}", s.index)
	s.mux.HandleFunc("GET /register", s.registerPage)
	s.mux.HandleFunc("GET /unlock", s.unlockPage)
	s.mux.HandleFunc("POST /unlock", s.unlockSubmit)
	s.mux.HandleFunc("GET /approve/{id}", s.approvePage)
	s.mux.HandleFunc("POST /approve/{id}/decide", s.decide)
	s.mux.HandleFunc("POST /logout", s.logout)
	s.mux.HandleFunc("POST /api/webauthn/register/begin", s.registerBegin)
	s.mux.HandleFunc("POST /api/webauthn/register/finish", s.registerFinish)
	s.mux.HandleFunc("POST /api/webauthn/login/begin", s.loginBegin)
	s.mux.HandleFunc("POST /api/webauthn/login/finish", s.loginFinish)
	s.mux.HandleFunc("POST /api/webauthn/assert/begin", s.assertBegin)
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.broker.Status())
}

// requirePageSession redirects unauthenticated page loads to the index,
// which serves the login form.
func (s *Server) requirePageSession(w http.ResponseWriter, r *http.Request) *session {
	sess := s.currentSession(r)
	if sess == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	return sess
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	sess := s.currentSession(r)
	data := indexData{
		Registered: s.user().credential != nil,
		Status:     s.broker.Status(),
	}
	if sess != nil {
		data.LoggedIn = true
		data.CSRF = sess.csrf
		data.Pending = s.broker.Pending()
	}
	render(w, indexTemplate, data)
}

func (s *Server) registerPage(w http.ResponseWriter, r *http.Request) {
	if s.user().credential != nil || !s.registerTokenValid(r.URL.Query().Get("token")) {
		http.Error(w, "registration is closed", http.StatusForbidden)
		return
	}
	render(w, registerTemplate, map[string]string{"Token": r.URL.Query().Get("token")})
}

func (s *Server) unlockPage(w http.ResponseWriter, r *http.Request) {
	sess := s.requirePageSession(w, r)
	if sess == nil {
		return
	}
	if s.broker.Status().Vault == "unlocked" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	render(w, unlockTemplate, unlockData{
		CSRF: sess.csrf, Error: r.URL.Query().Get("error"),
		NeedsLogin: s.broker.NeedsLogin(ctx),
	})
}

func (s *Server) unlockSubmit(w http.ResponseWriter, r *http.Request) {
	sess := s.currentSession(r)
	if sess == nil || !s.csrfValid(sess, r) {
		http.Error(w, "session or CSRF check failed", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	password := r.FormValue("password")
	var err error
	if email := r.FormValue("email"); email != "" {
		err = s.broker.Login(ctx, email, password)
	} else {
		err = s.broker.Unlock(ctx, password)
	}
	if err != nil {
		render(w, unlockTemplate, unlockData{
			CSRF: sess.csrf, Error: "Unlock failed. Check the password and try again.",
			NeedsLogin: s.broker.NeedsLogin(ctx),
		})
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) approvePage(w http.ResponseWriter, r *http.Request) {
	sess := s.requirePageSession(w, r)
	if sess == nil {
		return
	}
	req, ok := s.broker.Request(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	render(w, approveTemplate, approveData{
		CSRF: sess.csrf, Request: req,
		Mismatch: originMismatch(req.SubjectOrigin(), req.SubjectURIs()),
	})
}

// decide records the owner's decision. Deny needs session + CSRF. Approve
// additionally needs the fresh assertion from assert/begin, bound to this
// request id, with user verification required by the ceremony.
func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	sess := s.currentSession(r)
	if sess == nil || !s.csrfValid(sess, r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "session or CSRF check failed"})
		return
	}
	id := r.PathValue("id")
	decision := r.URL.Query().Get("decision")
	if decision == "approve" {
		c := s.takeCeremony(r, ceremonyAssert)
		if c == nil || c.requestID != id {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no assertion in progress for this request"})
			return
		}
		if err := s.finishAssertion(r, c); err != nil {
			s.webauthnError(w, "assert_finish", err)
			return
		}
	} else if decision != "deny" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decision must be approve or deny"})
		return
	}
	req, err := s.broker.Decide(id, decision == "approve")
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	if decision == "approve" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			s.broker.ExecuteApproved(ctx, id)
		}()
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": string(req.State)})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.endSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
