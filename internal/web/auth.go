package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/fu5ha/vaultbroker/internal/broker"
)

const (
	sessionCookie  = "vb_session"
	ceremonyCookie = "vb_ceremony"
	sessionTTL     = 12 * time.Hour
	ceremonyTTL    = 5 * time.Minute
)

// The pages have exactly one user: the owner. Their passkey lives in
// their own Bitwarden; the broker stores only the public credential.
type pageUser struct {
	name       string
	credential *webauthn.Credential
}

func (u pageUser) WebAuthnID() []byte          { return []byte(u.name) }
func (u pageUser) WebAuthnName() string        { return u.name }
func (u pageUser) WebAuthnDisplayName() string { return u.name }
func (u pageUser) WebAuthnCredentials() []webauthn.Credential {
	if u.credential == nil {
		return nil
	}
	return []webauthn.Credential{*u.credential}
}

type session struct {
	csrf    string
	expires time.Time
}

type ceremonyKind int

const (
	ceremonyRegister ceremonyKind = iota
	ceremonyLogin
	ceremonyAssert // fresh assertion bound to one approval decision
)

type ceremony struct {
	kind      ceremonyKind
	data      *webauthn.SessionData
	requestID string // ceremonyAssert only
	expires   time.Time
}

func randomToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (s *Server) loadCredential() error {
	raw, err := os.ReadFile(s.broker.Config().CredentialPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var cred webauthn.Credential
	if err := json.Unmarshal(raw, &cred); err != nil {
		return fmt.Errorf("parse stored credential: %w", err)
	}
	s.credential = &cred
	return nil
}

func (s *Server) saveCredential(cred *webauthn.Credential) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	path := s.broker.Config().CredentialPath
	if err := os.WriteFile(path+".tmp", raw, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// ensureRegisterToken writes the one-time registration token the owner reads
// with sudo. It exists only while no credential is registered. The token
// itself never appears in logs (the journal is wheel-readable).
func (s *Server) ensureRegisterToken() error {
	path := s.broker.Config().RegisterTokenPath
	if s.credential != nil {
		_ = os.Remove(path)
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, []byte(randomToken()+"\n"), 0o600)
}

func (s *Server) registerTokenValid(got string) bool {
	raw, err := os.ReadFile(s.broker.Config().RegisterTokenPath)
	if err != nil || got == "" {
		return false
	}
	want := string(raw)
	if len(want) > 0 && want[len(want)-1] == '\n' {
		want = want[:len(want)-1]
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) user() pageUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	return pageUser{name: s.broker.Config().WebAuthnUser, credential: s.credential}
}

func (s *Server) startSession(w http.ResponseWriter) {
	token := randomToken()
	s.mu.Lock()
	s.sessions[token] = &session{csrf: randomToken(), expires: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(sessionTTL.Seconds()),
	})
}

func (s *Server) currentSession(r *http.Request) *session {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[cookie.Value]
	if !ok || time.Now().After(sess.expires) {
		delete(s.sessions, cookie.Value)
		return nil
	}
	return sess
}

func (s *Server) endSession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
}

func (s *Server) csrfValid(sess *session, r *http.Request) bool {
	got := r.Header.Get("X-CSRF")
	if got == "" {
		got = r.FormValue("csrf")
	}
	return sess != nil && got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(sess.csrf)) == 1
}

func (s *Server) startCeremony(w http.ResponseWriter, c ceremony) {
	id := randomToken()
	c.expires = time.Now().Add(ceremonyTTL)
	s.mu.Lock()
	s.ceremonies[id] = &c
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: ceremonyCookie, Value: id, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(ceremonyTTL.Seconds()),
	})
}

func (s *Server) takeCeremony(r *http.Request, kind ceremonyKind) *ceremony {
	cookie, err := r.Cookie(ceremonyCookie)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ceremonies[cookie.Value]
	if ok {
		delete(s.ceremonies, cookie.Value)
	}
	if !ok || c.kind != kind || time.Now().After(c.expires) {
		return nil
	}
	return c
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) webauthnError(w http.ResponseWriter, what string, err error) {
	s.broker.Audit(broker.AuditEvent{Event: "webauthn." + what, Outcome: "failed"})
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": what + " failed"})
	_ = err
}

func (s *Server) registerBegin(w http.ResponseWriter, r *http.Request) {
	if s.user().credential != nil || !s.registerTokenValid(r.URL.Query().Get("token")) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "registration closed"})
		return
	}
	options, sessionData, err := s.webauthn.BeginRegistration(s.user(),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}))
	if err != nil {
		s.webauthnError(w, "register_begin", err)
		return
	}
	s.startCeremony(w, ceremony{kind: ceremonyRegister, data: sessionData})
	writeJSON(w, http.StatusOK, options)
}

func (s *Server) registerFinish(w http.ResponseWriter, r *http.Request) {
	c := s.takeCeremony(r, ceremonyRegister)
	if c == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no registration in progress"})
		return
	}
	cred, err := s.webauthn.FinishRegistration(s.user(), *c.data, r)
	if err != nil {
		s.webauthnError(w, "register_finish", err)
		return
	}
	if err := s.saveCredential(cred); err != nil {
		s.webauthnError(w, "register_save", err)
		return
	}
	s.mu.Lock()
	s.credential = cred
	s.mu.Unlock()
	_ = os.Remove(s.broker.Config().RegisterTokenPath)
	s.broker.Audit(broker.AuditEvent{Event: "webauthn.registered", Outcome: "ok"})
	s.startSession(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) loginBegin(w http.ResponseWriter, r *http.Request) {
	user := s.user()
	if user.credential == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no passkey registered"})
		return
	}
	options, sessionData, err := s.webauthn.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.webauthnError(w, "login_begin", err)
		return
	}
	s.startCeremony(w, ceremony{kind: ceremonyLogin, data: sessionData})
	writeJSON(w, http.StatusOK, options)
}

// finishAssertion verifies a login or per-approve assertion and persists
// the updated credential (sign count). It reports whether user
// verification was required and satisfied; VerificationRequired in the
// ceremony makes the library reject assertions without it.
func (s *Server) finishAssertion(r *http.Request, c *ceremony) error {
	cred, err := s.webauthn.FinishLogin(s.user(), *c.data, r)
	if err != nil {
		return err
	}
	if cred.Authenticator.CloneWarning {
		s.broker.Audit(broker.AuditEvent{Event: "webauthn.clone_warning", Outcome: "sign count did not increase"})
	}
	if err := s.saveCredential(cred); err != nil {
		return err
	}
	s.mu.Lock()
	s.credential = cred
	s.mu.Unlock()
	return nil
}

func (s *Server) loginFinish(w http.ResponseWriter, r *http.Request) {
	c := s.takeCeremony(r, ceremonyLogin)
	if c == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no login in progress"})
		return
	}
	if err := s.finishAssertion(r, c); err != nil {
		s.webauthnError(w, "login_finish", err)
		return
	}
	s.broker.Audit(broker.AuditEvent{Event: "webauthn.login", Outcome: "ok"})
	s.startSession(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) assertBegin(w http.ResponseWriter, r *http.Request) {
	sess := s.currentSession(r)
	if sess == nil || !s.csrfValid(sess, r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "session or CSRF check failed"})
		return
	}
	requestID := r.URL.Query().Get("request")
	if _, ok := s.broker.Request(requestID); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown request"})
		return
	}
	options, sessionData, err := s.webauthn.BeginLogin(s.user(),
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.webauthnError(w, "assert_begin", err)
		return
	}
	s.startCeremony(w, ceremony{kind: ceremonyAssert, data: sessionData, requestID: requestID})
	writeJSON(w, http.StatusOK, options)
}
