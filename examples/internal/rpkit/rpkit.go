//go:build example

// Package rpkit provides the minimal Relying Party building blocks
// the example/* main.go files share. Each example that pairs an OP
// with an in-process RP imports this package, mounts the RP's
// http.Handler on its own port, and tells embedders to drive the
// flow from a browser pointed at the RP.
//
// The package is build-tag gated and lives under examples/internal/
// so it cannot be imported into production binaries by accident.
// Production embedders that want a full-featured Go RP use the
// underlying golang.org/x/oauth2 + github.com/coreos/go-oidc/v3 APIs
// directly; rpkit is a thin demo wrapper, not a library.
package rpkit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Options configures a CodeFlow RP. Issuer, ClientID, and RedirectURL
// are required; everything else has a workable default for a
// localhost demo.
type Options struct {
	// Issuer is the OP's iss. The RP runs OIDC discovery against
	// Issuer + "/.well-known/openid-configuration" and pins the
	// returned endpoints.
	Issuer string

	// ClientID is the value the OP registered for this RP.
	ClientID string

	// ClientSecret is empty for public clients (which rpkit always
	// pairs with PKCE). Confidential clients populate this.
	ClientSecret string

	// RedirectURL is the absolute URL the OP will redirect back to
	// after authorization. It MUST resolve to the /callback handler
	// the rpkit Handler() returns when mounted.
	RedirectURL string

	// Scopes is the scope set requested at /authorize. "openid" is
	// auto-prepended if the caller forgets it.
	Scopes []string

	// ClaimsRequest is the OIDC Core 1.0 §5.5 "claims" request
	// parameter, or nil to omit it. The map is JSON-encoded and
	// URL-encoded into the authorize redirect.
	ClaimsRequest map[string]any
}

// CodeFlow is an Authorization Code + PKCE Relying Party.
type CodeFlow struct {
	issuer        string
	cfg           oauth2.Config
	verifier      *oidc.IDTokenVerifier
	claimsRequest string // JSON-encoded §5.5 claims param, "" to omit

	mu      sync.Mutex
	pending map[string]string // state -> code_verifier
	last    map[string]any    // last verified id_token claims (single-user demo)
}

// New runs OIDC discovery against opts.Issuer and returns a CodeFlow
// ready to mount through Handler(). The discovery request uses
// http.DefaultClient; embedders that need a custom transport pass
// their own oidc.Provider in via a future option.
func New(ctx context.Context, opts Options) (*CodeFlow, error) {
	provider, err := oidc.NewProvider(ctx, opts.Issuer)
	if err != nil {
		return nil, fmt.Errorf("rpkit: discover %s: %w", opts.Issuer, err)
	}

	scopes := opts.Scopes
	if !hasScope(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}

	cfg := oauth2.Config{
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		RedirectURL:  opts.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	cf := &CodeFlow{
		issuer:   opts.Issuer,
		cfg:      cfg,
		verifier: provider.Verifier(&oidc.Config{ClientID: opts.ClientID}),
		pending:  make(map[string]string),
	}
	if opts.ClaimsRequest != nil {
		raw, err := json.Marshal(opts.ClaimsRequest)
		if err != nil {
			return nil, fmt.Errorf("rpkit: encode ClaimsRequest: %w", err)
		}
		cf.claimsRequest = string(raw)
	}
	return cf, nil
}

// Handler exposes the RP HTTP surface:
//
//   - GET /            — landing page with a "log in" link
//   - GET /login       — generates state + PKCE, redirects to the OP
//   - GET /callback    — exchanges the code, verifies the ID token
//   - GET /me          — returns the most recent verified claims as JSON
//
// Mount it on any prefix; rpkit only generates relative URLs.
func (cf *CodeFlow) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", cf.index)
	mux.HandleFunc("/login", cf.login)
	mux.HandleFunc("/callback", cf.callback)
	mux.HandleFunc("/me", cf.me)
	return mux
}

func (cf *CodeFlow) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w,
		`<!doctype html><html><body><h1>rpkit demo RP</h1>`+
			`<p>Issuer: <code>%s</code></p>`+
			`<p>Client: <code>%s</code></p>`+
			`<ul><li><a href="/login">Log in via the OP</a></li>`+
			`<li><a href="/me">Show last verified claims (/me)</a></li></ul>`+
			`</body></html>`,
		htmlEscape(cf.issuer), htmlEscape(cf.cfg.ClientID))
}

func (cf *CodeFlow) login(w http.ResponseWriter, r *http.Request) {
	state, err := randURL(16)
	if err != nil {
		http.Error(w, "rpkit: generate state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	verifier, err := randURL(48)
	if err != nil {
		http.Error(w, "rpkit: generate code_verifier: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cf.mu.Lock()
	cf.pending[state] = verifier
	cf.mu.Unlock()

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authOpts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if cf.claimsRequest != "" {
		authOpts = append(authOpts,
			oauth2.SetAuthURLParam("claims", cf.claimsRequest))
	}
	http.Redirect(w, r, cf.cfg.AuthCodeURL(state, authOpts...), http.StatusFound)
}

func (cf *CodeFlow) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		http.Error(w, "rpkit: OP returned error="+errCode+" desc="+q.Get("error_description"),
			http.StatusBadGateway)
		return
	}

	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		http.Error(w, "rpkit: missing state or code", http.StatusBadRequest)
		return
	}

	cf.mu.Lock()
	verifier, ok := cf.pending[state]
	delete(cf.pending, state)
	cf.mu.Unlock()
	if !ok {
		http.Error(w, "rpkit: unknown state", http.StatusBadRequest)
		return
	}

	tok, err := cf.cfg.Exchange(r.Context(), code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		http.Error(w, "rpkit: token exchange: "+err.Error(), http.StatusBadGateway)
		return
	}

	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		http.Error(w, "rpkit: token response missing id_token", http.StatusBadGateway)
		return
	}

	idt, err := cf.verifier.Verify(r.Context(), rawID)
	if err != nil {
		http.Error(w, "rpkit: verify id_token: "+err.Error(), http.StatusBadGateway)
		return
	}

	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		http.Error(w, "rpkit: decode claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	cf.mu.Lock()
	cf.last = claims
	cf.mu.Unlock()

	http.Redirect(w, r, "/me", http.StatusFound)
}

func (cf *CodeFlow) me(w http.ResponseWriter, _ *http.Request) {
	cf.mu.Lock()
	claims := cf.last
	cf.mu.Unlock()

	if claims == nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("rpkit: no verified ID Token yet — visit /login first\n"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(claims)
}

func randURL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func htmlEscape(s string) string {
	const lt, gt, amp, quot, apos = "&lt;", "&gt;", "&amp;", "&#34;", "&#39;"
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch r {
		case '<':
			out = append(out, lt...)
		case '>':
			out = append(out, gt...)
		case '&':
			out = append(out, amp...)
		case '"':
			out = append(out, quot...)
		case '\'':
			out = append(out, apos...)
		default:
			out = append(out, string(r)...)
		}
	}
	return string(out)
}
