//go:build example

// rp.go — Relying Party for example 34-encrypted-id-token.
//
// This file holds the inline RP that drives the authorization_code +
// PKCE flow against the OP and consumes encrypted ID tokens. The RP
// does NOT depend on examples/internal/rpkit because rpkit's CodeFlow
// uses coreos/go-oidc's verifier, which does not understand the
// JWE-of-JWS nested shape this example exists to demonstrate; the RP
// performs the decrypt + verify dance itself (see jose.go).
//
// The HTTP surface is:
//
//   - GET /         — landing page with a "Log in via the OP" link.
//   - GET /login    — generates state / nonce / PKCE pair and 302s
//     to the OP's /authorize.
//   - GET /callback — exchanges the auth code for the encrypted
//     id_token, calls the JWE decrypt + JWS verify dance in jose.go,
//     stashes the claims for /me, and 302s.
//   - GET /me       — renders the last decrypted claims as JSON.

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	josev4 "github.com/go-jose/go-jose/v4"
)

// rpOptions configures the inline Relying Party. ClientSecret carries
// the demo client_secret_basic credential; EncPrivate is the RSA
// private half whose public counterpart is registered with the OP as
// the RP's use=enc key.
type rpOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	EncPrivate   *rsa.PrivateKey
}

type discoveryDoc struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

// rp is a minimal Authorization Code + PKCE Relying Party that
// expects an encrypted ID Token. It does not depend on
// examples/internal/rpkit because rpkit's CodeFlow uses
// coreos/go-oidc's verifier, which does not understand the
// JWE-of-JWS nested shape; this RP performs the decrypt + verify
// dance explicitly so the wire shape is observable.
type rp struct {
	opts      rpOptions
	endpoints discoveryDoc
	opSigJWKS *josev4.JSONWebKeySet // fetched once at startup

	mu      sync.Mutex
	pending map[string]pendingState
	last    map[string]any
}

// pendingState pairs the PKCE code_verifier with the nonce for a
// single in-flight authorization request.
type pendingState struct {
	verifier string
	nonce    string
}

func newRP(opts rpOptions) (*rp, error) {
	if opts.EncPrivate == nil {
		return nil, errors.New("rp: EncPrivate is required")
	}

	doc, err := fetchDiscovery(opts.Issuer)
	if err != nil {
		return nil, err
	}
	jwks, err := fetchJWKS(doc.JWKSURI)
	if err != nil {
		return nil, err
	}

	return &rp{
		opts:      opts,
		endpoints: doc,
		opSigJWKS: jwks,
		pending:   make(map[string]pendingState),
	}, nil
}

func fetchDiscovery(issuer string) (discoveryDoc, error) {
	var doc discoveryDoc
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return doc, fmt.Errorf("rp: build discovery request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("rp: discover %s: %w", issuer, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return doc, fmt.Errorf("rp: discovery %s status %d", issuer, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("rp: decode discovery: %w", err)
	}
	return doc, nil
}

func fetchJWKS(uri string) (*josev4.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("rp: build jwks request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rp: fetch jwks %s: %w", uri, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rp: jwks %s status %d", uri, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("rp: read jwks: %w", err)
	}
	var set josev4.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("rp: parse jwks: %w", err)
	}
	return &set, nil
}

func (r *rp) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", r.index)
	mux.HandleFunc("/login", r.login)
	mux.HandleFunc("/callback", r.callback)
	mux.HandleFunc("/me", r.me)
	return mux
}

func (r *rp) index(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w,
		`<!doctype html><html><body><h1>Encrypted ID Token demo RP</h1>`+
			`<p>Issuer: <code>%s</code></p>`+
			`<p>Client: <code>%s</code></p>`+
			`<p>The OP wraps every id_token in a JWE (RSA-OAEP-256 + A256GCM).</p>`+
			`<ul><li><a href="/login">Log in via the OP</a></li>`+
			`<li><a href="/me">Show last decrypted claims (/me)</a></li></ul>`+
			`</body></html>`,
		htmlEscape(r.opts.Issuer), htmlEscape(r.opts.ClientID))
}

func (r *rp) login(w http.ResponseWriter, req *http.Request) {
	state, err := randURL(16)
	if err != nil {
		http.Error(w, "rp: generate state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	verifier, err := randURL(48)
	if err != nil {
		http.Error(w, "rp: generate code_verifier: "+err.Error(), http.StatusInternalServerError)
		return
	}
	nonce, err := randURL(16)
	if err != nil {
		http.Error(w, "rp: generate nonce: "+err.Error(), http.StatusInternalServerError)
		return
	}

	r.mu.Lock()
	r.pending[state] = pendingState{verifier: verifier, nonce: nonce}
	r.mu.Unlock()

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", r.opts.ClientID)
	q.Set("redirect_uri", r.opts.RedirectURL)
	q.Set("scope", strings.Join(r.opts.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	http.Redirect(w, req, r.endpoints.AuthEndpoint+"?"+q.Encode(), http.StatusFound)
}

func (r *rp) callback(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		http.Error(w, "rp: OP returned error="+errCode+" desc="+q.Get("error_description"),
			http.StatusBadGateway)
		return
	}
	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		http.Error(w, "rp: missing state or code", http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	pending, ok := r.pending[state]
	delete(r.pending, state)
	r.mu.Unlock()
	if !ok {
		http.Error(w, "rp: unknown state", http.StatusBadRequest)
		return
	}

	rawIDToken, err := r.exchangeCode(req.Context(), code, pending.verifier)
	if err != nil {
		http.Error(w, "rp: token exchange: "+err.Error(), http.StatusBadGateway)
		return
	}

	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 5 {
		http.Error(w,
			fmt.Sprintf("rp: expected 5-part JWE id_token, got %d parts", len(parts)),
			http.StatusBadGateway)
		return
	}

	claims, err := r.decryptAndVerify(rawIDToken)
	if err != nil {
		http.Error(w, "rp: decrypt/verify id_token: "+err.Error(), http.StatusBadGateway)
		return
	}

	if got, _ := claims["nonce"].(string); got != pending.nonce {
		http.Error(w, "rp: id_token nonce mismatch", http.StatusBadGateway)
		return
	}

	// Surface the JWE wire shape next to the decrypted claims so the
	// operator sees both in a single /me response.
	claims["_id_token_jwe_parts"] = len(parts)

	r.mu.Lock()
	r.last = claims
	r.mu.Unlock()

	http.Redirect(w, req, "/me", http.StatusFound)
}

// exchangeCode POSTs to /token with client_secret_basic credentials
// and returns the raw id_token field. The token response also carries
// access_token / token_type but the example does not exercise the
// userinfo path.
func (r *rp) exchangeCode(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", r.opts.RedirectURL)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoints.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(r.opts.ClientID, r.opts.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("/token status %d: %s", resp.StatusCode, string(body))
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tok.IDToken == "" {
		return "", errors.New("/token response missing id_token")
	}
	return tok.IDToken, nil
}

func (r *rp) me(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	claims := r.last
	r.mu.Unlock()

	if claims == nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("rp: no decrypted ID Token yet — visit /login first\n"))
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
