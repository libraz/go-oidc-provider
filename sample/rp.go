//go:build example

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// relyingParty is the other half of the round-trip: a small OIDC client
// that starts an authorization code flow with PKCE, exchanges the code,
// verifies the ID token against the OP's JWKS, and shows the claims.
//
// It is written out rather than pulled from a helper because what an
// embedder has to get right on this side — state, nonce, PKCE, and
// verifying the token instead of decoding it — is part of what the sample
// is meant to show.
type relyingParty struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	pending  *pendingFlows

	// issuer is the provider this client discovered. The callback compares
	// it against the authorization response's iss parameter.
	issuer string

	// issRequired mirrors the provider's
	// authorization_response_iss_parameter_supported metadata: when the
	// provider says it stamps iss on every response, a response without
	// one is a failure rather than an older provider.
	issRequired bool
}

// pendingFlow holds the per-attempt values that must survive the redirect
// to the OP and be checked when the browser comes back.
type pendingFlow struct {
	Nonce    string
	Verifier string
	Expires  time.Time
}

type pendingFlows struct {
	mu sync.Mutex
	m  map[string]pendingFlow
}

// pendingFlowSweepAt is the size at which put reclaims expired flows.
// Only take removes an entry, and a sign-in the member abandons at the
// provider never reaches a callback, so without this an unauthenticated
// GET /login repeated in a loop grows the map for as long as the process
// runs. Sweeping inside put puts the reclamation on the path that creates
// the pressure, which is all a demonstration needs — a deployment that
// held these in shared storage would let the store expire them instead.
const pendingFlowSweepAt = 1024

func newPendingFlows() *pendingFlows {
	return &pendingFlows{m: make(map[string]pendingFlow)}
}

// take returns the flow for state and removes it, so a state value cannot
// be replayed against a second callback.
func (p *pendingFlows) take(state string) (pendingFlow, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, ok := p.m[state]
	delete(p.m, state)
	if !ok || time.Now().After(f.Expires) {
		return pendingFlow{}, false
	}
	return f, true
}

func (p *pendingFlows) put(state string, f pendingFlow) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.m) >= pendingFlowSweepAt {
		now := time.Now()
		for key, flow := range p.m {
			if now.After(flow.Expires) {
				delete(p.m, key)
			}
		}
	}
	p.m[state] = f
}

func newRelyingParty(ctx context.Context, cfg config) (*relyingParty, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	// RFC 9207 §3: the provider announces that it identifies itself in
	// every authorization response. Read once here so the callback knows
	// whether a response without iss is one this provider could have sent.
	var meta struct {
		IssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("discovery metadata: %w", err)
	}
	return &relyingParty{
		oauth: oauth2.Config{
			ClientID:    cfg.ClientID,
			Endpoint:    provider.Endpoint(),
			RedirectURL: cfg.RedirectURI,
			Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier:    provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		pending:     newPendingFlows(),
		issuer:      cfg.Issuer,
		issRequired: meta.IssParameterSupported,
	}, nil
}

func (rp *relyingParty) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", rp.index)
	mux.HandleFunc("GET /login", rp.login)
	mux.HandleFunc("GET /callback", rp.callback)
	mux.HandleFunc("GET /assets/app.css", rp.stylesheet)
}

func (rp *relyingParty) index(w http.ResponseWriter, _ *http.Request) {
	rp.page(w, http.StatusOK, "Relying party",
		`<p class="lead">This is a separate application that trusts the provider.
Signing in here sends you to the provider and back.</p>
<nav class="links"><a href="/login">Sign in with the provider</a></nav>`)
}

// login starts the flow. state, nonce, and the PKCE verifier are all
// freshly random per attempt: state defends the callback against forgery,
// nonce binds the ID token to this attempt, and PKCE binds the code to
// this client.
func (rp *relyingParty) login(w http.ResponseWriter, r *http.Request) {
	state, err := newOpaqueID()
	if err != nil {
		http.Error(w, "cannot start login", http.StatusInternalServerError)
		return
	}
	nonce, err := newOpaqueID()
	if err != nil {
		http.Error(w, "cannot start login", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	rp.pending.put(state, pendingFlow{
		Nonce:    nonce,
		Verifier: verifier,
		Expires:  time.Now().Add(10 * time.Minute),
	})
	url := rp.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

// callback completes the flow. Every check below is one an embedder has to
// perform: the response must come from the provider this client sent the
// request to, the state must match a flow this client started, the code
// exchange must carry the PKCE verifier, the ID token must verify against
// the OP's JWKS, and the nonce inside it must be the one sent.
func (rp *relyingParty) callback(w http.ResponseWriter, r *http.Request) {
	// The issuer check comes first, and covers the error branch below with
	// it: RFC 9207 §2.4 has the client establish which provider answered
	// before it acts on anything the response carries. Skipping it leaves
	// the client open to the mix-up attack, where a response minted by a
	// provider the attacker controls is redeemed against this one.
	if message, ok := rp.checkResponseIssuer(r.URL.Query().Get("iss")); !ok {
		rp.fail(w, http.StatusBadRequest, message)
		return
	}
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		rp.fail(w, http.StatusBadRequest, "The provider returned an error: "+errParam)
		return
	}
	flow, ok := rp.pending.take(r.URL.Query().Get("state"))
	if !ok {
		rp.fail(w, http.StatusBadRequest, "That sign-in attempt is unknown or has expired.")
		return
	}
	token, err := rp.oauth.Exchange(r.Context(), r.URL.Query().Get("code"),
		oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		rp.fail(w, http.StatusBadGateway, "Could not exchange the authorization code.")
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		rp.fail(w, http.StatusBadGateway, "The token response carried no ID token.")
		return
	}
	idToken, err := rp.verifier.Verify(r.Context(), rawID)
	if err != nil {
		rp.fail(w, http.StatusBadGateway, "The ID token did not verify.")
		return
	}
	if idToken.Nonce != flow.Nonce {
		rp.fail(w, http.StatusBadGateway, "The ID token was issued for a different attempt.")
		return
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		rp.fail(w, http.StatusBadGateway, "The ID token claims could not be read.")
		return
	}
	pretty, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		rp.fail(w, http.StatusInternalServerError, "Could not render the claims.")
		return
	}
	rp.page(w, http.StatusOK, "Signed in", fmt.Sprintf(
		`<dl class="spec"><dt>subject</dt><dd class="mono-wrap">%s</dd></dl>
<h2 class="subtitle">ID token claims</h2>
<pre class="blob">%s</pre>
<nav class="links"><a href="/">Start over</a></nav>`,
		html.EscapeString(idToken.Subject), html.EscapeString(string(pretty)),
	))
}

// checkResponseIssuer compares the authorization response's iss parameter
// against the provider this client discovered, per RFC 9207 §2.4. It
// reports whether the response may be used, and the message to show when
// it may not.
//
// An absent parameter fails only when the provider advertised that it
// sends one; a provider that never announced support is not expected to,
// and a value that names a different provider fails either way.
func (rp *relyingParty) checkResponseIssuer(iss string) (message string, ok bool) {
	switch {
	case iss == "" && rp.issRequired:
		return "The provider did not identify itself in that response.", false
	case iss != "" && iss != rp.issuer:
		return "That response came from a different provider than the one this sign-in went to.", false
	default:
		return "", true
	}
}

func (rp *relyingParty) fail(w http.ResponseWriter, status int, message string) {
	rp.page(w, status, "Sign-in failed", fmt.Sprintf(
		`<p class="flag flag-bad">%s</p><nav class="links"><a href="/">Try again</a></nav>`,
		html.EscapeString(message),
	))
}

// page wraps a fragment in the same chrome the provider's pages use, so
// the round-trip does not visibly change design language halfway through.
// The fragment is composed here rather than templated because the relying
// party has three screens and no user-supplied markup.
//
// The headers come from the same helper the provider's pages use. The
// sign-in-complete screen shows the verified identity claims, so it needs
// the framing defence at least as much as the pages that collected the
// credential does.
func (rp *relyingParty) page(w http.ResponseWriter, status int, title, body string) {
	stampHeaders(w)
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title><link rel="stylesheet" href="/assets/app.css"></head>
<body><header class="bar"><span class="mark">relying party</span><span class="rule"></span></header>
<main class="sheet"><h1 class="title">%s</h1>%s</main></body></html>`,
		html.EscapeString(title), html.EscapeString(title), body)
}

// stylesheet serves the shared styles on the relying party's origin too.
// The two halves run on different ports, so the provider's copy is
// cross-origin and style-src 'self' would refuse it.
func (rp *relyingParty) stylesheet(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(appCSS))
}
