package tokenexchange_test

// Test file drives the id_token-emission decision end to end against a
// fully wired provider. The decision is computed inside the handler and
// consumed by the wire layer that writes the /token response, so only a
// request that traverses both can tell "the policy declined an id_token"
// apart from "the policy declined and the OP emitted one anyway".
//
// Spec:
//   - RFC 8693 §2.2.1 — the token-exchange response parameters
//   - RFC 8693 §4.1 — the "act" claim and the delegation chain
//   - OIDC Core 1.0 §2 — the id_token claim set

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// txTokenTypeAccessToken is the RFC 8693 §3 token-type URN naming an
// access token as the subject_token.
const txTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // RFC 8693 token type URN, not a credential.

// fixedDecisionPolicy admits every exchange with one prepared decision,
// so a row states the policy's answer as data rather than as a closure.
type fixedDecisionPolicy struct {
	decision *op.TokenExchangeDecision
}

func (p fixedDecisionPolicy) Allow(_ context.Context, _ op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	return p.decision, nil
}

// TestTokenExchange_PolicyDeclinedIDTokenIsNotIssued pins the declining
// direction of the decision. The subject_token is an id_token and the
// granted scope still carries "openid", so scope alone would mint one —
// and the token minted on that path would carry neither the act chain
// nor the cnf binding the handler assembles only when it decided to
// issue an id_token. Emitting it would hand the caller a delegated
// identity laundered of its delegation record, and reset the act-chain
// depth the next exchange counts.
func TestTokenExchange_PolicyDeclinedIDTokenIsNotIssued(t *testing.T) {
	t.Parallel()

	policy := fixedDecisionPolicy{decision: &op.TokenExchangeDecision{IssueIDToken: op.PtrBool(false)}}
	tk, rp := newExchangeProvider(t, policy)
	idToken := issueIDToken(t, tk, rp)

	status, body := postToken(t, tk, url.Values{
		"grant_type":         {op.TokenExchangeGrantType},
		"subject_token":      {idToken},
		"subject_token_type": {txTokenTypeIDToken},
		"audience":           {txResource},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	if at, _ := body["access_token"].(string); at == "" {
		t.Errorf("access_token missing: %v", body)
	}
	if idt, _ := body["id_token"].(string); idt != "" {
		t.Errorf("id_token issued although the policy declined it: %v", body)
	}
	// The granted scope is what a scope-only gate would have keyed on,
	// so the row proves the decision — not the absence of "openid" —
	// withheld the token.
	scope, _ := body["scope"].(string)
	if !slicesContains(strings.Fields(scope), "openid") {
		t.Fatalf("granted scope=%q no longer carries openid; the assertion above proves nothing", scope)
	}
}

// TestTokenExchange_PolicyForcedIDTokenIsIssued pins the forcing
// direction on a subject_token type whose default is "no id_token", so
// only the policy override can account for the token appearing.
func TestTokenExchange_PolicyForcedIDTokenIsIssued(t *testing.T) {
	t.Parallel()

	policy := fixedDecisionPolicy{decision: &op.TokenExchangeDecision{IssueIDToken: op.PtrBool(true)}}
	tk, rp := newExchangeProvider(t, policy)
	accessToken := issueAccessToken(t, tk, rp)

	status, body := postToken(t, tk, url.Values{
		"grant_type":         {op.TokenExchangeGrantType},
		"subject_token":      {accessToken},
		"subject_token_type": {txTokenTypeAccessToken},
		"audience":           {txResource},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	if idt, _ := body["id_token"].(string); idt == "" {
		t.Errorf("id_token missing although the policy forced it: %v", body)
	}
}

// TestTokenExchange_AccessTokenSubjectDefaultsToNoIDToken pins the
// documented default for the other subject-token type: an exchange the
// policy leaves alone returns an access token only, even though the
// granted scope carries "openid".
func TestTokenExchange_AccessTokenSubjectDefaultsToNoIDToken(t *testing.T) {
	t.Parallel()

	tk, rp := newExchangeProvider(t, &recordingExchangePolicy{})
	accessToken := issueAccessToken(t, tk, rp)

	status, body := postToken(t, tk, url.Values{
		"grant_type":         {op.TokenExchangeGrantType},
		"subject_token":      {accessToken},
		"subject_token_type": {txTokenTypeAccessToken},
		"audience":           {txResource},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	if at, _ := body["access_token"].(string); at == "" {
		t.Errorf("access_token missing: %v", body)
	}
	if idt, _ := body["id_token"].(string); idt != "" {
		t.Errorf("id_token issued for an access-token subject with no policy override: %v", body)
	}
	scope, _ := body["scope"].(string)
	if !slicesContains(strings.Fields(scope), "openid") {
		t.Fatalf("granted scope=%q no longer carries openid; the assertion above proves nothing", scope)
	}
}

// issueAccessToken drives the same authorization-code flow [issueIDToken]
// uses and returns the access token the redemption produced, so the
// exchange consumes a credential the provider actually minted.
func issueAccessToken(t *testing.T, tk *testkit.Provider, rp *store.Client) string {
	t.Helper()
	code := runCodeFlow(t, tk, rp)
	status, body := postToken(t, tk, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {txRedirectURI},
		"code_verifier": {txPKCEVerifier},
	})
	if status != http.StatusOK {
		t.Fatalf("code redemption status=%d want 200, body=%v", status, body)
	}
	accessToken, _ := body["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("code redemption returned no access_token: %v", body)
	}
	return accessToken
}

// slicesContains reports whether want appears in list.
func slicesContains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
