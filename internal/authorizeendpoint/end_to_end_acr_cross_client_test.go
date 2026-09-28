package authorizeendpoint_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// hardwareACR is the canonical acr URI of AAL3.
const hardwareACR = "http://idmanagement.gov/ns/assurance/loa/4"

// TestEndToEnd_SessionReuseReportsTheLevelReached pins where the acr a
// session-served response reports comes from. A single-factor login
// that asked for the AAL3 acr receives the default policy's echo of it,
// but the session records only the level the login reached. Every later
// response served from that session — the same client's silent pass and
// another client's silent pass off a cached grant — reports the policy's
// verdict for its own request over that level, never the string the
// first request drew.
//
// Tracks: CVE-2026-97176 — a reused session reported (and so, on a
// weaker implementation, could satisfy) an acr stronger than the level
// it actually reached. The step-up half of the same class is pinned by
// TestEndToEnd_ACRStepUp.
func TestEndToEnd_SessionReuseReportsTheLevelReached(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	f := newE2EFlow(t, "rp-acr-first", testkit.WithClock(fakeClock{now: now}))
	const subject = "user-acr-cross-client"
	ctx := context.Background()

	first := f.values()
	first.Set("acr_values", hardwareACR)
	claims := f.exchange(t, f.completeLogin(t, f.authorize(t, first), subject))
	if got, _ := claims["acr"].(string); got != hardwareACR {
		t.Fatalf("login id_token acr=%q want the default policy's echo %q", got, hardwareACR)
	}

	// The same client, asking for nothing, is served silently.
	loc := f.authorize(t, f.values())
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("same-client pass expected a silent code, got %s", loc)
	}
	if got, _ := f.exchange(t, code)["acr"].(string); got != bronzeACR {
		t.Errorf("same-client silent id_token acr=%q want %q", got, bronzeACR)
	}

	// A second client that already holds a grant is served silently too.
	cached := f.sibling(t, "rp-acr-cached")
	if err := f.tk.Store.Grants().Save(ctx, &store.Grant{
		ID:        "grant-acr-cached",
		Subject:   subject,
		ClientID:  cached.rp.ID,
		Scope:     []string{"openid", "profile", "email"},
		ACR:       hardwareACR,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Save grant: %v", err)
	}
	loc = cached.authorize(t, cached.values())
	code = loc.Query().Get("code")
	if code == "" {
		t.Fatalf("cached-grant pass expected a silent code, got %s", loc)
	}
	if got, _ := cached.exchange(t, code)["acr"].(string); got != bronzeACR {
		t.Errorf("cached-grant silent id_token acr=%q want %q", got, bronzeACR)
	}
}

// sibling registers another confidential client on f's provider that
// shares f's browser, so its requests carry the same session cookie.
func (f *e2eFlow) sibling(t *testing.T, clientID string) *e2eFlow {
	t.Helper()
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(f.secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := f.tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	return &e2eFlow{tk: f.tk, client: f.client, rp: rp, secret: f.secret}
}

// TestEndToEnd_ConsentOnlyReportsTheLevelReached is the interactive
// counterpart: a consent-only pass served from the session reports the
// policy's verdict for its own request over the level the login
// reached, not the AAL3 acr the login's request drew.
func TestEndToEnd_ConsentOnlyReportsTheLevelReached(t *testing.T) {
	t.Parallel()
	fix := newFlowFixture(t, surfaceLoginFlow, newMovableClock(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)))
	d := newReauthDriver(t, fix)

	loc1 := d.authorize(url.Values{"scope": {"openid"}, "acr_values": {hardwareACR}})
	_, redirect1 := d.walkInteraction(loc1.Path)
	if got, _ := d.exchange(d.codeFrom(redirect1))["acr"].(string); got != hardwareACR {
		t.Fatalf("login id_token acr=%q want the default policy's echo %q", got, hardwareACR)
	}

	loc2 := d.authorize(nil)
	first, redirect2 := d.walkInteraction(loc2.Path)
	if first != consentPromptType {
		t.Fatalf("widened scope ran %q, want the consent screen alone", first)
	}
	if got, _ := d.exchange(d.codeFrom(redirect2))["acr"].(string); got != bronzeACR {
		t.Errorf("consent-only id_token acr=%q want %q", got, bronzeACR)
	}
	grant, err := fix.store.Grants().FindBySubjectClient(context.Background(), reauthSubject, fix.client.ID)
	if err != nil {
		t.Fatalf("FindBySubjectClient: %v", err)
	}
	if grant.ACR != bronzeACR {
		t.Errorf("grant acr=%q want %q", grant.ACR, bronzeACR)
	}
}
