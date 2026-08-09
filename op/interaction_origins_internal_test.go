package op

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// The CORS allowlist and the /interaction CSRF allowlist answer two
// different questions. CORS asks "may this page read a response from
// the OP's API surface?", and the origin of a registered client's
// redirect_uri is a legitimate yes: an SPA relying party calls /token
// and /userinfo from the page its callback landed on. The interaction
// gate asks "may this page drive the consent ceremony?", where the same
// entry means a page belonging to one client can post to another
// client's ceremony.
//
// These tests pin the two lists apart at the composition layer, which
// is where the entry is either admitted or not.

// originAllowlistConfig returns a config with one static client whose
// redirect_uri lives on a third-party origin, plus an explicitly
// enumerated origin, so the two builders can be compared on exactly
// those axes.
func originAllowlistConfig() *config {
	return &config{
		issuer:      "https://op.example.com",
		corsOrigins: []string{"https://login-ui.example.com"},
		staticClients: []store.Client{
			{
				ID:           "client-a",
				RedirectURIs: []string{"https://client-a.example.net/callback"},
			},
		},
	}
}

func TestBuildInteractionOriginAllowlist_ExcludesClientRedirectOrigins(t *testing.T) {
	t.Parallel()

	allow, err := buildInteractionOriginAllowlist(originAllowlistConfig())
	if err != nil {
		t.Fatalf("buildInteractionOriginAllowlist: %v", err)
	}
	if allow.Contains("https://client-a.example.net") {
		t.Error("a client's redirect_uri origin is admitted to the interaction gate; " +
			"it could then post to another client's consent ceremony")
	}
	if !allow.Contains("https://op.example.com") {
		t.Error("the OP's own origin must be admitted: the interaction UI is served from it")
	}
	if !allow.Contains("https://login-ui.example.com") {
		t.Error("an explicitly enumerated origin must be admitted: that is how an embedder " +
			"hosts the interaction UI off-issuer")
	}
}

func TestBuildOriginAllowlist_KeepsClientRedirectOriginsForCORS(t *testing.T) {
	t.Parallel()

	allow, err := buildOriginAllowlist(originAllowlistConfig())
	if err != nil {
		t.Fatalf("buildOriginAllowlist: %v", err)
	}
	if !allow.Contains("https://client-a.example.net") {
		t.Error("the CORS allowlist must keep client redirect origins; an SPA relying party " +
			"calls /token from its callback page")
	}
	if !allow.Contains("https://op.example.com") {
		t.Error("the OP's own origin must remain on the CORS allowlist")
	}
}

// TestOriginAllowlists_DifferOnlyByClientRedirectOrigins states the
// relationship as an invariant rather than as two independent lists: the
// interaction gate is the CORS list minus what client registration
// contributed, so a future entry added to one is a deliberate decision
// about the other.
func TestOriginAllowlists_DifferOnlyByClientRedirectOrigins(t *testing.T) {
	t.Parallel()

	cfg := originAllowlistConfig()
	cors, err := buildOriginAllowlist(cfg)
	if err != nil {
		t.Fatalf("buildOriginAllowlist: %v", err)
	}
	interactions, err := buildInteractionOriginAllowlist(cfg)
	if err != nil {
		t.Fatalf("buildInteractionOriginAllowlist: %v", err)
	}
	if got, want := interactions.Len(), cors.Len()-1; got != want {
		t.Errorf("interaction allowlist size=%d want %d (CORS size %d minus the one client origin)",
			got, want, cors.Len())
	}
}
