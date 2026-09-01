package authorizeendpoint

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/op/store"
)

// resolveGrantACRAMR names the exit a completed ceremony took and asks
// the record it points at for the authentication the response reports.
//
// It is the two production statements that precede the terminal gate,
// spelled as one call: the endpoint itself resolves the same pair inside
// [validateTerminalAuthorization], which returns what it validated. The
// tests below drive it directly because their subject is the resolution
// — which record is read, and what the ACR policy is handed — rather
// than the request constraints the gate goes on to apply.
func resolveGrantACRAMR(
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	req *authorize.Request,
	authnState authn.State,
	subject string,
	authTime time.Time,
) (string, []string, time.Time, error) {
	_, backing := interactionExit(r, deps, rec, req, authnState, subject, authTime)
	authCtx, err := backing.authContext(r.Context())
	if err != nil {
		return "", nil, time.Time{}, err
	}
	if !authCtx.AuthTime.IsZero() {
		authTime = authCtx.AuthTime
	}
	return authCtx.ACR, authCtx.AMR, authTime, nil
}

// acrCapture records the input the ACR policy was handed and answers
// with a fixed verdict, so a test can assert on what the wire layer
// resolved rather than on what the policy decided to do with it.
type acrCapture struct {
	in  ACRResolveInput
	out ACRResolveOutput
}

func (c *acrCapture) resolver() ACRResolver {
	return func(_ context.Context, in ACRResolveInput) ACRResolveOutput {
		c.in = in
		return c.out
	}
}

// acrTestState marks st as the state of a chain that ran a credential
// factor. Only such a chain consults the ACR policy: one that
// authenticated nobody reports the backing session's assurance
// verbatim, so a factor-less state would never reach the resolver.
func acrTestState(st authn.State) authn.State {
	st.Factors = []authn.Factor{{Type: authn.FactorPassword, AssuranceLevel: authn.AAL1}}
	return st
}

// acrTestRequest builds an interaction-endpoint request carrying the
// browser headers the remote hints are read from.
func acrTestRequest(t *testing.T) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://op.example.com/interaction/uid-1",
		http.NoBody,
	)
	r.Header.Set("Accept-Language", "ja-JP,ja;q=0.9")
	return r
}

// TestResolveGrantACRAMR_ClaimsOnlyACRReachesPolicy covers the request
// shape where the relying party names its authentication context only
// through the claims parameter. The step-up gate honours that spelling,
// so the policy has to see the same value; a policy that saw an empty
// requested set would hand back an acr the OP never agreed to.
func TestResolveGrantACRAMR_ClaimsOnlyACRReachesPolicy(t *testing.T) {
	t.Parallel()

	capture := &acrCapture{out: ACRResolveOutput{ACR: "urn:example:strong", OK: true}}
	req := &authorize.Request{
		ClientID: "client-1",
		Claims: &authorize.ClaimsRequest{
			IDToken: map[string]authorize.ClaimSpec{
				"acr": {Essential: true, Values: []any{"urn:example:strong", "urn:example:stronger"}},
			},
		},
	}
	acr, _, _, err := resolveGrantACRAMR(
		acrTestRequest(t),
		resolved{Deps: Deps{ACRResolver: capture.resolver()}},
		&store.Interaction{ClientID: "client-1"},
		req,
		acrTestState(authn.State{}),
		"user-1",
		time.Time{},
	)
	if err != nil {
		t.Fatalf("resolveGrantACRAMR: %v", err)
	}
	want := []string{"urn:example:strong", "urn:example:stronger"}
	if !slices.Equal(capture.in.RequestedACRValues, want) {
		t.Errorf("RequestedACRValues = %v, want %v", capture.in.RequestedACRValues, want)
	}
	if acr != "urn:example:strong" {
		t.Errorf("acr = %q, want %q", acr, "urn:example:strong")
	}
}

// TestResolveGrantACRAMR_UnionsBothACRSpellings pins the merge order and
// the de-duplication: acr_values first (it carries the RP's preference
// order), then the claims entries, each value offered once.
func TestResolveGrantACRAMR_UnionsBothACRSpellings(t *testing.T) {
	t.Parallel()

	capture := &acrCapture{out: ACRResolveOutput{ACR: "a", OK: true}}
	req := &authorize.Request{
		ClientID:  "client-1",
		ACRValues: []string{"a", "b"},
		Claims: &authorize.ClaimsRequest{
			IDToken: map[string]authorize.ClaimSpec{
				"acr": {Value: "b", Values: []any{"c", 42}},
			},
		},
	}
	if _, _, _, err := resolveGrantACRAMR(
		acrTestRequest(t),
		resolved{Deps: Deps{ACRResolver: capture.resolver()}},
		&store.Interaction{ClientID: "client-1"},
		req,
		acrTestState(authn.State{}),
		"user-1",
		time.Time{},
	); err != nil {
		t.Fatalf("resolveGrantACRAMR: %v", err)
	}
	want := []string{"a", "b", "c"}
	if !slices.Equal(capture.in.RequestedACRValues, want) {
		t.Errorf("RequestedACRValues = %v, want %v (non-string entries skipped)",
			capture.in.RequestedACRValues, want)
	}
}

// TestResolveGrantACRAMR_RemoteHintsReachPolicy asserts the network
// context travels to the policy. A policy that scores the login against
// the address it came from would otherwise always take its no-hints
// branch on this path and score every completed interaction the same.
func TestResolveGrantACRAMR_RemoteHintsReachPolicy(t *testing.T) {
	t.Parallel()

	capture := &acrCapture{out: ACRResolveOutput{ACR: "urn:example:strong", OK: true}}
	state := authn.State{
		RemoteIP:  netip.MustParseAddr("203.0.113.7"),
		UserAgent: "Mozilla/5.0 (test)",
	}
	if _, _, _, err := resolveGrantACRAMR(
		acrTestRequest(t),
		resolved{Deps: Deps{ACRResolver: capture.resolver()}},
		&store.Interaction{ClientID: "client-1"},
		&authorize.Request{ClientID: "client-1", ACRValues: []string{"urn:example:strong"}},
		acrTestState(state),
		"user-1",
		time.Time{},
	); err != nil {
		t.Fatalf("resolveGrantACRAMR: %v", err)
	}
	if capture.in.RemoteIP != "203.0.113.7" {
		t.Errorf("RemoteIP = %q, want %q", capture.in.RemoteIP, "203.0.113.7")
	}
	if capture.in.UserAgent != "Mozilla/5.0 (test)" {
		t.Errorf("UserAgent = %q, want %q", capture.in.UserAgent, "Mozilla/5.0 (test)")
	}
	if capture.in.AcceptLanguage != "ja-JP,ja;q=0.9" {
		t.Errorf("AcceptLanguage = %q, want the request's Accept-Language", capture.in.AcceptLanguage)
	}
}

// TestResolveGrantACRAMR_RemoteHintsFallBackToRequest covers a chain
// that carries no recorded address — the hints are re-derived from the
// terminal request through the same trusted-proxy path rather than
// reaching the policy as netip.Addr's "invalid IP" placeholder.
func TestResolveGrantACRAMR_RemoteHintsFallBackToRequest(t *testing.T) {
	t.Parallel()

	capture := &acrCapture{out: ACRResolveOutput{ACR: "urn:example:strong", OK: true}}
	r := acrTestRequest(t)
	r.RemoteAddr = "198.51.100.4:51234"
	r.Header.Set("User-Agent", "curl/8")
	// A forwarded header from an untrusted peer must not win: no trust
	// is configured here, so the socket address is authoritative.
	r.Header.Set("X-Forwarded-For", "192.0.2.1")
	if _, _, _, err := resolveGrantACRAMR(
		r,
		resolved{Deps: Deps{ACRResolver: capture.resolver()}},
		&store.Interaction{ClientID: "client-1"},
		&authorize.Request{ClientID: "client-1", ACRValues: []string{"urn:example:strong"}},
		acrTestState(authn.State{}),
		"user-1",
		time.Time{},
	); err != nil {
		t.Fatalf("resolveGrantACRAMR: %v", err)
	}
	if capture.in.RemoteIP != "198.51.100.4" {
		t.Errorf("RemoteIP = %q, want the socket address", capture.in.RemoteIP)
	}
	if capture.in.UserAgent != "curl/8" {
		t.Errorf("UserAgent = %q, want %q", capture.in.UserAgent, "curl/8")
	}
}

// TestResolveGrantACRAMR_EssentialUnsatisfiedFails is the refusal path:
// the request declared the acr essential and the policy could not
// satisfy it, so the resolution fails instead of flattening the claim
// and minting a code the relying party asked the OP not to mint.
func TestResolveGrantACRAMR_EssentialUnsatisfiedFails(t *testing.T) {
	t.Parallel()

	capture := &acrCapture{out: ACRResolveOutput{OK: false}}
	req := &authorize.Request{
		ClientID:  "client-1",
		ACRValues: []string{"urn:example:strong"},
		Claims: &authorize.ClaimsRequest{
			IDToken: map[string]authorize.ClaimSpec{"acr": {Essential: true}},
		},
	}
	_, _, _, err := resolveGrantACRAMR(
		acrTestRequest(t),
		resolved{Deps: Deps{ACRResolver: capture.resolver()}},
		&store.Interaction{ClientID: "client-1"},
		req,
		acrTestState(authn.State{}),
		"user-1",
		time.Time{},
	)
	if !errors.Is(err, errACRUnmet) {
		t.Fatalf("err = %v, want errACRUnmet", err)
	}
}

// TestResolveGrantACRAMR_VoluntaryUnsatisfiedOmitsACR is the contrast:
// acr_values is a voluntary hint, so an unsatisfiable request is served
// with the acr claim omitted rather than refused.
func TestResolveGrantACRAMR_VoluntaryUnsatisfiedOmitsACR(t *testing.T) {
	t.Parallel()

	capture := &acrCapture{out: ACRResolveOutput{OK: false}}
	acr, _, _, err := resolveGrantACRAMR(
		acrTestRequest(t),
		resolved{Deps: Deps{ACRResolver: capture.resolver()}},
		&store.Interaction{ClientID: "client-1"},
		&authorize.Request{ClientID: "client-1", ACRValues: []string{"urn:example:strong"}},
		acrTestState(authn.State{}),
		"user-1",
		time.Time{},
	)
	if err != nil {
		t.Fatalf("resolveGrantACRAMR: %v", err)
	}
	if acr != "" {
		t.Errorf("acr = %q, want the claim to be omitted", acr)
	}
}

// TestResolveGrantACRAMR_NonEssentialClaimsSpecOmitsACR pins the
// boundary between the two branches: naming acr through the claims
// parameter without marking it essential stays voluntary.
func TestResolveGrantACRAMR_NonEssentialClaimsSpecOmitsACR(t *testing.T) {
	t.Parallel()

	capture := &acrCapture{out: ACRResolveOutput{OK: false}}
	req := &authorize.Request{
		ClientID: "client-1",
		Claims: &authorize.ClaimsRequest{
			IDToken: map[string]authorize.ClaimSpec{
				"acr": {Values: []any{"urn:example:strong"}},
			},
		},
	}
	acr, _, _, err := resolveGrantACRAMR(
		acrTestRequest(t),
		resolved{Deps: Deps{ACRResolver: capture.resolver()}},
		&store.Interaction{ClientID: "client-1"},
		req,
		acrTestState(authn.State{}),
		"user-1",
		time.Time{},
	)
	if err != nil {
		t.Fatalf("resolveGrantACRAMR: %v", err)
	}
	if acr != "" {
		t.Errorf("acr = %q, want the claim to be omitted", acr)
	}
}
