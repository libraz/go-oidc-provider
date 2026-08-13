package op_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

//nolint:gosec // opaque test fixture secret, not a credential.
const authMethodSurfaceSecret = "authmethod-surface-secret"

// enumeratedAuthMethods lists every [op.AuthMethod] constant the package
// exports. A constant added without a row here is invisible to the
// guards below, so the list is checked for completeness against
// discovery rather than trusted on its own.
var enumeratedAuthMethods = []op.AuthMethod{
	op.AuthClientSecretBasic,
	op.AuthClientSecretPost,
	op.AuthPrivateKeyJWT,
	op.AuthTLSClientAuth,
	op.AuthSelfSignedTLSClientAuth,
	op.AuthNone,
}

// notSelectableAuthMethods is the set of method names the type
// enumerates but no public surface admits: [op.New] refuses a static
// client seeded with one, dynamic registration refuses it, and
// discovery never advertises it.
//
// The set is declared here rather than derived so it has to be edited
// deliberately. It is the machine-checkable half of the caveat carried
// by the constants' godoc, and the two are meant to move together: if
// the OP ever learns to negotiate an RFC 8705 method, the guard below
// fails until the row is dropped, which is the prompt to drop the
// caveat as well.
var notSelectableAuthMethods = []op.AuthMethod{
	op.AuthTLSClientAuth,
	op.AuthSelfSignedTLSClientAuth,
}

// TestAuthMethod_RecognisedSetMatchesTheAdvertisedSurface pins the two
// sets that must not drift: the method names [op.AuthMethod.Valid]
// accepts, and the ones the OP actually publishes in
// token_endpoint_auth_methods_supported.
//
// Valid reporting true for a method no surface admits is what made the
// enum misleading in the first place, and a review of the godoc cannot
// hold that shut — the doc and the wiring live in different packages.
// Anchoring the difference to an explicit set turns a silent divergence
// into a failing test in both directions: a new constant that nothing
// advertises fails here, and a method that becomes selectable fails
// here too, until the declared set is corrected.
func TestAuthMethod_RecognisedSetMatchesTheAdvertisedSurface(t *testing.T) {
	t.Parallel()

	advertised := advertisedAuthMethods(t)
	if len(advertised) == 0 {
		t.Fatal("discovery advertised no token_endpoint_auth_methods_supported; the probe is broken, not the enum")
	}

	// Everything the OP advertises must be a name the enum knows, or an
	// embedder cannot express the OP's own configuration in the type.
	for _, name := range advertised {
		if !op.AuthMethod(name).Valid() {
			t.Errorf("discovery advertises %q but AuthMethod(%q).Valid() is false: "+
				"the OP accepts a method the exported enum does not name", name, name)
		}
	}

	for _, m := range enumeratedAuthMethods {
		if !m.Valid() {
			t.Errorf("AuthMethod(%q).Valid() is false but the constant is exported", m)
			continue
		}
		listed := slices.Contains(advertised, m.String())
		excluded := slices.Contains(notSelectableAuthMethods, m)
		switch {
		case listed && excluded:
			t.Errorf("%q is declared not-selectable but discovery advertises it; "+
				"drop it from notSelectableAuthMethods and from the godoc caveat", m)
		case !listed && !excluded:
			t.Errorf("%q is recognised by Valid() but discovery does not advertise it and it "+
				"is not declared not-selectable; either wire it through or document it as unreachable", m)
		}
	}
}

// TestNew_RejectsAStaticClientSeededWithAnUnselectableAuthMethod is the
// seed half of the same property. Discovery says what the OP is willing
// to publish; this says what it is willing to persist, and the invariant
// only holds if the two agree.
func TestNew_RejectsAStaticClientSeededWithAnUnselectableAuthMethod(t *testing.T) {
	t.Parallel()

	for _, m := range notSelectableAuthMethods {
		t.Run(m.String(), func(t *testing.T) {
			t.Parallel()

			_, err := op.New(staticClientOpts(t, m)...)
			if err == nil {
				t.Fatalf("op.New accepted a static client seeded with %q, "+
					"which no runtime path can authenticate", m)
			}
			if !strings.Contains(err.Error(), m.String()) {
				t.Errorf("error does not name the offending method %q: %v", m, err)
			}
		})
	}
}

// TestNew_AcceptsAStaticClientSeededWithASelectableAuthMethod keeps the
// rejection above worth reading: the seed shape is otherwise valid, so
// the refusal is attributable to the method and nothing else.
func TestNew_AcceptsAStaticClientSeededWithASelectableAuthMethod(t *testing.T) {
	t.Parallel()

	for _, m := range []op.AuthMethod{op.AuthClientSecretBasic, op.AuthClientSecretPost} {
		t.Run(m.String(), func(t *testing.T) {
			t.Parallel()

			if _, err := op.New(staticClientOpts(t, m)...); err != nil {
				t.Fatalf("op.New rejected a static client seeded with %q: %v", m, err)
			}
		})
	}
}

// staticClientOpts is the base configuration plus one confidential
// static client whose only varying field is the authentication method.
//
// The store is [inmem.Store] rather than the package's default stub
// because startup seeding requires a [store.StaticClientReconciler];
// without one every seed is refused for that reason and the method
// under test is never reached.
func staticClientOpts(tb testing.TB, m op.AuthMethod) []op.Option {
	tb.Helper()
	opts := append(validBaseOptsWithStoreNoAuthn(tb, inmem.New()), fixtureAuthenticator())
	return append(opts, op.WithStaticClients(op.ConfidentialClient{
		ID:           "authmethod-surface",
		Secret:       authMethodSurfaceSecret,
		AuthMethod:   m,
		RedirectURIs: []string{"https://rp.example.com/callback"},
		Scopes:       []string{"openid"},
	}))
}

// advertisedAuthMethods reads token_endpoint_auth_methods_supported off
// a default provider's discovery document.
func advertisedAuthMethods(tb testing.TB) []string {
	tb.Helper()

	provider, err := op.New(validBaseOpts(tb)...)
	if err != nil {
		tb.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/.well-known/openid-configuration", http.NoBody)
	if reqErr != nil {
		tb.Fatalf("NewRequest: %v", reqErr)
	}
	resp, doErr := srv.Client().Do(req)
	if doErr != nil {
		tb.Fatalf("GET discovery: %v", doErr)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		tb.Fatalf("read body: %v", readErr)
	}
	var doc struct {
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		tb.Fatalf("decode discovery: %v", err)
	}
	return doc.TokenEndpointAuthMethodsSupported
}
