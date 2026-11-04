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
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

//nolint:gosec // opaque test fixture secret, not a credential.
const authMethodSurfaceSecret = "authmethod-surface-secret-0123456789"

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

// mtlsAuthMethods is the set of method names that are selectable only
// with [feature.MTLS]: without it [op.New] refuses a static client seeded
// with one, dynamic registration refuses it, and discovery does not
// advertise it. Declared rather than derived so the gate is edited
// deliberately.
var mtlsAuthMethods = []op.AuthMethod{
	op.AuthTLSClientAuth,
	op.AuthSelfSignedTLSClientAuth,
}

// TestAuthMethod_RecognisedSetMatchesTheAdvertisedSurface pins the sets
// that must not drift: the method names [op.AuthMethod.Valid] accepts,
// and the ones the OP publishes in token_endpoint_auth_methods_supported.
// Without feature.MTLS every recognised method except [mtlsAuthMethods]
// is advertised; with it, every recognised method is.
func TestAuthMethod_RecognisedSetMatchesTheAdvertisedSurface(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		extra []op.Option
		gated []op.AuthMethod
	}{
		{"without feature.MTLS", nil, mtlsAuthMethods},
		{"with feature.MTLS", []op.Option{op.WithFeature(feature.MTLS)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			advertised := advertisedAuthMethods(t, tc.extra...)
			if len(advertised) == 0 {
				t.Fatal("discovery advertised no token_endpoint_auth_methods_supported; the probe is broken, not the enum")
			}
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
				gated := slices.Contains(tc.gated, m)
				switch {
				case listed && gated:
					t.Errorf("%q is advertised although its feature is off", m)
				case !listed && !gated:
					t.Errorf("%q is recognised by Valid() but discovery does not advertise it", m)
				}
			}
		})
	}
}

// TestNew_RejectsAStaticClientSeededWithAnMTLSMethodWithoutTheFeature is
// the seed half of the same property: without feature.MTLS the OP neither
// publishes nor persists an mTLS method.
func TestNew_RejectsAStaticClientSeededWithAnMTLSMethodWithoutTheFeature(t *testing.T) {
	t.Parallel()

	for _, m := range mtlsAuthMethods {
		t.Run(m.String(), func(t *testing.T) {
			t.Parallel()

			_, err := op.New(staticClientOpts(t, m)...)
			if err == nil {
				t.Fatalf("op.New accepted a static client seeded with %q without feature.MTLS", m)
			}
			if !strings.Contains(err.Error(), m.String()) || !strings.Contains(err.Error(), "WithFeature(feature.MTLS)") {
				t.Errorf("error does not name %q and the feature it needs: %v", m, err)
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
// the discovery document of a default provider plus extra.
func advertisedAuthMethods(tb testing.TB, extra ...op.Option) []string {
	tb.Helper()

	provider, err := op.New(append(validBaseOpts(tb), extra...)...)
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
