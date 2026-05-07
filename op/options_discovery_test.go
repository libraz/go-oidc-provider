package op_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jwks"
	"github.com/libraz/go-oidc-provider/op"
)

// TestWithJWKSRotationActive_FlipsCacheControl pins the wiring from
// op.WithJWKSRotationActive through op.New to the JWKS handler's
// rotation-aware Cache-Control branch. The predicate's return value
// flips between calls and the response header MUST track it: long
// cache while idle, short cache while rotating, long cache again
// once the predicate returns false.
func TestWithJWKSRotationActive_FlipsCacheControl(t *testing.T) {
	t.Parallel()

	var rotating atomic.Bool
	provider, err := op.New(append(validBaseOpts(t),
		op.WithJWKSRotationActive(rotating.Load),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	get := func() string {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/oidc/jwks", http.NoBody)
		if reqErr != nil {
			t.Fatalf("NewRequest: %v", reqErr)
		}
		resp, doErr := srv.Client().Do(req)
		if doErr != nil {
			t.Fatalf("GET /oidc/jwks: %v", doErr)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d want 200", resp.StatusCode)
		}
		return resp.Header.Get("Cache-Control")
	}

	if got := get(); got != jwks.CacheControl {
		t.Errorf("idle Cache-Control=%q want %q", got, jwks.CacheControl)
	}

	rotating.Store(true)
	if got := get(); got != jwks.CacheControlRotating {
		t.Errorf("rotating Cache-Control=%q want %q", got, jwks.CacheControlRotating)
	}

	rotating.Store(false)
	if got := get(); got != jwks.CacheControl {
		t.Errorf("post-rotation Cache-Control=%q want %q", got, jwks.CacheControl)
	}
}

// TestWithJWKSRotationActive_NilLeavesLongCache documents that
// passing a nil predicate (or omitting the option entirely) leaves
// the JWKS handler in long-cache mode for every response. The test
// exercises the explicit-nil path because the omitted-option path is
// already covered by every other op_test case that hits /jwks.
func TestWithJWKSRotationActive_NilLeavesLongCache(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithJWKSRotationActive(nil),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/oidc/jwks", http.NoBody)
	if reqErr != nil {
		t.Fatalf("NewRequest: %v", reqErr)
	}
	resp, doErr := srv.Client().Do(req)
	if doErr != nil {
		t.Fatalf("GET /oidc/jwks: %v", doErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != jwks.CacheControl {
		t.Errorf("Cache-Control=%q want %q (nil predicate must leave long cache)", got, jwks.CacheControl)
	}
}

// TestWithDiscoveryMetadata_HappyPathRoundTrips wires the option into
// op.New, fetches the discovery document, and verifies that every
// configured field appears at the top level of the JSON. The test
// is the integration anchor for the option's plumbing into the wire.
//
// Spec: RFC 8414 §2.
func TestWithDiscoveryMetadata_HappyPathRoundTrips(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithDiscoveryMetadata(op.DiscoveryMetadata{
			ServiceDocumentation: "https://idp.example.com/docs",
			OPPolicyURI:          "https://idp.example.com/policy",
			OPTermsOfServiceURI:  "https://idp.example.com/tos",
			UILocalesSupported:   []string{"ja-JP", "en-US"},
			Extra: map[string]any{
				"x_custom_thing": "frobnicate",
			},
		}),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/.well-known/openid-configuration", http.NoBody)
	if reqErr != nil {
		t.Fatalf("NewRequest: %v", reqErr)
	}
	resp, doErr := srv.Client().Do(req)
	if doErr != nil {
		t.Fatalf("GET discovery: %v", doErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("read body: %v", readErr)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	stringChecks := map[string]string{
		"service_documentation": "https://idp.example.com/docs",
		"op_policy_uri":         "https://idp.example.com/policy",
		"op_tos_uri":            "https://idp.example.com/tos",
		"x_custom_thing":        "frobnicate",
	}
	for key, want := range stringChecks {
		got, _ := wire[key].(string)
		if got != want {
			t.Errorf("wire %q = %q, want %q", key, got, want)
		}
	}
	locales, ok := wire["ui_locales_supported"].([]any)
	if !ok {
		t.Fatalf("ui_locales_supported is not a JSON array: %T (%v)",
			wire["ui_locales_supported"], wire["ui_locales_supported"])
	}
	if len(locales) != 2 || locales[0] != "ja-JP" || locales[1] != "en-US" {
		t.Errorf("ui_locales_supported=%v want [ja-JP en-US]", locales)
	}
}

// TestWithDiscoveryMetadata_RejectsOPControlledOverride confirms that
// any embedder Extra key matching an OP-controlled field name (computed
// via reflection over the discovery document) fails op.New with a
// configuration error that names the offending key.
//
// Spec: RFC 8414 §2 (OP-controlled fields cannot be silently shadowed).
func TestWithDiscoveryMetadata_RejectsOPControlledOverride(t *testing.T) {
	t.Parallel()

	cases := []string{
		"authorization_endpoint",
		"issuer",
		"response_types_supported",
		"token_endpoint",
		"jwks_uri",
		"grant_types_supported",
	}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t),
				op.WithDiscoveryMetadata(op.DiscoveryMetadata{
					Extra: map[string]any{
						key: "https://attacker.example.com",
					},
				}),
			)...)
			if err == nil {
				t.Fatalf("expected error when Extra overrides %q, got nil", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("err = %v, want it to name the offending key %q", err, key)
			}
			var typed *op.Error
			if !errors.As(err, &typed) {
				t.Fatalf("err = %v, want *op.Error", err)
			}
		})
	}
}

// TestWithDiscoveryMetadata_OmitsDefaultMetadata pins the no-metadata
// posture: when the option is absent, the discovery document MUST NOT
// advertise the embedder-owned static fields (service_documentation,
// op_policy_uri, op_tos_uri). The ui_locales_supported field is
// auto-derived from the registered locale resolver (seed bundles plus
// [WithLocale]) so it is asserted separately — its presence is honest
// advertisement, not embedder-supplied metadata.
func TestWithDiscoveryMetadata_OmitsDefaultMetadata(t *testing.T) {
	t.Parallel()

	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/.well-known/openid-configuration", http.NoBody)
	if reqErr != nil {
		t.Fatalf("NewRequest: %v", reqErr)
	}
	resp, doErr := srv.Client().Do(req)
	if doErr != nil {
		t.Fatalf("GET discovery: %v", doErr)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("read body: %v", readErr)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{
		"service_documentation", "op_policy_uri", "op_tos_uri",
	} {
		if _, present := wire[key]; present {
			t.Errorf("wire %q must be absent without WithDiscoveryMetadata", key)
		}
	}
	// ui_locales_supported is auto-derived from the resolver. The seed
	// bundles guarantee at least the canonical "en" tag is registered,
	// so the wire MUST advertise a non-empty array even without an
	// explicit WithDiscoveryMetadata or WithLocale call.
	locales, ok := wire["ui_locales_supported"].([]any)
	if !ok {
		t.Fatalf("ui_locales_supported missing or not a JSON array: %T (%v)",
			wire["ui_locales_supported"], wire["ui_locales_supported"])
	}
	if len(locales) == 0 {
		t.Errorf("ui_locales_supported is empty; want the seed locales")
	}
}

// TestDiscovery_UILocalesSupported_DerivedFromResolver pins the
// auto-derivation rule documented on
// [DiscoveryMetadata.UILocalesSupported]: when the embedder does not
// supply an explicit list, the discovery document advertises every
// locale registered with the runtime resolver — seed bundles plus any
// [WithLocale] additions. The test registers a custom French bundle
// and asserts "fr" appears in the wire array alongside the seed
// locales.
func TestDiscovery_UILocalesSupported_DerivedFromResolver(t *testing.T) {
	t.Parallel()

	french, err := op.LocaleBundleFromMap("fr", map[string]string{
		"login.title": "Connexion",
	})
	if err != nil {
		t.Fatalf("LocaleBundleFromMap(fr): %v", err)
	}
	provider, err := op.New(append(validBaseOpts(t), op.WithLocale(french))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/.well-known/openid-configuration", http.NoBody)
	if reqErr != nil {
		t.Fatalf("NewRequest: %v", reqErr)
	}
	resp, doErr := srv.Client().Do(req)
	if doErr != nil {
		t.Fatalf("GET discovery: %v", doErr)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("read body: %v", readErr)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	locales, ok := wire["ui_locales_supported"].([]any)
	if !ok {
		t.Fatalf("ui_locales_supported missing or not a JSON array: %T (%v)",
			wire["ui_locales_supported"], wire["ui_locales_supported"])
	}
	sawFR := false
	for _, l := range locales {
		if s, _ := l.(string); s == "fr" {
			sawFR = true
			break
		}
	}
	if !sawFR {
		t.Errorf("ui_locales_supported = %v, want it to include the WithLocale-registered \"fr\"", locales)
	}
}

// TestWithDiscoveryMetadata_RejectsDuplicate confirms that the option
// is single-shot: a second call fails op.New with a configuration
// error so a misconfiguration is not silently masked by the second
// value winning.
func TestWithDiscoveryMetadata_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithDiscoveryMetadata(op.DiscoveryMetadata{
			ServiceDocumentation: "https://idp.example.com/docs",
		}),
		op.WithDiscoveryMetadata(op.DiscoveryMetadata{
			ServiceDocumentation: "https://other.example.com/docs",
		}),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate WithDiscoveryMetadata, got nil")
	}
	var typed *op.Error
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *op.Error", err)
	}
}

// TestWithDiscoveryMetadata_EmptyServiceDocumentationOmitted confirms
// that the empty string is treated as a no-op: the option accepts the
// value (consistent with the rest of the option surface — empty
// strings denote "field unset" everywhere) and the wire shape stays
// clean.
func TestWithDiscoveryMetadata_EmptyServiceDocumentationOmitted(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithDiscoveryMetadata(op.DiscoveryMetadata{
			ServiceDocumentation: "",
		}),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	defer srv.Close()

	req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/.well-known/openid-configuration", http.NoBody)
	if reqErr != nil {
		t.Fatalf("NewRequest: %v", reqErr)
	}
	resp, doErr := srv.Client().Do(req)
	if doErr != nil {
		t.Fatalf("GET discovery: %v", doErr)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("read body: %v", readErr)
	}
	var wire map[string]any
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := wire["service_documentation"]; present {
		t.Errorf("service_documentation must be omitted when an empty string is supplied")
	}
}

// TestWithDiscoveryMetadata_RejectsEmptyExtraKey confirms that a
// blank string under Extra fails fast — silently accepting it would
// produce a "":value entry on the wire, which no RP can address.
func TestWithDiscoveryMetadata_RejectsEmptyExtraKey(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithDiscoveryMetadata(op.DiscoveryMetadata{
			Extra: map[string]any{"": "v"},
		}),
	)...)
	if err == nil {
		t.Fatal("expected error for empty Extra key, got nil")
	}
}
