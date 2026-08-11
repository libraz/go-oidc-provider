package op_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// validBaseOptsWithInmem returns the same option shape as
// [validBaseOpts] but swaps [stubStore] for the inmem reference
// implementation, so tests that exercise paths reaching the DPoP /
// MTLS verifier wiring (which calls into substores [stubStore]
// deliberately leaves panicking) construct without panic.
func validBaseOptsWithInmem(tb testing.TB) []op.Option {
	tb.Helper()
	return []op.Option{
		op.WithIssuer(validIssuer),
		op.WithStore(inmem.New()),
		op.WithKeyset(validKeyset(tb)),
		op.WithCookieKeys(newRandomCookieKey(tb)),
		fixtureAuthenticator(),
	}
}

func TestWithMountPrefix_Validates(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		prefix  string
		wantErr bool
	}{
		{"slash", "/", false},
		{"oidc", "/oidc", false},
		{"empty", "", true},
		{"no leading slash", "oidc", true},
		{"trailing slash", "/oidc/", true},
		{"query", "/oidc?debug=1", true},
		{"duplicate slash", "/oidc//tenant", true},
		{"serve mux wildcard", "/oidc/{tenant}", true},
		{"percent encoded alias", "/%6fidc", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := append(validBaseOpts(t), op.WithMountPrefix(tc.prefix))
			_, err := op.New(opts...)
			if (err != nil) != tc.wantErr {
				t.Fatalf("WithMountPrefix(%q): err=%v wantErr=%v", tc.prefix, err, tc.wantErr)
			}
		})
	}
}

func TestWithEndpoints_OverrideAndDefaults(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t),
		op.WithEndpoints(op.Endpoints{Authorize: "/login", Token: "/jwt"}),
	)...)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestWithEndpoints_RejectsMalformedPaths(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		endpoints op.Endpoints
		wantField string
	}{
		{name: "relative", endpoints: op.Endpoints{Token: "token"}, wantField: "Token"},
		{name: "host pattern", endpoints: op.Endpoints{Token: "//example.com/token"}, wantField: "Token"},
		{name: "query", endpoints: op.Endpoints{Token: "/token?debug=1"}, wantField: "Token"},  //nolint:gosec // URL path test input, not a credential.
		{name: "fragment", endpoints: op.Endpoints{Token: "/token#debug"}, wantField: "Token"}, //nolint:gosec // URL path test input, not a credential.
		{name: "trailing slash", endpoints: op.Endpoints{Token: "/token/"}, wantField: "Token"},
		{name: "unclean", endpoints: op.Endpoints{Token: "/token//nested"}, wantField: "Token"}, //nolint:gosec // URL path test input, not a credential.
		{name: "serve mux wildcard", endpoints: op.Endpoints{Token: "/token/{id}"}, wantField: "Token"},
		{name: "percent encoded alias", endpoints: op.Endpoints{Token: "/%74oken"}, wantField: "Token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := op.New(append(validBaseOpts(t), op.WithEndpoints(tc.endpoints))...)
			if err == nil {
				t.Fatal("expected malformed endpoint path to fail construction")
			}
			if !strings.Contains(err.Error(), "WithEndpoints."+tc.wantField) {
				t.Errorf("err=%v want field WithEndpoints.%s", err, tc.wantField)
			}
		})
	}
}

func TestWithEndpoints_RejectsActiveRouteCollisions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		endpoints op.Endpoints
		wantLeft  string
		wantRight string
	}{
		{
			name:      "exact core endpoints",
			endpoints: op.Endpoints{JWKS: "/shared", Token: "/shared"},
			wantLeft:  "JWKS",
			wantRight: "Token",
		},
		{
			name: "interaction session prefix",
			// Session is deprecated and mounts nothing, but it still
			// takes part in the collision check; that is the property
			// this row covers.
			endpoints: op.Endpoints{Interaction: "/flow", Session: "/flow/session"},
			wantLeft:  "Interaction",
			wantRight: "Session",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := op.New(append(validBaseOpts(t), op.WithEndpoints(tc.endpoints))...)
			if err == nil {
				t.Fatal("expected colliding endpoint routes to fail construction")
			}
			if !strings.Contains(err.Error(), tc.wantLeft) || !strings.Contains(err.Error(), tc.wantRight) {
				t.Errorf("err=%v want both %s and %s", err, tc.wantLeft, tc.wantRight)
			}
		})
	}
}

func TestWithEndpoints_CollisionCheckUsesEnabledRouteSet(t *testing.T) {
	t.Parallel()

	endpoints := op.WithEndpoints(op.Endpoints{
		Introspect: "/optional",
		Revoke:     "/optional",
	})
	if _, err := op.New(append(validBaseOpts(t), endpoints)...); err != nil {
		t.Fatalf("disabled optional endpoints must not collide: %v", err)
	}
	if _, err := op.New(append(validBaseOpts(t),
		endpoints,
		op.WithFeature(feature.Introspect),
	)...); err != nil {
		t.Fatalf("one enabled optional endpoint must construct: %v", err)
	}

	_, err := op.New(append(validBaseOpts(t),
		endpoints,
		op.WithFeature(feature.Introspect),
		op.WithFeature(feature.Revoke),
	)...)
	if err == nil {
		t.Fatal("expected two enabled optional endpoints at the same path to fail")
	}
	if !strings.Contains(err.Error(), "Introspect") || !strings.Contains(err.Error(), "Revoke") {
		t.Errorf("err=%v want Introspect and Revoke", err)
	}
}

func TestWithAccessTokenTTL_RejectsNegative(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithAccessTokenTTL(-1*time.Second))...)
	if err == nil {
		t.Fatal("expected error for negative TTL, got nil")
	}
	if !strings.Contains(err.Error(), "non-negative") {
		t.Errorf("err = %v, want it to mention non-negative", err)
	}
}

func TestWithPARLifetime_RejectsNegative(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithPARLifetime(-1*time.Second))...)
	if err == nil {
		t.Fatal("expected error for negative PAR lifetime, got nil")
	}
	if !strings.Contains(err.Error(), "non-negative") {
		t.Errorf("err = %v, want it to mention non-negative", err)
	}
}

func TestWithPARLifetime_AcceptsZeroAndCustom(t *testing.T) {
	t.Parallel()

	// Zero opts into the PAR endpoint's own default (60s); a positive
	// value is threaded to the record lifetime. Both must construct.
	if _, err := op.New(append(validBaseOpts(t), op.WithPARLifetime(0))...); err != nil {
		t.Fatalf("zero PAR lifetime: %v", err)
	}
	if _, err := op.New(append(validBaseOpts(t), op.WithPARLifetime(5*time.Minute))...); err != nil {
		t.Fatalf("custom PAR lifetime: %v", err)
	}
}

func TestWithAccessTokenTTL_AcceptsZero(t *testing.T) {
	t.Parallel()

	// Zero opts into [DefaultAccessTokenTTL]. The construction must
	// succeed; the actual default substitution is observable through
	// downstream behavior, not directly readable here.
	_, err := op.New(append(validBaseOpts(t), op.WithAccessTokenTTL(0))...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithAccessTokenTTL_AcceptsCustomValue(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithAccessTokenTTL(2*time.Minute))...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestWithAccessTokenTTL_RejectsAboveImplementationMax pins the
// ceiling: the option layer enforces an implementation-defined upper bound
// (24h) so a typo cannot produce a token whose practical
// invalidation requires per-grant revocation. The bound composes
// with profile-supplied caps; this test exercises the bare
// (no-profile) deployment.
func TestWithAccessTokenTTL_RejectsAboveImplementationMax(t *testing.T) {
	t.Parallel()

	// 24h+1s is just past the bound; the option must reject.
	_, err := op.New(append(validBaseOpts(t), op.WithAccessTokenTTL(op.MaxAccessTokenTTL+time.Second))...)
	if err == nil {
		t.Fatal("expected error for TTL above implementation max, got nil")
	}
	if !strings.Contains(err.Error(), "implementation-defined maximum") {
		t.Errorf("err = %v, want it to mention the implementation-defined maximum", err)
	}
}

// TestWithAccessTokenTTL_AcceptsAtImplementationMax pins the
// happy-path boundary: exactly the documented max is accepted so an
// embedder can dial up to the ceiling without a one-off configuration
// error.
func TestWithAccessTokenTTL_AcceptsAtImplementationMax(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithAccessTokenTTL(op.MaxAccessTokenTTL))...); err != nil {
		t.Fatalf("unexpected error at the implementation max: %v", err)
	}
}

func TestWithAccessTokenTTL_FAPI2BaselineRejectsTooLong(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenTTL(15*time.Minute),
	)...)
	if err == nil {
		t.Fatal("expected error for TTL above FAPI2 cap, got nil")
	}
	if !strings.Contains(err.Error(), "fapi2-baseline") || !strings.Contains(err.Error(), "10m") {
		t.Errorf("err = %v, want it to mention fapi2-baseline and the 10m cap", err)
	}
}

func TestWithAccessTokenTTL_FAPI2BaselineAcceptsAtCap(t *testing.T) {
	t.Parallel()

	// Stricter-than-profile is OK; exactly at the cap is also OK.
	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenTTL(10*time.Minute),
	)...)
	if err != nil {
		t.Fatalf("unexpected error at the cap: %v", err)
	}
}

func TestWithRefreshTokenTTL_RejectsNegative(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithRefreshTokenTTL(-1*time.Second))...)
	if err == nil {
		t.Fatal("expected error for negative TTL, got nil")
	}
	if !strings.Contains(err.Error(), "non-negative") {
		t.Errorf("err = %v, want it to mention non-negative", err)
	}
}

func TestWithRefreshTokenTTL_AcceptsZero(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithRefreshTokenTTL(0))...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithRefreshTokenTTL_AcceptsCustomValue(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithRefreshTokenTTL(7*24*time.Hour))...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestWithRefreshTokenOfflineTTL_RejectsNegative pins the option-site
// argument validation. A negative duration is a misconfiguration the
// embedder must see at startup rather than at /token, where it would
// silently issue refresh tokens with a back-dated expiry.
func TestWithRefreshTokenOfflineTTL_RejectsNegative(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithRefreshTokenOfflineTTL(-1*time.Second))...)
	if err == nil {
		t.Fatal("expected error for negative TTL, got nil")
	}
	if !strings.Contains(err.Error(), "non-negative") {
		t.Errorf("err = %v, want it to mention non-negative", err)
	}
}

// TestWithRefreshTokenOfflineTTL_AcceptsZero confirms the explicit
// zero defers to [op.WithRefreshTokenTTL]. An embedder who does not
// distinguish offline use must be able to leave the option absent
// without seeing a build-time error.
func TestWithRefreshTokenOfflineTTL_AcceptsZero(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithRefreshTokenOfflineTTL(0))...); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestWithRefreshTokenOfflineTTL_AcceptsCustomValue exercises the
// happy path: a 90-day offline bucket alongside the 30-day default
// is the canonical "stay-signed-in" cadence.
func TestWithRefreshTokenOfflineTTL_AcceptsCustomValue(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithRefreshTokenOfflineTTL(90*24*time.Hour))...); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestWithStrictOfflineAccess_AcceptedAlone exercises the happy
// path. Without [op.WithOpenIDScopeOptional] the strict-mode flag
// is profile-orthogonal and constructs cleanly.
func TestWithStrictOfflineAccess_AcceptedAlone(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithStrictOfflineAccess())...); err != nil {
		t.Fatalf("op.New rejected WithStrictOfflineAccess in vanilla mode: %v", err)
	}
}

// TestWithSessionDurabilityPosture_AcceptsVolatile exercises the
// happy path for the default declaration. Embedders who do not call
// the option get [op.SessionDurabilityVolatile]; calling the option
// with the same value is an explicit no-op that constructs cleanly.
func TestWithSessionDurabilityPosture_AcceptsVolatile(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithSessionDurabilityPosture(op.SessionDurabilityVolatile),
	)...); err != nil {
		t.Fatalf("op.New rejected the volatile declaration: %v", err)
	}
}

// TestWithSessionDurabilityPosture_AcceptsDurable exercises the
// embedder-facing branch. The option records the declaration; it
// does not enforce that the configured SessionStore is actually
// durable, so op.New must accept the flag regardless of the store
// adapter the embedder wired.
func TestWithSessionDurabilityPosture_AcceptsDurable(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithSessionDurabilityPosture(op.SessionDurabilityDurable),
	)...); err != nil {
		t.Fatalf("op.New rejected the durable declaration: %v", err)
	}
}

// TestWithStrictOfflineAccess_RejectsOpenIDScopeOptional pins the
// construction-time refusal of the conflicting pair. The strict
// reading of OIDC Core 1.0 §11 has no meaning when "openid" is
// optional, so combining the two would silently disable refresh
// issuance for every non-OIDC client. The error must name both
// option identifiers so an operator reading the message sees which
// pair conflicts.
func TestWithStrictOfflineAccess_RejectsOpenIDScopeOptional(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithOpenIDScopeOptional(),
		op.WithStrictOfflineAccess(),
	)...)
	if err == nil {
		t.Fatal("expected error combining WithStrictOfflineAccess + WithOpenIDScopeOptional, got nil")
	}
	if !strings.Contains(err.Error(), "WithStrictOfflineAccess") ||
		!strings.Contains(err.Error(), "WithOpenIDScopeOptional") {
		t.Errorf("err = %v, want it to name both options", err)
	}
}

func TestWithAccessTokenTTL_FAPI2BaselineAcceptsStricter(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenTTL(2*time.Minute),
	)...)
	if err != nil {
		t.Fatalf("unexpected error for stricter-than-profile TTL: %v", err)
	}
}

func TestWithAccessTokenTTL_FAPI2MessageSigningRejectsTooLong(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2MessageSigning),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenTTL(11*time.Minute),
	)...)
	if err == nil {
		t.Fatal("expected error for TTL above FAPI2 Message Signing cap, got nil")
	}
}

func TestWithTrustedProxies_AcceptsCIDRs(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithTrustedProxies("10.0.0.0/8", "2400:cb00::/32"))...,
	); err != nil {
		t.Fatalf("WithTrustedProxies rejected valid CIDRs: %v", err)
	}
}

func TestWithTrustedProxies_RejectsInvalidCIDR(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithTrustedProxies("10.0.0.1"))...)
	if err == nil {
		t.Fatal("WithTrustedProxies accepted bare IP without prefix")
	}
}

func TestWithTrustedProxies_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithTrustedProxies())...); err == nil {
		t.Fatal("WithTrustedProxies accepted empty input")
	}
}

// TestWithTrustedProxyHosts_AcceptsHosts pins the happy path: an
// embedder running a multi-hostname OP can register additional XFH
// allowlist entries alongside the auto-derived issuer host.
func TestWithTrustedProxyHosts_AcceptsHosts(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithTrustedProxies("10.0.0.0/8"),
		op.WithTrustedProxyHosts("alt.example.com", "legacy.example.com"),
	)...); err != nil {
		t.Fatalf("WithTrustedProxyHosts rejected valid hosts: %v", err)
	}
}

// TestWithTrustedProxyHosts_RejectsEmpty pins that calling the option
// with no host argument is a configuration error — the embedder must
// supply at least one entry or omit the option entirely.
func TestWithTrustedProxyHosts_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithTrustedProxyHosts())...); err == nil {
		t.Fatal("WithTrustedProxyHosts accepted empty input")
	}
}

// TestWithTrustedProxyHosts_RejectsBlankHost pins the empty-string
// rejection: a blank host would silently widen the allowlist (host
// allowlist matching strips ports, so an empty-string entry could
// match any port-only XFH value).
func TestWithTrustedProxyHosts_RejectsBlankHost(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithTrustedProxyHosts("ok.example.com", "   "),
	)...); err == nil {
		t.Fatal("WithTrustedProxyHosts accepted a blank host")
	}
}

func TestWithCORSOrigins_AcceptsOrigins(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithCORSOrigins("https://app.example.com", "https://admin.example.com"))...,
	); err != nil {
		t.Fatalf("WithCORSOrigins rejected valid origins: %v", err)
	}
}

func TestWithCORSOrigins_RejectsInvalidOrigin(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithCORSOrigins("not-a-url"))...); err == nil {
		t.Fatal("WithCORSOrigins accepted invalid origin")
	}
}

func TestWithCORSOrigins_RejectsEmpty(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithCORSOrigins())...); err == nil {
		t.Fatal("WithCORSOrigins accepted empty input")
	}
}

func TestWithCORSOrigins_AppendsAcrossCalls(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithCORSOrigins("https://a.example.com"),
		op.WithCORSOrigins("https://b.example.com"),
	)...); err != nil {
		t.Fatalf("two WithCORSOrigins calls failed: %v", err)
	}
}

// TestStaticClientRedirectURI_AddsToCORSAllowlist pins the
// auto-derivation rule documented on [WithStaticClients]: every
// redirect_uri origin attached to a registered client is admitted by
// the CORS gate without the embedder repeating it in
// [WithCORSOrigins]. The check goes through the live
// /.well-known/openid-configuration endpoint via a CORS preflight
// from the SPA's redirect_uri origin — a 204 response with a matching
// Access-Control-Allow-Origin header proves the allowlist was widened,
// while a 403 from a sibling origin proves the widening did not turn
// into an "allow all" mistake.
func TestStaticClientRedirectURI_AddsToCORSAllowlist(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "spa",
			RedirectURIs: []string{"https://spa.example.com/callback"},
			Scopes:       []string{"openid", "profile"},
		}),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)

	cases := []struct {
		name       string
		origin     string
		wantStatus int
		wantAllow  bool
	}{
		{
			name:       "redirect_uri origin admitted",
			origin:     "https://spa.example.com",
			wantStatus: http.StatusNoContent,
			wantAllow:  true,
		},
		{
			name:       "untrusted origin rejected",
			origin:     "https://evil.example.com",
			wantStatus: http.StatusForbidden,
			wantAllow:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodOptions,
				srv.URL+"/oidc/token", http.NoBody)
			if reqErr != nil {
				t.Fatalf("NewRequest: %v", reqErr)
			}
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Access-Control-Request-Method", "POST")
			resp, doErr := srv.Client().Do(req)
			if doErr != nil {
				t.Fatalf("preflight: %v", doErr)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			gotAllow := resp.Header.Get("Access-Control-Allow-Origin")
			if tc.wantAllow {
				if gotAllow != tc.origin {
					t.Errorf("Access-Control-Allow-Origin = %q, want %q", gotAllow, tc.origin)
				}
			} else if gotAllow != "" {
				t.Errorf("Access-Control-Allow-Origin = %q, want empty", gotAllow)
			}
		})
	}
}

// TestWithScope_RejectsStandardScopeNonPublic enforces the
// construction-time guard: every OIDC standard scope MUST stay in the
// discovery document, so registering one with Public:false is a
// configuration bug surfaced at op.New rather than a silent runtime
// drift in /.well-known/openid-configuration.
func TestWithScope_RejectsStandardScopeNonPublic(t *testing.T) {
	t.Parallel()

	standard := []string{"openid", "profile", "email", "address", "phone", "offline_access"}
	for _, name := range standard {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t),
				op.WithScope(op.Scope{Name: name, Public: false}),
			)...)
			if err == nil {
				t.Fatalf("op.New must reject Public:false for standard scope %q", name)
			}
			if op.IsClientError(err) {
				t.Errorf("standard-scope misconfiguration must surface as a server error, got %v", err)
			}
		})
	}
}

// TestWithScope_AcceptsStandardScopePublic confirms that overriding a
// standard scope with explicit Public:true (typically to attach
// translations or a Title) is the supported way to customise the
// built-in entry without breaking discovery.
func TestWithScope_AcceptsStandardScopePublic(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithScope(op.Scope{
			Name:        "profile",
			Public:      true,
			Title:       "Profile",
			Description: "Read your profile information.",
		}),
	)...); err != nil {
		t.Fatalf("op.New rejected standard-scope Public:true override: %v", err)
	}
}

// TestWithScope_RejectsDuplicateName surfaces a configuration mistake
// the moment two registrations collide on the wire identifier; without
// this the second call would silently shadow the first.
func TestWithScope_RejectsDuplicateName(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithScope(op.Scope{Name: "read:projects", Public: true}),
		op.WithScope(op.Scope{Name: "read:projects", Public: true}),
	)...)
	if err == nil {
		t.Fatal("op.New must reject duplicate WithScope registrations")
	}
}

// TestWithScope_RejectsEmptyName covers the option-level guard. The
// registry's wire identifier is the contract clients build against; a
// blank Name would corrupt the registry and is rejected eagerly.
func TestWithScope_RejectsEmptyName(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithScope(op.Scope{Name: "", Public: true}),
	)...)
	if err == nil {
		t.Fatal("op.New must reject WithScope with empty Name")
	}
}

// TestWithScope_AcceptsCustomNonPublic registers a private custom scope
// (the "internal-only API" use case). Public:false is permitted on
// custom names; only standard scopes are forced public.
func TestWithScope_AcceptsCustomNonPublic(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithScope(op.Scope{Name: "internal:metrics", Public: false}),
	)...); err != nil {
		t.Fatalf("op.New rejected Public:false custom scope: %v", err)
	}
}

// TestWithScope_AcceptsCustomWithAllowedClients exercises the
// orthogonal AllowedClients axis: a public scope locked to a specific
// service client. The registration must succeed; runtime enforcement is
// validated in the authorize / token endpoint tests.
func TestWithScope_AcceptsCustomWithAllowedClients(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithScope(op.Scope{
			Name:           "billing:write",
			Public:         true,
			AllowedClients: []string{"svc-billing", "svc-admin"},
		}),
	)...); err != nil {
		t.Fatalf("op.New rejected AllowedClients-restricted scope: %v", err)
	}
}

// TestWithACRValuesSupported_OmittedByDefault confirms the discovery
// document drops acr_values_supported when WithACRValuesSupported is
// not invoked. OIDC Discovery 1.0 §3 lists the field as OPTIONAL; an
// OP that has not declared a trust framework MUST NOT advertise an
// empty list.
func TestWithACRValuesSupported_OmittedByDefault(t *testing.T) {
	t.Parallel()

	provider, err := op.New(validBaseOptsWithInmem(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	doc := fetchDiscoveryRaw(t, provider)
	if _, present := doc["acr_values_supported"]; present {
		t.Errorf("discovery document carries acr_values_supported when option is unset: %v", doc["acr_values_supported"])
	}
}

// TestWithACRValuesSupported_PublishesValuesInOrder confirms that the
// supplied acr_values are echoed onto /.well-known/openid-configuration
// in the embedder's order. The order is meaningful because trust
// frameworks rank acr values from strongest to weakest and clients
// honour the rank when picking a requested entry.
func TestWithACRValuesSupported_PublishesValuesInOrder(t *testing.T) {
	t.Parallel()

	want := []string{
		"urn:mace:incommon:iap:silver",
		"urn:mace:incommon:iap:bronze",
	}
	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithACRValuesSupported(want...),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	doc := fetchDiscoveryRaw(t, provider)
	raw, present := doc["acr_values_supported"]
	if !present {
		t.Fatalf("discovery document is missing acr_values_supported (doc=%v)", doc)
	}
	got, ok := raw.([]any)
	if !ok {
		t.Fatalf("acr_values_supported = %T, want []any", raw)
	}
	if len(got) != len(want) {
		t.Fatalf("acr_values_supported len=%d want %d (%v)", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("acr_values_supported[%d]=%v want %q", i, got[i], v)
		}
	}
}

// TestWithACRValuesSupported_AcceptsEmptyAsExplicitOptIn confirms an
// empty variadic call records the option-was-set signal but still
// drops the field via omitempty so the wire shape stays compatible
// with deployments that have not opted in.
func TestWithACRValuesSupported_AcceptsEmptyAsExplicitOptIn(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithACRValuesSupported(),
	)...)
	if err != nil {
		t.Fatalf("WithACRValuesSupported rejected empty invocation: %v", err)
	}
	doc := fetchDiscoveryRaw(t, provider)
	if _, present := doc["acr_values_supported"]; present {
		t.Errorf("empty WithACRValuesSupported still emitted acr_values_supported on the wire: %v", doc["acr_values_supported"])
	}
}

// TestWithACRValuesSupported_RejectsEmptyValue confirms an empty
// string in the value slice is rejected at construction time. OIDC
// Discovery 1.0 §3 leaves the value format open, but an empty class
// reference cannot be matched against a request and would silently
// poison every discovery response.
func TestWithACRValuesSupported_RejectsEmptyValue(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithACRValuesSupported("urn:example:high", ""),
	)...)
	if err == nil {
		t.Fatal("expected error for empty-string acr value, got nil")
	}
	if !strings.Contains(err.Error(), "empty value") {
		t.Errorf("err = %v, want empty-value diagnostic", err)
	}
}

func TestWithACRValuesSupported_RejectsDuplicateOption(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithACRValuesSupported("urn:example:high"),
		op.WithACRValuesSupported("urn:example:low"),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate WithACRValuesSupported, got nil")
	}
	var typed *op.Error
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *op.Error", err)
	}
	if typed.Code != "configuration_error" {
		t.Fatalf("op.Error.Code=%q want configuration_error", typed.Code)
	}
	if !strings.Contains(err.Error(), "supplied more than once") {
		t.Errorf("err = %v, want duplicate-option diagnostic", err)
	}
}

// TestWithJWKSHTTPTransport_RejectsNil pins the construction-time
// refusal of a nil [http.RoundTripper]. The option's contract is
// "swap the transport"; a nil value is never the embedder's intent
// and would silently leave the package-default behaviour in place,
// which would surprise an operator wiring an internal CA bundle.
func TestWithJWKSHTTPTransport_RejectsNil(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithJWKSHTTPTransport(nil))...)
	if err == nil {
		t.Fatal("expected error for nil transport, got nil")
	}
	if !strings.Contains(err.Error(), "WithJWKSHTTPTransport") {
		t.Errorf("err = %v, want it to name the option", err)
	}
}

// TestWithJWKSHTTPTransport_RejectsDouble pins the once-only contract.
// An embedder calling the option twice almost certainly has a wiring
// bug — two transports cannot both back the same fetcher — so the
// library refuses construction rather than silently keeping the
// later value.
func TestWithJWKSHTTPTransport_RejectsDouble(t *testing.T) {
	t.Parallel()

	rt := &http.Transport{}
	_, err := op.New(append(validBaseOpts(t),
		op.WithJWKSHTTPTransport(rt),
		op.WithJWKSHTTPTransport(rt),
	)...)
	if err == nil {
		t.Fatal("expected error for two WithJWKSHTTPTransport calls, got nil")
	}
	if !strings.Contains(err.Error(), "at most once") {
		t.Errorf("err = %v, want at-most-once diagnostic", err)
	}
}

// TestWithJWKSHTTPTransport_AcceptsCustom exercises the success path:
// a non-nil transport on a fresh provider constructs cleanly. The
// transport itself is exercised by the internal/jar fetcher tests;
// at the option layer we only need to confirm wiring does not
// regress.
func TestWithJWKSHTTPTransport_AcceptsCustom(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithJWKSHTTPTransport(&http.Transport{}),
	)...); err != nil {
		t.Fatalf("op.New rejected a valid WithJWKSHTTPTransport: %v", err)
	}
}

// fetchDiscoveryRaw issues a GET to /.well-known/openid-configuration
// against the provided handler and decodes the response body into a
// generic map so individual tests can probe presence / absence of
// optional fields without coupling to the Document Go type. The
// helper exists so option tests can verify the wire shape an embedder
// actually sees rather than going through the unexported config.
func fetchDiscoveryRaw(t *testing.T, handler http.Handler) map[string]any {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery status=%d want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode discovery body: %v (body=%q)", err, rec.Body.String())
	}
	return doc
}
