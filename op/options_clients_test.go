package op_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func TestWithStaticClients_AcceptsPublicSeed(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-spa",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	)...); err != nil {
		t.Fatalf("WithStaticClients rejected PublicClient seed: %v", err)
	}
}

func TestWithStaticClients_AcceptsMixedSeeds(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "demo-spa",
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			},
			op.ConfidentialClient{
				ID:           "demo-confidential",
				Secret:       "demo-secret",
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			},
			op.PrivateKeyJWTClient{
				ID:           "demo-fapi",
				JWKS:         validStaticJWKS(t),
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			},
		),
	)...); err != nil {
		t.Fatalf("WithStaticClients rejected mixed seed list: %v", err)
	}
}

func validStaticJWKS(tb testing.TB) []byte {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	raw, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key:       &key.PublicKey,
		KeyID:     "static-p256",
		Algorithm: "ES256",
		Use:       "sig",
	}}})
	if err != nil {
		tb.Fatalf("json.Marshal JWKS: %v", err)
	}
	return raw
}

func TestWithStaticClients_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithStaticClients())...)
	if err == nil {
		t.Fatal("expected error for empty seed list, got nil")
	}
	if !strings.Contains(err.Error(), "at least one ClientSeed") {
		t.Errorf("err = %v, want it to require at least one seed", err)
	}
}

func TestWithStaticClients_RejectsNilSeed(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "demo-spa",
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			},
			nil,
		),
	)...)
	if err == nil {
		t.Fatal("expected error for nil seed, got nil")
	}
	// The error description MUST carry the offending index so the
	// embedder can locate the bad entry without dichotomising the
	// list themselves.
	if !strings.Contains(err.Error(), "[1]") {
		t.Errorf("err = %v, want it to mention seed index [1]", err)
	}
}

// TestWithStaticClients_PersistsToStore verifies the H1-D seeding
// step: every ClientSeed projected through op.WithStaticClients lands
// in the configured store as a real [store.Client] record so the
// token / authorize / introspect endpoints can authenticate against
// it. Without this step the option silently degraded to a no-op.
func TestWithStaticClients_PersistsToStore(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	if _, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(st),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "demo-spa",
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			},
			op.ConfidentialClient{
				ID:           "demo-confidential",
				Secret:       "demo-secret",
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			},
		),
	); err != nil {
		t.Fatalf("op.New: %v", err)
	}

	pub, err := st.Clients().GetClient(context.Background(), "demo-spa")
	if err != nil {
		t.Fatalf("PublicClient not persisted: %v", err)
	}
	if !pub.PublicClient {
		t.Errorf("demo-spa.PublicClient = false, want true")
	}

	conf, err := st.Clients().GetClient(context.Background(), "demo-confidential")
	if err != nil {
		t.Fatalf("ConfidentialClient not persisted: %v", err)
	}
	if conf.SecretHash == "" {
		t.Errorf("demo-confidential.SecretHash is empty; ConfidentialClient.seed() must hash the secret")
	}
}

// TestWithStaticClients_RejectsReadOnlyStore confirms op.New fails
// fast when the embedder configures static clients but supplies a
// store that does not satisfy [store.ClientRegistry] — the
// configuration cannot succeed because the seeds have nowhere to
// land.
func TestWithStaticClients_RejectsReadOnlyStore(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-spa",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	)...)
	if err == nil {
		t.Fatal("expected error for read-only store, got nil")
	}
	if !strings.Contains(err.Error(), "StaticClientReconciler") {
		t.Errorf("err = %v, want it to mention StaticClientReconciler", err)
	}
}

func TestWithStaticClients_AppendsAcrossCalls(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-spa-a",
			RedirectURIs: []string{"https://a.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-spa-b",
			RedirectURIs: []string{"https://b.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	)...); err != nil {
		t.Fatalf("WithStaticClients rejected layered calls: %v", err)
	}
}

// TestWithStaticClients_ConfidentialEmptySecret pins the H1-C contract:
// [op.ConfidentialClient.seed] currently does NOT reject an empty
// Secret because [op.HashClientSecret] hashes empty strings without
// error. The test documents the current behaviour so a future H1-C
// change that adds an empty-Secret guard surfaces here as a loud
// regression rather than a silent behaviour drift; once the guard
// lands, flip the assertion to expect an error and propagate the
// "WithStaticClients[i]:" index prefix from the option site.
func TestWithStaticClients_ConfidentialEmptySecret(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithStaticClients(op.ConfidentialClient{
			ID:           "demo-empty-secret",
			Secret:       "",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	)...)
	// Today: empty Secret hashes successfully, so op.New accepts the
	// configuration. If a future revision rejects the empty Secret at
	// the seed() boundary, the option site MUST prepend
	// "WithStaticClients[0]: " so the embedder can locate the entry.
	if err == nil {
		return
	}
	if !strings.Contains(err.Error(), "WithStaticClients[0]") {
		t.Errorf("seed error must surface with index prefix, got %v", err)
	}
}

// TestWithStaticClients_RejectsBadRedirectURI pins the construction-
// time refusal of an http:// redirect_uri on a non-loopback host. The
// validator shares its rule set with DCR's /register handler, so a
// static seed and a dynamically registered client see the same shape
// of error (the wire code lives on the wrapped
// [registrationendpoint.StaticClientValidationError]).
func TestWithStaticClients_RejectsBadRedirectURI(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-spa",
			RedirectURIs: []string{"http://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	)...)
	if err == nil {
		t.Fatal("expected configuration error for plaintext redirect_uri, got nil")
	}
	if !op.IsServerError(err) {
		t.Errorf("err = %v, want server-class configuration error", err)
	}
	if !strings.Contains(err.Error(), "WithStaticClients[0]") {
		t.Errorf("err = %v, want it to carry the seed index", err)
	}
	if !strings.Contains(err.Error(), "demo-spa") {
		t.Errorf("err = %v, want it to mention the offending client_id", err)
	}
}

// TestWithStaticClients_RejectsBadBackchannelLogoutURI pins the
// construction-time refusal of a non-https backchannel_logout_uri. The
// rule mirrors the DCR validator so an embedder cannot persist a
// plaintext logout endpoint via WithStaticClients that the /register
// handler would refuse.
func TestWithStaticClients_RejectsBadBackchannelLogoutURI(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithStaticClients(op.PublicClient{
			ID:                   "demo-spa",
			RedirectURIs:         []string{"https://app.example.com/cb"},
			Scopes:               []string{"openid"},
			BackchannelLogoutURI: "http://rp.example.com/logout",
		}),
	)...)
	if err == nil {
		t.Fatal("expected configuration error for plaintext backchannel_logout_uri, got nil")
	}
	if !strings.Contains(err.Error(), "backchannel_logout_uri") {
		t.Errorf("err = %v, want it to mention the offending field", err)
	}
}

func TestWithStaticClients_FAPIRejectsSecretAuthSeed(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithStaticClients(op.ConfidentialClient{
			ID:           "fapi-secret-client",
			Secret:       "demo-secret",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	)...)
	if err == nil {
		t.Fatal("expected FAPI profile to reject client_secret_basic static client, got nil")
	}
	if !strings.Contains(err.Error(), "token_endpoint_auth_method client_secret_basic is not allowed by active profile") {
		t.Errorf("err = %v, want profile auth-method diagnostic", err)
	}
}

// TestWithStaticClients_FAPIRejectsMTLSAuthSeed pins that a FAPI static
// client declaring an mTLS token-endpoint auth method (tls_client_auth /
// self_signed_tls_client_auth) is rejected at construction. The runtime
// client-auth verifier handles only none / client_secret_basic /
// client_secret_post / private_key_jwt, so accepting an mTLS seed would
// produce a client that boots clean yet can never authenticate at /token.
// op.New must fail fast rather than admit that dead-on-arrival seed.
func TestWithStaticClients_FAPIRejectsMTLSAuthSeed(t *testing.T) {
	t.Parallel()

	for _, method := range []op.AuthMethod{op.AuthTLSClientAuth, op.AuthSelfSignedTLSClientAuth} {
		t.Run(string(method), func(t *testing.T) {
			t.Parallel()

			_, err := op.New(append(validBaseOptsWithInmem(t),
				op.WithProfile(profile.FAPI2Baseline),
				op.WithStaticClients(op.ConfidentialClient{
					ID:           "fapi-mtls-client",
					AuthMethod:   method,
					RedirectURIs: []string{"https://app.example.com/cb"},
					Scopes:       []string{"openid"},
				}),
			)...)
			if err == nil {
				t.Fatalf("expected FAPI profile to reject %s static client (runtime cannot enforce mTLS), got nil", method)
			}
			// The seed must be rejected because the runtime cannot enforce
			// the method. The diagnostic references the method name; the
			// exact wording ("not supported" from the global validator, or
			// "not allowed by active profile" from the profile gate) is an
			// implementation detail of which layer fires first.
			if !strings.Contains(err.Error(), "token_endpoint_auth_method "+string(method)) {
				t.Errorf("err = %v, want token_endpoint_auth_method diagnostic for %s", err, method)
			}
		})
	}
}

// TestWithStaticClients_AcceptsHTTPLoopbackBackchannelWithDevOptIn
// pins the dev / CI carve-out introduced by
// [op.WithAllowInsecureBackchannelLogoutForDev]: a static seed
// carrying a plain-http loopback `backchannel_logout_uri` constructs
// successfully when the option is configured, while production
// posture (option absent) keeps rejecting the same URL.
func TestWithStaticClients_AcceptsHTTPLoopbackBackchannelWithDevOptIn(t *testing.T) {
	t.Parallel()

	loopbackHosts := []string{
		"http://127.0.0.1:9090/backchannel-logout",
		"http://[::1]:9090/backchannel-logout",
		"http://localhost:9090/backchannel-logout",
	}
	for _, raw := range loopbackHosts {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			// Without the opt-in the URL is rejected.
			_, err := op.New(append(validBaseOptsWithInmem(t),
				op.WithStaticClients(op.ConfidentialClient{
					ID:                   "demo-rp",
					Secret:               "rotate-me",
					AuthMethod:           op.AuthClientSecretBasic,
					RedirectURIs:         []string{"https://rp.example.com/cb"},
					Scopes:               []string{"openid"},
					BackchannelLogoutURI: raw,
				}),
			)...)
			if err == nil {
				t.Fatal("expected configuration error for plaintext backchannel_logout_uri without opt-in, got nil")
			}

			// With the opt-in the URL is accepted.
			_, err = op.New(append(validBaseOptsWithInmem(t),
				op.WithAllowInsecureBackchannelLogoutForDev(),
				op.WithStaticClients(op.ConfidentialClient{
					ID:                   "demo-rp",
					Secret:               "rotate-me",
					AuthMethod:           op.AuthClientSecretBasic,
					RedirectURIs:         []string{"https://rp.example.com/cb"},
					Scopes:               []string{"openid"},
					BackchannelLogoutURI: raw,
				}),
			)...)
			if err != nil {
				t.Fatalf("WithAllowInsecureBackchannelLogoutForDev rejected loopback %q: %v", raw, err)
			}
		})
	}
}

// TestWithStaticClients_RejectsHTTPNonLoopbackBackchannelEvenWithDevOptIn
// pins the upper bound of the dev opt-out: it admits plain-http only
// for the loopback identities (127.0.0.1, [::1], localhost). A public
// host over plain http is still refused so a misconfiguration cannot
// turn the dev convenience into a production-time mistake.
func TestWithStaticClients_RejectsHTTPNonLoopbackBackchannelEvenWithDevOptIn(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithAllowInsecureBackchannelLogoutForDev(),
		op.WithStaticClients(op.ConfidentialClient{
			ID:                   "demo-rp",
			Secret:               "rotate-me",
			AuthMethod:           op.AuthClientSecretBasic,
			RedirectURIs:         []string{"https://rp.example.com/cb"},
			Scopes:               []string{"openid"},
			BackchannelLogoutURI: "http://rp.example.com/logout",
		}),
	)...)
	if err == nil {
		t.Fatal("expected configuration error for plaintext non-loopback backchannel_logout_uri, got nil")
	}
	if !strings.Contains(err.Error(), "backchannel_logout_uri") {
		t.Errorf("err = %v, want it to mention the offending field", err)
	}
}

// TestWithStaticClients_RejectsUnknownGrantType pins the construction-
// time refusal of a grant_type that falls outside the configured
// AllowedGrantTypes whitelist. The validator inherits the whitelist
// from the DCR configuration when [WithDynamicRegistration] is set;
// otherwise it falls back to the library default
// {"authorization_code", "refresh_token"}.
func TestWithStaticClients_RejectsUnknownGrantType(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-spa",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
			GrantTypes:   []string{"password"},
		}),
	)...)
	if err == nil {
		t.Fatal("expected configuration error for unknown grant_type, got nil")
	}
	if !strings.Contains(err.Error(), "grant_type") {
		t.Errorf("err = %v, want it to mention grant_type", err)
	}
}

// TestWithStaticClients_RejectsBackchannelSessionRequired pins the
// construction-time refusal of a client that requests session-bound
// logout. Supplying a delivery URI does not make the request safe:
// the provider cannot recover an RP-specific SID from the current
// grant model.
func TestWithStaticClients_RejectsBackchannelSessionRequired(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithStaticClients(op.PublicClient{
			ID:                               "demo-spa",
			RedirectURIs:                     []string{"https://app.example.com/cb"},
			Scopes:                           []string{"openid"},
			BackchannelLogoutURI:             "https://app.example.com/logout",
			BackchannelLogoutSessionRequired: true,
		}),
	)...)
	if err == nil {
		t.Fatal("expected configuration error for unsupported session_required, got nil")
	}
	if !strings.Contains(err.Error(), "backchannel_logout") {
		t.Errorf("err = %v, want it to mention the offending field", err)
	}
}

// TestWithStaticClients_AcceptsLoopbackWithOptIn confirms that the
// textual "http://localhost" host is admitted when the embedder opted
// in via [op.WithAllowLocalhostLoopback]. Without the option the URI
// would be rejected because RFC 8252 §7.3 only carves out IP literals
// (127.0.0.1 / [::1]) by default.
func TestWithStaticClients_AcceptsLoopbackWithOptIn(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithAllowLocalhostLoopback(),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-native",
			RedirectURIs: []string{"http://localhost:8080/cb"},
			Scopes:       []string{"openid"},
		}),
	)...); err != nil {
		t.Fatalf("WithStaticClients rejected http://localhost under WithAllowLocalhostLoopback: %v", err)
	}
}

// TestWithStaticClients_AcceptsLoopbackIPLiteral confirms that the
// IP-literal loopback redirect_uri (127.0.0.1) is admitted without
// the explicit opt-in: RFC 8252 §7.3 reserves the carve-out for IP
// literals so the OP accepts the URI by default.
func TestWithStaticClients_AcceptsLoopbackIPLiteral(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-native",
			RedirectURIs: []string{"http://127.0.0.1:8080/cb"},
			Scopes:       []string{"openid"},
		}),
	)...); err != nil {
		t.Fatalf("WithStaticClients rejected http://127.0.0.1 redirect_uri: %v", err)
	}
}

func TestWithFirstPartyClients_RejectsUnknownID(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "known",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
		op.WithFirstPartyClients("unknown"),
	)...)
	if err == nil {
		t.Fatal("expected error for unknown first-party client_id, got nil")
	}
	if !strings.Contains(err.Error(), "unknown client_id unknown") {
		t.Errorf("err = %v, want it to mention the unknown id", err)
	}
}

func TestWithFirstPartyClients_AcceptsKnownID(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "first-party-spa",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
		op.WithFirstPartyClients("first-party-spa"),
	)...); err != nil {
		t.Fatalf("WithFirstPartyClients rejected known id: %v", err)
	}
}

func TestWithFirstPartyClients_RejectsDuplicateInCall(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithStaticClients(op.PublicClient{
			ID:           "x",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
		op.WithFirstPartyClients("x", "x"),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate id within a single call, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate client_id") {
		t.Errorf("err = %v, want duplicate-id diagnostic", err)
	}
}

func TestWithFirstPartyClients_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithFirstPartyClients())...)
	if err == nil {
		t.Fatal("expected error for empty id list, got nil")
	}
}

func TestWithFirstPartyClients_RejectsFAPI2Profile(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithStaticClients(op.PublicClient{
			ID:           "fp-client",
			RedirectURIs: []string{"https://app.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
		op.WithFirstPartyClients("fp-client"),
	)...)
	if err == nil {
		t.Fatal("expected error combining WithFirstPartyClients with FAPI 2.0 profile, got nil")
	}
	if !strings.Contains(err.Error(), "FAPI 2.0") {
		t.Errorf("err = %v, want it to mention FAPI 2.0", err)
	}
}

// TestWithOpenIDScopeOptional_RejectsFAPI2Profile pins the construction-
// time refusal of [op.WithOpenIDScopeOptional] under any FAPI 2.0
// profile. Both Baseline and Message Signing presuppose OIDC
// semantics (id_token-bound state-or-nonce, scope-driven refresh
// gating); the option's "no openid required" relaxation is
// fundamentally incompatible. The error must mention "FAPI 2.0" so
// the operator sees the conflict at a glance instead of a generic
// "configuration" diagnostic.
func TestWithOpenIDScopeOptional_RejectsFAPI2Profile(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithOpenIDScopeOptional(),
	)...)
	if err == nil {
		t.Fatal("expected error combining WithOpenIDScopeOptional with FAPI 2.0 profile, got nil")
	}
	if !strings.Contains(err.Error(), "FAPI 2.0") {
		t.Errorf("err = %v, want it to mention FAPI 2.0", err)
	}
}

// TestWithOpenIDScopeOptional_AcceptedWithoutFAPI2 confirms the
// option constructs cleanly when no FAPI 2.0 profile is active. The
// happy-path build is the prerequisite for the end-to-end token
// endpoint test that drives the plain-OAuth flow; if op.New refuses
// the option in vanilla OIDC mode the rest of the test surface is
// untestable.
func TestWithOpenIDScopeOptional_AcceptedWithoutFAPI2(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithOpenIDScopeOptional(),
	)...); err != nil {
		t.Fatalf("op.New rejected WithOpenIDScopeOptional in vanilla mode: %v", err)
	}
}

func TestWithClaimsSupported_AcceptsList(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithClaimsSupported("sub", "iss", "aud", "exp", "iat"),
	)...); err != nil {
		t.Fatalf("WithClaimsSupported rejected valid list: %v", err)
	}
}

func TestWithClaimsSupported_AcceptsEmptyAsExplicitOptIn(t *testing.T) {
	t.Parallel()

	// An explicit empty list signals "embedder confirms no extra
	// claims beyond defaults"; the option accepts it (the discovery
	// builder still drops the field via omitempty so the wire shape
	// is unchanged, but the option-was-set signal is preserved).
	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithClaimsSupported(),
	)...); err != nil {
		t.Fatalf("WithClaimsSupported rejected empty list: %v", err)
	}
}

func TestWithClaimsSupported_RejectsDuplicateInvocation(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithClaimsSupported("sub"),
		op.WithClaimsSupported("email"),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate WithClaimsSupported invocation, got nil")
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Errorf("err = %v, want duplicate-invocation diagnostic", err)
	}
}
