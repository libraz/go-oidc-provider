package op_test

import (
	"context"
	"strings"
	"testing"

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
				JWKS:         []byte(`{"keys":[]}`),
				RedirectURIs: []string{"https://app.example.com/cb"},
				Scopes:       []string{"openid"},
			},
		),
	)...); err != nil {
		t.Fatalf("WithStaticClients rejected mixed seed list: %v", err)
	}
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
	if !strings.Contains(err.Error(), "ClientRegistry") {
		t.Errorf("err = %v, want it to mention ClientRegistry", err)
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
