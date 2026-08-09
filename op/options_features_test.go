package op_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/profile"
)

func TestWithGrants_RequiresAtLeastOne(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithGrants())...)
	if err == nil {
		t.Fatal("expected error for empty grants, got nil")
	}
}

func TestWithGrants_RejectsUnknown(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithGrants(grant.Type(0)))...)
	if err == nil {
		t.Fatal("expected error for zero-value grant, got nil")
	}
}

func TestWithGrants_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithGrants(grant.AuthorizationCode, grant.AuthorizationCode),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate grant, got nil")
	}
}

// TestWithGrants_RejectsSecondCall pins #26: a second WithGrants must
// error rather than silently replacing the first set, so a caller that
// composes option slices from several helpers cannot lose an earlier
// grant set under a later one.
func TestWithGrants_RejectsSecondCall(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithGrants(grant.AuthorizationCode, grant.RefreshToken),
		op.WithGrants(grant.AuthorizationCode),
	)...)
	if err == nil {
		t.Fatal("expected error for a second WithGrants call, got nil")
	}
	if !strings.Contains(err.Error(), "at most once") {
		t.Errorf("err = %v, want it to mention 'at most once'", err)
	}
}

func TestWithFeature_DuplicateIsIdempotent(t *testing.T) {
	t.Parallel()

	// WithFeature for an already-enabled flag is a silent no-op so
	// the `WithProfile(FAPI2Baseline) + WithFeature(feature.PAR)` pattern
	// composes regardless of call order. The pre-idempotence behaviour
	// (duplicate-rejection) lived in the v0 surface; this test pins
	// the new contract.
	if _, err := op.New(append(validBaseOpts(t),
		op.WithFeature(feature.PAR), op.WithFeature(feature.PAR),
	)...); err != nil {
		t.Fatalf("expected nil error for duplicate WithFeature, got %v", err)
	}
}

func TestWithFeature_RejectsZeroValue(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithFeature(feature.Flag(0)))...)
	if err == nil {
		t.Fatal("expected error for zero-value flag, got nil")
	}
}

func TestWithProfile_RejectsDuplicate(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithProfile(profile.FAPI2Baseline), op.WithProfile(profile.FAPI2Baseline),
	)...)
	if err == nil {
		t.Fatal("expected error for duplicate profile, got nil")
	}
}

// TestWithProfile_RejectsUnrecognisedValue pins that a profile value
// outside the exported constants cannot boot. [profile.Profile] is a
// uint8, so nothing stops a caller from handing op.New an arbitrary
// number; every constraint predicate answers such a value with its
// permissive arm, so the provider would come up enforcing none of the
// profile's MUST clauses while the configuration reads as though a
// profile were active. The zero value is included because an
// uninitialised struct field is the way this arrives in practice.
func TestWithProfile_RejectsUnrecognisedValue(t *testing.T) {
	t.Parallel()

	for _, p := range []profile.Profile{profile.Profile(0), profile.Profile(99), profile.Profile(200)} {
		_, err := op.New(append(validBaseOpts(t),
			op.WithProfile(p),
		)...)
		if err == nil {
			t.Fatalf("op.New accepted profile value %d", uint8(p))
		}
		if !strings.Contains(err.Error(), "unknown profile") {
			t.Errorf("profile %d: err = %v, want an unknown-profile diagnostic", uint8(p), err)
		}
	}
}

// TestValidateProfile_NoFalsePositiveWithoutProfile pins the
// contrapositive of the add-only invariant: when no profile is
// active the validator MUST NOT demand any profile-required flag be
// present. Features may be added without a matching profile (the
// "stricter-than-default" posture documented on validateProfiles).
func TestValidateProfile_NoFalsePositiveWithoutProfile(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithFeature(feature.PAR),
	)...); err != nil {
		t.Fatalf("WithFeature(PAR) without WithProfile failed: %v", err)
	}
}

// TestValidateProfile_RejectsMissingRequiredFeature pins the
// add-only invariant directly through the unexported validate path:
// a profile whose conjunctive required features are absent from
// c.features MUST be rejected with a configuration error that names
// the missing flag. The public option surface gives no way to drop
// an auto-enabled feature, so we exercise the validator through
// [validateConfigForTest] which builds a config without running the
// WithProfile auto-enable loop. A regression that removed the
// validator's add-only check (relying on auto-enable alone) would
// let this fall through and fail.
func TestValidateProfile_RejectsMissingRequiredFeature(t *testing.T) {
	t.Parallel()

	required := profile.RequiredFeatures(profile.FAPI2Baseline)
	if len(required) == 0 {
		t.Skip("FAPI2Baseline declares no required features; nothing to assert")
	}
	err := op.ValidateProfileFeatureSetForTest(profile.FAPI2Baseline, []feature.Flag{feature.DPoP})
	if err == nil {
		t.Fatal("expected configuration error when required features are missing, got nil")
	}
	if !op.IsServerError(err) {
		t.Errorf("missing required feature must surface as server-side configuration error: %v", err)
	}
	// The error description must call out the first missing flag so
	// an operator can locate the misconfiguration.
	missing := required[0]
	if !strings.Contains(err.Error(), missing.String()) {
		t.Errorf("err description %q must mention missing flag %q", err, missing)
	}
}

// TestWithProfile_FAPI2Baseline_AutoEnablesRequiredFeatures confirms
// the profile auto-enable contract: an embedder calling
// [op.WithProfile(profile.FAPI2Baseline)] without explicit
// [op.WithFeature] calls for PAR and JAR still constructs
// successfully because both flags are auto-enabled. The disjunctive
// DPoP/MTLS requirement still has to be supplied manually.
func TestWithProfile_FAPI2Baseline_AutoEnablesRequiredFeatures(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)...)
	if err != nil {
		t.Fatalf("WithProfile auto-enable did not satisfy PAR/JAR: %v", err)
	}
}

func TestWithProfile_FAPI2Baseline_AutoEnablesDPoPDefault(t *testing.T) {
	t.Parallel()

	// PAR / JAR are auto-enabled via [profile.RequiredFeatures]; the
	// disjunctive DPoP/MTLS requirement (profile.RequiredAnyOf) is
	// satisfied by [config.applyProfileAnyOfDefaults] auto-enabling the
	// first member (DPoP) when the embedder did not pick MTLS. The
	// wired DPoP path needs the inmem substores [stubStore] panics on,
	// so the test uses [validBaseOptsWithInmem].
	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
	)...)
	if err != nil {
		t.Fatalf("WithProfile(FAPI2Baseline) alone must succeed via DPoP auto-enable: %v", err)
	}
}

// TestWithProfile_FAPI2Baseline_ExplicitMTLSSuppressesDPoPDefault
// confirms that an embedder who picks mTLS as the sender-binding
// mechanism does not also have DPoP silently auto-enabled. The
// auto-enable in [config.applyProfileAnyOfDefaults] only fires when
// no member of the disjunctive set is already configured; with
// MTLS in the feature list the AnyOf is already satisfied. The
// observation surface here is the OP discovery document — a config
// where DPoP was auto-defaulted advertises
// dpop_signing_alg_values_supported, while a config where mTLS
// owns the sender binding does not.
//
// The order of options is intentionally varied: the test asserts
// that whether [WithFeature](MTLS) precedes or follows
// [WithProfile], the result is the same — DPoP advertisement stays
// absent, mTLS-bound-tokens advertisement stays present.
func TestWithProfile_FAPI2Baseline_ExplicitMTLSSuppressesDPoPDefault(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opts []op.Option
	}{
		{
			name: "mtls-then-profile",
			opts: []op.Option{
				op.WithFeature(feature.MTLS),
				op.WithProfile(profile.FAPI2Baseline),
			},
		},
		{
			name: "profile-then-mtls",
			opts: []op.Option{
				op.WithProfile(profile.FAPI2Baseline),
				op.WithFeature(feature.MTLS),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			provider, err := op.New(append(validBaseOptsWithInmem(t), tc.opts...)...)
			if err != nil {
				t.Fatalf("op.New failed: %v", err)
			}
			srv := httptest.NewServer(provider)
			t.Cleanup(srv.Close)
			req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet,
				srv.URL+"/.well-known/openid-configuration", http.NoBody)
			if reqErr != nil {
				t.Fatalf("NewRequest: %v", reqErr)
			}
			resp, doErr := srv.Client().Do(req)
			if doErr != nil {
				t.Fatalf("GET discovery: %v", doErr)
			}
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				t.Fatalf("read body: %v", readErr)
			}
			doc := string(body)
			if strings.Contains(doc, "dpop_signing_alg_values_supported") {
				t.Errorf("discovery advertises DPoP support but the embedder picked MTLS only:\n%s", doc)
			}
			if !strings.Contains(doc, "tls_client_certificate_bound_access_tokens") {
				t.Errorf("discovery does not advertise mTLS sender binding:\n%s", doc)
			}
		})
	}
}

func TestWithProfile_FAPI2Baseline_AcceptsDPoP(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithProfile_FAPI2Baseline_AcceptsMTLS(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.MTLS),
	)...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestWithProfile_FAPI2MessageSigning_AutoEnablesJARM confirms the
// auto-enable contract extends to the Message Signing requirement
// set (JARM is added to RequiredFeatures alongside PAR / JAR). The
// embedder only needs to supply the disjunctive DPoP/MTLS choice and,
// when DPoP is the chosen sender constraint, the RFC 9449 §8 / §9
// nonce source FAPI 2.0 §5.3.4 mandates.
func TestWithProfile_FAPI2MessageSigning_AutoEnablesJARM(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2MessageSigning),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(stubDPoPNonceSource{}),
	)...)
	if err != nil {
		t.Fatalf("WithProfile auto-enable did not satisfy JARM requirement: %v", err)
	}
}

func TestWithProfile_FAPI2MessageSigning_AcceptsFullStack(t *testing.T) {
	t.Parallel()

	// PAR / JAR / JARM are auto-enabled by [op.WithProfile]; the
	// disjunctive DPoP/MTLS requirement plus the FAPI 2.0 Message
	// Signing nonce source are the only flags the embedder must supply.
	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2MessageSigning),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(stubDPoPNonceSource{}),
	)...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestWithProfile_FAPI_JARVerifierConstructs pins that op.New under
// any FAPI-family profile constructs a working JAR verifier. The
// verifier admits jti-less request objects per RFC 9101 §6.1
// (jti is OPTIONAL on the wire); the §10.8 replay-defence floor is
// preserved through the JTIs store, which the verifier still consumes
// for every jti it does see. The construction path is exercised
// through every FAPI profile that admits JAR (FAPI 2.0 Baseline
// auto-enables JAR; FAPI 2.0 Message Signing inherits the same
// auto-enable; FAPI-CIBA also auto-enables JAR through its
// RequiredFeatures table).
func TestWithProfile_FAPI_JARVerifierConstructs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opts []op.Option
	}{
		{
			name: "FAPI2Baseline",
			opts: []op.Option{
				op.WithProfile(profile.FAPI2Baseline),
				op.WithFeature(feature.DPoP),
			},
		},
		{
			name: "FAPI2MessageSigning",
			opts: []op.Option{
				op.WithProfile(profile.FAPI2MessageSigning),
				op.WithFeature(feature.DPoP),
				op.WithDPoPNonceSource(stubDPoPNonceSource{}),
			},
		},
		{
			name: "FAPICIBA",
			opts: []op.Option{
				op.WithCIBA(op.WithCIBAHintResolver(stubCIBAHintResolver{})),
				op.WithProfile(profile.FAPICIBA),
				op.WithFeature(feature.DPoP),
				op.WithDPoPNonceSource(stubDPoPNonceSource{}),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOptsWithInmem(t), tc.opts...)...)
			if err != nil {
				t.Fatalf("expected nil error wiring %s with JAR auto-enabled, got %v", tc.name, err)
			}
		})
	}
}

// TestWithProfile_FAPI2MessageSigning_RequiresDPoPNonceSource confirms
// the FAPI 2.0 §5.3.4 mandate: when the profile is active and DPoP is
// the chosen sender constraint, the embedder MUST supply a nonce
// source. Omitting it produces a configuration error at op.New time
// rather than a silent runtime degradation.
func TestWithProfile_FAPI2MessageSigning_RequiresDPoPNonceSource(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2MessageSigning),
		op.WithFeature(feature.DPoP),
	)...)
	if err == nil {
		t.Fatal("expected configuration error when DPoP nonce source is omitted, got nil")
	}
	if !strings.Contains(err.Error(), "WithDPoPNonceSource") {
		t.Errorf("err = %v, want it to mention WithDPoPNonceSource", err)
	}
}

// stubDPoPNonceSource is a minimal [DPoPNonceSource] used by tests
// that need to satisfy the FAPI 2.0 Message Signing nonce mandate
// without exercising the runtime nonce flow. It always issues "n"
// and accepts any non-empty value.
type stubDPoPNonceSource struct{}

func (stubDPoPNonceSource) IssueNonce() string         { return "n" }
func (stubDPoPNonceSource) Validate(nonce string) bool { return nonce != "" }

func TestWithProfile_FAPI2_StampsInteractionIDHeader(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration", http.NoBody)
	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, req)
	got := rec.Header().Get("x-fapi-interaction-id")
	if got == "" {
		t.Errorf("response x-fapi-interaction-id missing under FAPI2Baseline profile")
	}
}

func TestWithProfile_FAPI2_EchoesClientInteractionID(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	want := "0123abcd-4567-89ef-0123-456789abcdef"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration", http.NoBody)
	req.Header.Set("x-fapi-interaction-id", want)
	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, req)
	if got := rec.Header().Get("x-fapi-interaction-id"); got != want {
		t.Errorf("response x-fapi-interaction-id = %q, want %q (must echo client value)", got, want)
	}
}

func TestNoProfile_DoesNotStampInteractionIDHeader(t *testing.T) {
	t.Parallel()

	// Without any profile, the FAPI middleware MUST be off — otherwise
	// every OP would advertise FAPI 2.0 §6 compliance the embedder
	// did not opt into.
	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration", http.NoBody)
	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, req)
	if got := rec.Header().Get("x-fapi-interaction-id"); got != "" {
		t.Errorf("non-profile OP stamped x-fapi-interaction-id = %q, want absent", got)
	}
}

func TestWithProfile_AutoEnablesRequiredFeatures(t *testing.T) {
	t.Parallel()

	// FAPI2Baseline requires PAR + JAR per profile.RequiredFeatures.
	// With H1-E auto-enable in WithProfile the embedder no longer
	// needs explicit WithFeature(PAR) / WithFeature(JAR) calls; only
	// the disjunctive sender-constrained-token requirement (DPoP OR
	// MTLS) still has to be supplied manually because it lives on
	// RequiredAnyOf.
	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)...); err != nil {
		t.Fatalf("WithProfile auto-enable failed: %v", err)
	}
}

func TestWithProfile_AutoEnableSilentlySkipsExisting(t *testing.T) {
	t.Parallel()

	// Embedders are allowed to layer WithFeature before WithProfile.
	// The auto-enable contract is "silently skip", not "fail loudly":
	// a profile that requires PAR must accept a config that already
	// has WithFeature(PAR).
	if _, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithFeature(feature.PAR),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)...); err != nil {
		t.Fatalf("WithProfile auto-enable rejected pre-enabled feature: %v", err)
	}
}

// TestWithProfile_FAPICIBA_AutoEnablesJAR_RequiresSenderConstraint
// pins the FAPI-CIBA build-time validation contract:
//
//   - WithProfile(FAPICIBA) auto-enables JAR (RequiredFeatures);
//   - the disjunctive DPoP / MTLS sender-constraint requirement
//     ([profile.RequiredAnyOf]) is satisfied by the auto-enable
//     default (DPoP) when neither flag is supplied — but FAPICIBA
//     also forces a [WithDPoPNonceSource], so a nonce-less call still
//     fails with a config error pointing at that missing wiring;
//   - either explicit DPoP (with nonce source) or explicit MTLS
//     satisfies the disjunctive gate without further objections.
//
// FAPI-CIBA does NOT auto-enable PAR (CIBA does not flow through
// /authorize). The disjunctive sender-constrained requirement is
// auto-defaulted to DPoP via [config.applyProfileAnyOfDefaults]; an
// embedder picking MTLS instead opts in via [WithFeature](MTLS) and
// the default steps aside.
func TestWithProfile_FAPICIBA_AutoEnablesJAR_RequiresSenderConstraint(t *testing.T) {
	t.Parallel()

	// WithCIBA appends grant.CIBA to the configured grant set
	// idempotently, so a separate WithGrants call is unnecessary; the
	// shared option set keeps the per-subtest body terse.
	cibaCommon := func() []op.Option {
		return []op.Option{
			op.WithCIBA(op.WithCIBAHintResolver(stubCIBAHintResolver{})),
		}
	}

	t.Run("auto-default-still-needs-nonce-source", func(t *testing.T) {
		t.Parallel()
		opts := append(validBaseOptsWithInmem(t), cibaCommon()...)
		opts = append(opts, op.WithProfile(profile.FAPICIBA))
		_, err := op.New(opts...)
		if err == nil {
			t.Fatal("expected error when DPoP is auto-enabled without WithDPoPNonceSource, got nil")
		}
		// DPoP is auto-defaulted (sender-constraint AnyOf satisfied),
		// so the validator now points at the FAPI 2.0 §5.3.4 nonce
		// source FAPI-CIBA inherits — the resulting error message
		// names WithDPoPNonceSource rather than dpop/mtls.
		if !strings.Contains(err.Error(), "WithDPoPNonceSource") {
			t.Errorf("err = %v, want it to mention WithDPoPNonceSource", err)
		}
	})

	t.Run("dpop-satisfies-sender-constraint", func(t *testing.T) {
		t.Parallel()
		opts := append(validBaseOptsWithInmem(t), cibaCommon()...)
		opts = append(opts,
			op.WithProfile(profile.FAPICIBA),
			op.WithFeature(feature.DPoP),
			op.WithDPoPNonceSource(stubDPoPNonceSource{}),
		)
		if _, err := op.New(opts...); err != nil {
			t.Fatalf("WithProfile(FAPICIBA) + DPoP failed: %v", err)
		}
	})

	t.Run("mtls-satisfies-sender-constraint", func(t *testing.T) {
		t.Parallel()
		opts := append(validBaseOptsWithInmem(t), cibaCommon()...)
		opts = append(opts,
			op.WithProfile(profile.FAPICIBA),
			op.WithFeature(feature.MTLS),
		)
		if _, err := op.New(opts...); err != nil {
			t.Fatalf("WithProfile(FAPICIBA) + MTLS failed: %v", err)
		}
	})
}

// TestWithProfile_FAPICIBA_RequiresDPoPNonceSource confirms that
// FAPI-CIBA inherits the FAPI 2.0 §5.3.4 mandate: when the profile
// is active and DPoP is the chosen sender constraint, the embedder
// MUST supply a nonce source. Omitting it produces a configuration
// error at op.New time rather than a silent runtime degradation.
func TestWithProfile_FAPICIBA_RequiresDPoPNonceSource(t *testing.T) {
	t.Parallel()

	opts := append(validBaseOptsWithInmem(t),
		op.WithCIBA(op.WithCIBAHintResolver(stubCIBAHintResolver{})),
		op.WithProfile(profile.FAPICIBA),
		op.WithFeature(feature.DPoP),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("expected configuration error when DPoP nonce source is omitted, got nil")
	}
	if !strings.Contains(err.Error(), "WithDPoPNonceSource") {
		t.Errorf("err = %v, want it to mention WithDPoPNonceSource", err)
	}
}

// stubCIBAHintResolver is a minimal [op.HintResolver] used by tests
// that need to satisfy [op.WithCIBA]'s resolver-presence invariant
// without exercising the runtime hint-resolution flow.
type stubCIBAHintResolver struct{}

func (stubCIBAHintResolver) Resolve(_ context.Context, _ op.HintKind, _ string) (string, error) {
	return "user-stub", nil
}

// TestWithAccessTokenFormatPerAudience_RejectsCanonicalCollision
// confirms that two map keys whose canonical forms collide (one
// mixed-case, one trailing-slash, both reducing to the same canonical
// audience) fail [op.New]. The collision is a configuration mistake
// the embedder must see at startup rather than the wire layer
// silently picking whichever entry hashed first. The two values are
// both JWT so the test does not also require an OpaqueAccessTokens
// substore wired into the stub store.
//
// The remaining option-site coverage (canonicalisable keys accepted,
// fragment / userinfo / relative-URI keys rejected, empty-map and
// empty-key gates, per-audience-wins-over-global lookup) lives in
// access_token_format_test.go alongside the rest of the access-token-
// format option suite.
func TestWithAccessTokenFormatPerAudience_RejectsCanonicalCollision(t *testing.T) {
	t.Parallel()

	keys := map[string]op.AccessTokenFormat{
		"https://api.example.com/orders":  op.AccessTokenFormatJWT,
		"https://API.Example.COM/orders/": op.AccessTokenFormatJWT,
	}
	_, err := op.New(append(validBaseOpts(t),
		op.WithAccessTokenFormatPerAudience(keys),
	)...)
	if err == nil {
		t.Fatal("expected configuration error for canonical-form collision, got nil")
	}
	if !strings.Contains(err.Error(), "canonicalise") {
		t.Errorf("err = %v, want it to mention canonical-form collision", err)
	}
}
