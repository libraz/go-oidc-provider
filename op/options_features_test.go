package op_test

import (
	"context"
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

// TestValidateProfile_NoFalsePositiveWithoutProfile pins the
// contrapositive of the F-7 add-only invariant: when no profile is
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

// TestValidateProfile_RejectsMissingRequiredFeature pins the F-7
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
// the plan 005 §3.6 auto-enable contract: an embedder calling
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

func TestWithProfile_FAPI2Baseline_RequiresSenderConstrainedToken(t *testing.T) {
	t.Parallel()

	// PAR and JAR are auto-enabled by [op.WithProfile]; the
	// disjunctive DPoP/MTLS requirement (profile.RequiredAnyOf) is
	// the only remaining flag the embedder must supply.
	_, err := op.New(append(validBaseOpts(t),
		op.WithProfile(profile.FAPI2Baseline),
	)...)
	if err == nil {
		t.Fatal("expected error when neither DPoP nor MTLS is enabled, got nil")
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

// TestWithProfile_FAPI_JARVerifierStrictJTIPosture pins the wiring
// rule that op.New flips the JAR verifier's AllowMissingJTI off
// under any FAPI-family profile. The flag is internal-only — there
// is no public option for an embedder to flip it back on — so the
// test exercises the construction path through every FAPI profile
// that admits JAR (FAPI 2.0 Baseline auto-enables JAR; FAPI 2.0
// Message Signing inherits the same auto-enable; FAPICIBA is a
// placeholder profile today but the wiring still flips the bit so
// its conformance landing does not have to revisit the rule).
//
// A dedicated negative test ("FAPI profile + AllowMissingJTI=true
// fails") cannot exist in the option layer because the surface does
// not expose AllowMissingJTI. The Wave-1C report documents the
// absence of an embedder path; the op.go wiring is the single
// declaration site of the rule.
func TestWithProfile_FAPI_JARVerifierStrictJTIPosture(t *testing.T) {
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
