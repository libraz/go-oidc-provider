package op_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// TestWithProfile_FAPICIBARequiresCIBAGrant pins the grant-axis
// constraint: the FAPI-CIBA profile exists to govern the
// /bc-authorize ceremony, and that endpoint is mounted from the grant
// set rather than the profile set. Declaring the profile without the
// grant would produce an OP that advertises a backchannel
// authentication posture and answers 404 to every backchannel
// authentication request, so [op.New] refuses it.
func TestWithProfile_FAPICIBARequiresCIBAGrant(t *testing.T) {
	t.Parallel()

	opts := append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPICIBA),
		op.WithDPoPNonceSource(stubDPoPNonceSource{}),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("expected construction error for FAPICIBA without the CIBA grant, got nil")
	}
	if !op.IsServerError(err) {
		t.Errorf("expected a server-side configuration error, got %v", err)
	}
	if !strings.Contains(err.Error(), "fapi-ciba") {
		t.Errorf("err = %v, want it to name the declared profile", err)
	}
	if !strings.Contains(err.Error(), "WithCIBA") {
		t.Errorf("err = %v, want it to name the option that activates the grant", err)
	}
}

// TestWithProfile_FAPICIBAAcceptsWiredGrant is the companion case:
// the same profile constructs cleanly once the grant is activated
// through the option that also wires the grant's collaborators.
func TestWithProfile_FAPICIBAAcceptsWiredGrant(t *testing.T) {
	t.Parallel()

	opts := append(validBaseOptsWithInmem(t),
		op.WithCIBA(op.WithCIBAHintResolver(stubCIBAHintResolver{})),
		op.WithProfile(profile.FAPICIBA),
		op.WithDPoPNonceSource(stubDPoPNonceSource{}),
	)
	if _, err := op.New(opts...); err != nil {
		t.Fatalf("WithProfile(FAPICIBA) + WithCIBA failed: %v", err)
	}
}

// TestWithProfile_NonCIBAProfilesConstrainNoGrant documents that the
// grant constraint is specific to FAPI-CIBA. The FAPI 2.0 family
// governs how the authorization-code grant behaves rather than which
// grants exist, so the default grant set satisfies them.
func TestWithProfile_NonCIBAProfilesConstrainNoGrant(t *testing.T) {
	t.Parallel()

	for _, p := range []profile.Profile{profile.Baseline, profile.FAPI2Baseline, profile.FAPI2MessageSigning} {
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()
			opts := append(validBaseOptsWithInmem(t),
				op.WithProfile(p),
				op.WithDPoPNonceSource(stubDPoPNonceSource{}),
			)
			if _, err := op.New(opts...); err != nil {
				t.Fatalf("WithProfile(%s) with the default grant set failed: %v", p, err)
			}
		})
	}
}

// TestWithProfile_BaselineAddsNoFeatureRequirement checks that the
// OAuth 2.1 baseline profile is adoptable on its own: unlike the FAPI
// family it auto-enables nothing and demands no supporting
// infrastructure, so a plain OIDC deployment can declare it without
// changing anything else about its wiring.
func TestWithProfile_BaselineAddsNoFeatureRequirement(t *testing.T) {
	t.Parallel()

	if got := profile.RequiredFeatures(profile.Baseline); got != nil {
		t.Errorf("RequiredFeatures(Baseline) = %v, want nil", got)
	}
	if got := profile.RequiredGrants(profile.Baseline); got != nil {
		t.Errorf("RequiredGrants(Baseline) = %v, want nil", got)
	}
	if _, err := op.New(append(validBaseOptsWithInmem(t), op.WithProfile(profile.Baseline))...); err != nil {
		t.Fatalf("WithProfile(Baseline) alone failed: %v", err)
	}
}

// startupRecord is the decoded [op.AuditStartupProfile] line. Only the
// fields the assertions below read are modelled; the slog JSON handler
// emits the canonical audit attributes at the top level and the event
// payload under an "extras" group.
type startupRecord struct {
	Audit  string         `json:"audit"`
	Event  string         `json:"event"`
	Extras map[string]any `json:"extras"`
}

// captureStartupProfile constructs a Provider with the supplied extra
// options and returns the startup record it emitted. It fails the test
// when no such record appears, which is the point: the event is the
// only place an operator can read the resolved posture from.
func captureStartupProfile(t *testing.T, extra ...op.Option) startupRecord {
	t.Helper()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	opts := append(validBaseOptsWithInmem(t), op.WithAuditLogger(logger))
	opts = append(opts, extra...)
	if _, err := op.New(opts...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec startupRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode audit line %q: %v", line, err)
		}
		if rec.Event == string(op.AuditStartupProfile) {
			return rec
		}
	}
	t.Fatalf("no %s record in audit output: %s", op.AuditStartupProfile, buf.String())
	return startupRecord{}
}

// TestAuditStartupProfile_UnprofiledDeployment pins the record an OP
// with no declared profile emits. The permissive answers are the
// interesting part: this is exactly the configuration whose posture
// could not previously be read off the audit stream.
func TestAuditStartupProfile_UnprofiledDeployment(t *testing.T) {
	t.Parallel()

	rec := captureStartupProfile(t)
	if rec.Audit != "true" {
		t.Errorf("audit=%q want \"true\" so shippers can route the record", rec.Audit)
	}
	assertStrings(t, rec, "profiles", nil)
	assertStrings(t, rec, "grants", []string{"authorization_code", "refresh_token"})
	assertBool(t, rec, "pkce_required", false)
	assertBool(t, rec, "par_required", false)
	if got := rec.Extras["sender_constrained"]; got != "" {
		t.Errorf("sender_constrained=%v want empty (bearer tokens are legal)", got)
	}
}

// TestAuditStartupProfile_BaselineDeployment checks that declaring the
// OAuth 2.1 baseline changes the recorded posture — the record has to
// distinguish a deliberate declaration from the permissive default or
// it does not answer the question it exists for.
func TestAuditStartupProfile_BaselineDeployment(t *testing.T) {
	t.Parallel()

	rec := captureStartupProfile(t, op.WithProfile(profile.Baseline))
	assertStrings(t, rec, "profiles", []string{"baseline"})
	assertBool(t, rec, "pkce_required", true)
	assertBool(t, rec, "par_required", false)
	assertStrings(t, rec, "client_auth_methods", nil)
}

// TestAuditStartupProfile_FAPI2Deployment checks the resolved-policy
// half of the record: the profile's auto-enabled features, the arm it
// picked out of the DPoP-or-mTLS disjunction, and the TTL cap it
// applied all have to be readable without re-deriving them from the
// profile name.
func TestAuditStartupProfile_FAPI2Deployment(t *testing.T) {
	t.Parallel()

	rec := captureStartupProfile(t,
		op.WithProfile(profile.FAPI2Baseline),
		op.WithDPoPNonceSource(stubDPoPNonceSource{}),
	)
	assertStrings(t, rec, "profiles", []string{"fapi2-baseline"})
	assertStrings(t, rec, "features", []string{"par", "jar", "dpop"})
	assertBool(t, rec, "pkce_required", true)
	assertBool(t, rec, "par_required", true)
	assertBool(t, rec, "state_or_nonce_required", true)
	if got := rec.Extras["sender_constrained"]; got != "dpop" {
		t.Errorf("sender_constrained=%v want \"dpop\" (the auto-enabled arm)", got)
	}
	// The profile permits the two mTLS methods as well, but the
	// runtime client-auth verifier does not negotiate them and
	// discovery does not advertise them. The record reports what the
	// OP enforces rather than what the spec permits — an operator
	// reading it needs the effective set.
	assertStrings(t, rec, "client_auth_methods", []string{"private_key_jwt"})
}

// TestAuditStartupProfile_MTLSSuppressesDPoPDefault confirms the
// record reports the mechanism the deployment actually runs rather
// than the profile's default pick: an explicit mTLS opt-in satisfies
// the disjunction, so the DPoP auto-enable steps aside.
func TestAuditStartupProfile_MTLSSuppressesDPoPDefault(t *testing.T) {
	t.Parallel()

	rec := captureStartupProfile(t,
		op.WithFeature(feature.MTLS),
		op.WithProfile(profile.FAPI2Baseline),
	)
	if got := rec.Extras["sender_constrained"]; got != "mtls" {
		t.Errorf("sender_constrained=%v want \"mtls\"", got)
	}
	assertBool(t, rec, "dpop_nonce_required", false)
}

// TestAuditStartupProfile_CIBADeployment checks that the grant axis
// reaches the record, so an operator can see that the declared
// FAPI-CIBA posture is backed by a mounted backchannel endpoint.
func TestAuditStartupProfile_CIBADeployment(t *testing.T) {
	t.Parallel()

	rec := captureStartupProfile(t,
		op.WithCIBA(op.WithCIBAHintResolver(stubCIBAHintResolver{})),
		op.WithProfile(profile.FAPICIBA),
		op.WithDPoPNonceSource(stubDPoPNonceSource{}),
	)
	assertStrings(t, rec, "grants", []string{"authorization_code", "refresh_token", grant.CIBA.String()})
	assertBool(t, rec, "signed_backchannel_request_required", true)
	assertBool(t, rec, "dpop_nonce_required", true)
}

// assertStrings compares a string-slice payload field. A nil want
// asserts the field is present but empty, which is how the record
// spells "no profile narrowed this".
func assertStrings(t *testing.T, rec startupRecord, key string, want []string) {
	t.Helper()
	raw, ok := rec.Extras[key]
	if !ok {
		t.Fatalf("%s missing from the startup record", key)
	}
	items, ok := raw.([]any)
	if !ok {
		t.Fatalf("%s = %v (%T), want a list", key, raw, raw)
	}
	got := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			t.Fatalf("%s contains %v (%T), want strings", key, item, item)
		}
		got = append(got, s)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s = %v, want %v", key, got, want)
	}
}

// assertBool compares a boolean payload field.
func assertBool(t *testing.T, rec startupRecord, key string, want bool) {
	t.Helper()
	raw, ok := rec.Extras[key]
	if !ok {
		t.Fatalf("%s missing from the startup record", key)
	}
	got, ok := raw.(bool)
	if !ok {
		t.Fatalf("%s = %v (%T), want a bool", key, raw, raw)
	}
	if got != want {
		t.Errorf("%s = %v, want %v", key, got, want)
	}
}
