package jar_test

import (
	"context"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

const (
	testIssuer   = "https://op.example.com"
	testClientID = "client-1"
	testKID      = "kid-1"
)

// fakeClock returns a constant Now() reading; tests inject it so the
// verifier and the request object share a single notion of "now".
type fakeClock struct{ now time.Time }

func (f fakeClock) Now() time.Time { return f.now }

var _ timex.Clock = fakeClock{}

// staticResolver is a tiny [jar.JWKSResolver] for unit tests. It
// returns the supplied keyset verbatim regardless of the client.
type staticResolver struct {
	keys *josev4.JSONWebKeySet
	err  error
}

func (s *staticResolver) Resolve(_ context.Context, _ *store.Client) (*josev4.JSONWebKeySet, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.keys, nil
}

// happyClaims returns a claim bag that satisfies every check the
// verifier performs; rows mutate the field they want to fail.
func happyClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":           testClientID,
		"aud":           testIssuer,
		"exp":           now.Add(5 * time.Minute).Unix(),
		"iat":           now.Unix(),
		"response_type": "code",
		"redirect_uri":  "https://rp.example.com/cb",
		"state":         "s",
		"nonce":         "n",
		"scope":         "openid",
		"client_id":     testClientID,
	}
}

// newTestVerifier wires a verifier with a fake clock pinned to now and
// the supplied keyset. It returns the verifier so individual tests can
// drive [jar.Verifier.Verify] directly.
//
// The helper sets [jar.VerifierConfig.AllowMissingNbf] and
// [jar.VerifierConfig.AllowMissingJTI] because the shared [happyClaims]
// fixture below does not include "nbf" / "jti" — the runtime defaults
// reject nbf-less and jti-less request objects so without the opt-outs
// every claim-shape test would fail before reaching the assertion
// under test. The dedicated [newStrictTestVerifier] helper exercises
// the FAPI 2.0 stance, and [newJTITestVerifier] exercises the jti
// gate specifically.
func newTestVerifier(t *testing.T, now time.Time, keys *josev4.JSONWebKeySet) *jar.Verifier {
	t.Helper()
	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:          testIssuer,
		Resolver:        &staticResolver{keys: keys},
		Clock:           fakeClock{now: now},
		AllowMissingNbf: true,
		AllowMissingJTI: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// makeRequestObject signs claims with a fresh key and returns the JWS
// plus a single-key keyset that verifies it. Tests use this to keep the
// happy-path scaffolding short.
func makeRequestObject(t *testing.T, claims any) (string, *josev4.JSONWebKeySet) {
	t.Helper()
	raw, jwk, _ := signedRequestObject(t, claims, testKID)
	keys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{*jwk}}
	return raw, keys
}

func newClient() *store.Client {
	return &store.Client{ID: testClientID}
}

func TestVerify_HappyPath(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	raw, keys := makeRequestObject(t, happyClaims(now))
	v := newTestVerifier(t, now, keys)
	obj, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if obj.Claims["state"] != "s" {
		t.Errorf("Claims[state]=%v want s", obj.Claims["state"])
	}
}

func TestVerify_RejectsWrongTypeHeader(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	raw, jwk, _ := signedRequestObjectWithType(t, happyClaims(now), testKID, "JWT")
	keys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{*jwk}}
	v := newTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrTypeInvalid) {
		t.Fatalf("err=%v want ErrTypeInvalid", err)
	}
}

func TestVerify_RejectsIssMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["iss"] = "someone-else"
	raw, keys := makeRequestObject(t, c)
	v := newTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrIssMismatch) {
		t.Fatalf("err=%v want ErrIssMismatch", err)
	}
}

func TestVerify_RejectsAudMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["aud"] = "https://different-op.example.com"
	raw, keys := makeRequestObject(t, c)
	v := newTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrAudMismatch) {
		t.Fatalf("err=%v want ErrAudMismatch", err)
	}
}

func TestVerify_AcceptsAudArrayWithIssuer(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["aud"] = []string{"https://other.example", testIssuer}
	raw, keys := makeRequestObject(t, c)
	v := newTestVerifier(t, now, keys)
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_StrictAudienceRejectsAudArray(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["nbf"] = now.Unix()
	c["aud"] = []string{testIssuer}
	raw, keys := makeRequestObject(t, c)
	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:                testIssuer,
		Resolver:              &staticResolver{keys: keys},
		Clock:                 fakeClock{now: now},
		RequireNbf:            true,
		RequireSingleAudience: true,
		AllowMissingJTI:       true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); !errors.Is(err, jar.ErrAudMismatch) {
		t.Fatalf("err=%v want ErrAudMismatch", err)
	}
}

func TestVerify_RejectsExpired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["exp"] = now.Add(-1 * time.Minute).Unix()
	raw, keys := makeRequestObject(t, c)
	v := newTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrExpired) {
		t.Fatalf("err=%v want ErrExpired", err)
	}
}

func TestVerify_RejectsMissingExp(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	delete(c, "exp")
	raw, keys := makeRequestObject(t, c)
	v := newTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrExpired) {
		t.Fatalf("err=%v want ErrExpired", err)
	}
}

func TestVerify_RejectsNbfFuture(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["nbf"] = now.Add(10 * time.Minute).Unix()
	raw, keys := makeRequestObject(t, c)
	v := newTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrNotYetValid) {
		t.Fatalf("err=%v want ErrNotYetValid", err)
	}
}

func TestVerify_RejectsIatTooOld(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["iat"] = now.Add(-30 * time.Minute).Unix()
	c["exp"] = now.Add(5 * time.Minute).Unix()
	raw, keys := makeRequestObject(t, c)
	v := newTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrExpired) {
		t.Fatalf("err=%v want ErrExpired", err)
	}
}

func TestVerify_RejectsNestedRequest(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["request"] = "another-jwt"
	raw, keys := makeRequestObject(t, c)
	v := newTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrNestedRequest) {
		t.Fatalf("err=%v want ErrNestedRequest", err)
	}
}

func TestVerify_RejectsAlgNotInClientPin(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	raw, keys := makeRequestObject(t, happyClaims(now))
	v := newTestVerifier(t, now, keys)
	c := newClient()
	c.RequestObjectSigningAlg = "PS256"
	_, err := v.Verify(context.Background(), raw, testClientID, c)
	if !errors.Is(err, jar.ErrAlgNotAllowed) {
		t.Fatalf("err=%v want ErrAlgNotAllowed", err)
	}
}

func TestVerify_RejectsSignatureWithMismatchedKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	raw, _ := makeRequestObject(t, happyClaims(now))
	// Build a fresh keyset whose key does not match the signer.
	_, otherKey, _ := signedRequestObject(t, map[string]any{}, testKID)
	keys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{*otherKey}}
	v := newTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrSigInvalid) {
		t.Fatalf("err=%v want ErrSigInvalid", err)
	}
}

func TestVerify_RejectsNoMatchingKID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	raw, _, _ := signedRequestObject(t, happyClaims(now), "kid-real")
	// Keyset advertises a different kid.
	_, jwk2, _ := signedRequestObject(t, map[string]any{}, "kid-other")
	keys := &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{*jwk2}}
	v := newTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrNoMatchingJWK) {
		t.Fatalf("err=%v want ErrNoMatchingJWK", err)
	}
}

func TestVerify_RejectsUnconfiguredClient(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	raw, _ := makeRequestObject(t, happyClaims(now))
	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:          testIssuer,
		Resolver:        &staticResolver{err: jar.ErrJWKSConfigured},
		Clock:           fakeClock{now: now},
		AllowMissingJTI: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	_, gotErr := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(gotErr, jar.ErrJWKSConfigured) {
		t.Fatalf("err=%v want ErrJWKSConfigured", gotErr)
	}
}

func TestNewVerifier_RequiresIssuer(t *testing.T) {
	t.Parallel()
	_, err := jar.NewVerifier(jar.VerifierConfig{Resolver: &staticResolver{}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewVerifier_RequiresResolver(t *testing.T) {
	t.Parallel()
	_, err := jar.NewVerifier(jar.VerifierConfig{Issuer: testIssuer})
	if err == nil {
		t.Fatal("expected error")
	}
}

// newStrictTestVerifier wires a verifier configured with the FAPI 2.0
// Message Signing posture (RequireNbf + 60-minute lifetime cap). Use it
// to exercise the OFCS conformance modules
// "ensure-request-object-without-nbf-fails",
// "ensure-request-object-with-exp-over-60-fails", and
// "ensure-request-object-with-nbf-over-60-fails". The cap matches the
// op-builder wiring at op_builders.go which pins MaxLifetime to 60
// minutes for every FAPI-family profile.
func newStrictTestVerifier(t *testing.T, now time.Time, keys *josev4.JSONWebKeySet) *jar.Verifier {
	t.Helper()
	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:          testIssuer,
		Resolver:        &staticResolver{keys: keys},
		Clock:           fakeClock{now: now},
		RequireNbf:      true,
		MaxLifetime:     60 * time.Minute,
		AllowMissingJTI: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestVerify_FAPI2_RejectsMissingNbf(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	delete(c, "nbf")
	// exp is well within the 60-minute FAPI lifetime cap so the
	// verifier reaches assertNbf instead of bailing out earlier on
	// assertExp.
	c["exp"] = now.Add(30 * time.Second).Unix()
	raw, keys := makeRequestObject(t, c)
	v := newStrictTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrNotYetValid) {
		t.Fatalf("err=%v want ErrNotYetValid", err)
	}
}

// TestVerify_FAPI2_RejectsExpOver60Minutes asserts the FAPI 2.0
// Message Signing §5.6 rule that exp must not be more than 60 minutes
// in the future. The OFCS module
// "ensure-request-object-with-exp-over-60-fails" pushes exp to 70
// minutes ahead and expects rejection.
func TestVerify_FAPI2_RejectsExpOver60Minutes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["nbf"] = now.Unix()
	c["exp"] = now.Add(70 * time.Minute).Unix()
	raw, keys := makeRequestObject(t, c)
	v := newStrictTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrExpired) {
		t.Fatalf("err=%v want ErrExpired", err)
	}
}

// TestVerify_FAPI2_AcceptsExpJustUnder60Minutes confirms the boundary
// of [TestVerify_FAPI2_RejectsExpOver60Minutes]: an exp 59 minutes in
// the future MUST pass the lifetime cap (so the test pins both sides
// of the threshold and a regression that flips the comparison from
// ">" to ">=" surfaces immediately).
func TestVerify_FAPI2_AcceptsExpJustUnder60Minutes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["nbf"] = now.Unix()
	c["iat"] = now.Unix()
	c["exp"] = now.Add(59 * time.Minute).Unix()
	raw, keys := makeRequestObject(t, c)
	v := newStrictTestVerifier(t, now, keys)
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); err != nil {
		t.Fatalf("err=%v want nil", err)
	}
}

// TestVerify_FAPI2_RejectsNbfOver60MinutesPast asserts the FAPI 2.0
// Message Signing §5.6 staleness bound: nbf must not be more than
// 60 minutes in the past. The OFCS module
// "ensure-request-object-with-nbf-over-60-fails" pushes nbf to 70
// minutes ago and expects rejection. iat is held inside DefaultMaxAge
// so the failure surface is unambiguously the nbf check rather than
// the iat staleness gate.
func TestVerify_FAPI2_RejectsNbfOver60MinutesPast(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["nbf"] = now.Add(-70 * time.Minute).Unix()
	// iat is held fresh so the iat staleness gate (DefaultMaxAge=10min)
	// does not fire first; the rejection must surface from assertNbf.
	c["iat"] = now.Unix()
	c["exp"] = now.Add(30 * time.Second).Unix()
	raw, keys := makeRequestObject(t, c)
	v := newStrictTestVerifier(t, now, keys)
	_, err := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrNotYetValid) {
		t.Fatalf("err=%v want ErrNotYetValid", err)
	}
}

// TestVerify_FAPI2_AcceptsNbfJustUnder60MinutesPast pins the boundary
// opposite to [TestVerify_FAPI2_RejectsNbfOver60MinutesPast]: an nbf
// 59 minutes in the past MUST pass the lifetime cap. iat stays fresh
// so the iat staleness gate (DefaultMaxAge=10min) is not the gate
// being exercised here.
func TestVerify_FAPI2_AcceptsNbfJustUnder60MinutesPast(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["nbf"] = now.Add(-59 * time.Minute).Unix()
	c["iat"] = now.Unix()
	c["exp"] = now.Add(1 * time.Second).Unix()
	raw, keys := makeRequestObject(t, c)
	v := newStrictTestVerifier(t, now, keys)
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); err != nil {
		t.Fatalf("err=%v want nil", err)
	}
}

// TestVerify_FAPI2_AcceptsWithinWindow exercises the canonical
// OFCS happy-flow shape (nbf=now, exp=now+5min). The strict verifier
// MUST accept this so the wider plan can drive past PAR.
func TestVerify_FAPI2_AcceptsWithinWindow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["nbf"] = now.Unix()
	c["iat"] = now.Unix()
	c["exp"] = now.Add(5 * time.Minute).Unix()
	raw, keys := makeRequestObject(t, c)
	v := newStrictTestVerifier(t, now, keys)
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); err != nil {
		t.Fatalf("err=%v want nil", err)
	}
}

func TestVerifier_AllowedAlgs_DefaultIncludesAll(t *testing.T) {
	t.Parallel()
	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:          testIssuer,
		Resolver:        &staticResolver{},
		AllowMissingJTI: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	algs := v.AllowedAlgs()
	if len(algs) == 0 {
		t.Fatal("AllowedAlgs empty")
	}
}
