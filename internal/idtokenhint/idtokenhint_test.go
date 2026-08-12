package idtokenhint_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/idtokenhint"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

const (
	hintIssuer     = "https://op.example"
	hintClientID   = "client-hint"
	hintOtherAud   = "other-audience"
	hintSubject    = "user-hint"
	hintKID        = "hint-kid"
	hintUnknownKID = "kid-not-in-the-set"
)

// hintNow is the fixed instant every minted token is dated with. The
// package under test reads no clock, so a constant keeps the iat
// assertion exact without a clock seam.
func hintNow() time.Time {
	return time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
}

// hintKeys returns a fresh single-entry OP keyset plus the entry behind
// it, so the tests sign with the same machinery the OP uses in
// production rather than assembling a JWS by hand.
func hintKeys(t *testing.T) (*keys.Set, keys.Entry) {
	t.Helper()
	entry, err := keys.GenerateES256(hintKID)
	if err != nil {
		t.Fatalf("keys.GenerateES256: %v", err)
	}
	set, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	return set, entry
}

// baseHintClaims is the canonical id_token claim set the tests mutate.
// The audience is multi-valued so the raw form the package hands back
// is the array shape of RFC 7519 §4.1.3 rather than a bare string.
func baseHintClaims() tokens.IDTokenClaims {
	now := hintNow()
	return tokens.IDTokenClaims{
		Issuer:    hintIssuer,
		Subject:   hintSubject,
		Audience:  []string{hintClientID, hintOtherAud},
		AZP:       hintClientID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
	}
}

// signHint serialises an id_token with the supplied claims under entry.
func signHint(t *testing.T, entry keys.Entry, claims tokens.IDTokenClaims) string {
	t.Helper()
	raw, err := tokens.SignIDToken(tokens.FromInternalEntry(entry), claims)
	if err != nil {
		t.Fatalf("tokens.SignIDToken: %v", err)
	}
	return raw
}

// signHintWithKID serialises an id_token whose kid header is kid rather
// than the entry's own, so a test can present a token that names a key
// the verifying set never held.
func signHintWithKID(t *testing.T, entry keys.Entry, kid string, claims tokens.IDTokenClaims) string {
	t.Helper()
	key := tokens.FromInternalEntry(entry)
	key.KeyID = kid
	raw, err := tokens.SignIDToken(key, claims)
	if err != nil {
		t.Fatalf("tokens.SignIDToken: %v", err)
	}
	return raw
}

// signRawPayload serialises payload as a compact JWS under entry,
// stamping a kid header only when kid is non-empty. The claim encoder
// always emits a kid and always emits a JSON object, so the header and
// payload edges have to be produced at the JOSE layer.
func signRawPayload(t *testing.T, entry keys.Entry, kid string, payload []byte) string {
	t.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{
			Algorithm: josev4.ES256,
			Key: josev4.JSONWebKey{
				Key:       entry.Signer,
				KeyID:     kid,
				Algorithm: string(josev4.ES256),
				Use:       "sig",
			},
		},
		(&josev4.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("josev4.NewSigner: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return raw
}

// TestVerify_RejectsNilKeysetAsUnverifiable pins that a missing keyset
// is reported as a wiring fault of its own rather than folded into a
// signature failure: the OP could not check the token at all, which is
// a different problem from a token that failed the check.
func TestVerify_RejectsNilKeysetAsUnverifiable(t *testing.T) {
	t.Parallel()
	_, entry := hintKeys(t)
	raw := signHint(t, entry, baseHintClaims())

	if _, err := idtokenhint.Verify(context.Background(), nil, hintIssuer, raw); !errors.Is(
		err, idtokenhint.ErrUnverifiable,
	) {
		t.Fatalf("err=%v want %v", err, idtokenhint.ErrUnverifiable)
	}
}

func TestVerify_RejectsInputThatIsNotACompactJWS(t *testing.T) {
	t.Parallel()
	set, _ := hintKeys(t)

	if _, err := idtokenhint.Verify(
		context.Background(), set, hintIssuer, "this.is.not-a-valid-jwt",
	); !errors.Is(err, idtokenhint.ErrMalformed) {
		t.Fatalf("err=%v want %v", err, idtokenhint.ErrMalformed)
	}
}

// TestVerify_RejectsHeaderWithoutKid pins that key resolution is driven
// by an explicit kid and never falls back to trying the active key: a
// kid-less token names no entry, so there is nothing to verify against.
func TestVerify_RejectsHeaderWithoutKid(t *testing.T) {
	t.Parallel()
	set, entry := hintKeys(t)
	payload, err := json.Marshal(map[string]any{
		"iss": hintIssuer,
		"sub": hintSubject,
		"aud": hintClientID,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	raw := signRawPayload(t, entry, "", payload)

	if _, err := idtokenhint.Verify(context.Background(), set, hintIssuer, raw); !errors.Is(
		err, idtokenhint.ErrSignature,
	) {
		t.Fatalf("err=%v want %v", err, idtokenhint.ErrSignature)
	}
}

func TestVerify_RejectsKidNamingNoEntryInTheSet(t *testing.T) {
	t.Parallel()
	set, entry := hintKeys(t)
	raw := signHintWithKID(t, entry, hintUnknownKID, baseHintClaims())

	if _, err := idtokenhint.Verify(context.Background(), set, hintIssuer, raw); !errors.Is(
		err, idtokenhint.ErrSignature,
	) {
		t.Fatalf("err=%v want %v", err, idtokenhint.ErrSignature)
	}
}

// TestVerify_RejectsSignatureFromAKeyOutsideTheSet pins the keyset
// binding: the token's kid resolves to an entry of the verifying set,
// but the bytes were produced by a different private key. A verifier
// that trusted the kid header alone would admit it.
func TestVerify_RejectsSignatureFromAKeyOutsideTheSet(t *testing.T) {
	t.Parallel()
	set, _ := hintKeys(t)
	_, foreign := hintKeys(t)
	raw := signHint(t, foreign, baseHintClaims())

	if _, err := idtokenhint.Verify(context.Background(), set, hintIssuer, raw); !errors.Is(
		err, idtokenhint.ErrSignature,
	) {
		t.Fatalf("err=%v want %v", err, idtokenhint.ErrSignature)
	}
}

// TestVerify_RejectsPayloadThatIsNotAJSONObject covers the step after
// a successful signature check: the OP signed these bytes, but they do
// not decode as a claim set, so no claim can be read out of them.
func TestVerify_RejectsPayloadThatIsNotAJSONObject(t *testing.T) {
	t.Parallel()
	set, entry := hintKeys(t)
	raw := signRawPayload(t, entry, hintKID, []byte(`"a bare JSON string"`))

	if _, err := idtokenhint.Verify(context.Background(), set, hintIssuer, raw); !errors.Is(
		err, idtokenhint.ErrMalformed,
	) {
		t.Fatalf("err=%v want %v", err, idtokenhint.ErrMalformed)
	}
}

// TestVerify_RejectsIssuerOtherThanTheOP pins the check that stops a
// kid collision from being enough to replay a token this OP never
// minted, or one it minted under a different issuer.
func TestVerify_RejectsIssuerOtherThanTheOP(t *testing.T) {
	t.Parallel()
	set, entry := hintKeys(t)
	claims := baseHintClaims()
	claims.Issuer = "https://other-op.example"
	raw := signHint(t, entry, claims)

	if _, err := idtokenhint.Verify(context.Background(), set, hintIssuer, raw); !errors.Is(
		err, idtokenhint.ErrIssuer,
	) {
		t.Fatalf("err=%v want %v", err, idtokenhint.ErrIssuer)
	}
}

// TestVerify_SkipsIssuerCheckWhenIssuerArgumentIsEmpty pins the
// documented escape hatch: a caller that passes no issuer gets the
// signature guarantee only, and any iss the token carries is admitted.
func TestVerify_SkipsIssuerCheckWhenIssuerArgumentIsEmpty(t *testing.T) {
	t.Parallel()
	set, entry := hintKeys(t)
	claims := baseHintClaims()
	claims.Issuer = "https://other-op.example"
	raw := signHint(t, entry, claims)

	got, err := idtokenhint.Verify(context.Background(), set, "", raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Issuer != "https://other-op.example" {
		t.Errorf("iss=%q want %q", got.Issuer, "https://other-op.example")
	}
}

// TestVerify_ReturnsEveryClaimVerbatim pins the contract the two
// calling endpoints build their own policies on: each member is handed
// back exactly as the token carried it, and the audience stays raw JSON
// so neither RFC 7519 §4.1.3 shape is collapsed into the other.
func TestVerify_ReturnsEveryClaimVerbatim(t *testing.T) {
	t.Parallel()
	set, entry := hintKeys(t)
	claims := baseHintClaims()
	raw := signHint(t, entry, claims)

	got, err := idtokenhint.Verify(context.Background(), set, hintIssuer, raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Issuer != hintIssuer {
		t.Errorf("iss=%q want %q", got.Issuer, hintIssuer)
	}
	if got.Subject != hintSubject {
		t.Errorf("sub=%q want %q", got.Subject, hintSubject)
	}
	if got.AZP != hintClientID {
		t.Errorf("azp=%q want %q", got.AZP, hintClientID)
	}
	if got.IssuedAt != hintNow().Unix() {
		t.Errorf("iat=%d want %d", got.IssuedAt, hintNow().Unix())
	}
	wantAud := `["` + hintClientID + `","` + hintOtherAud + `"]`
	if string(got.Audience) != wantAud {
		t.Errorf("aud=%s want %s", got.Audience, wantAud)
	}
}

// TestVerify_ReturnsBareStringAudienceUnwidened pins the other half of
// the raw-audience contract: a single-valued audience stays the bare
// string form the token carried instead of being widened to an array.
func TestVerify_ReturnsBareStringAudienceUnwidened(t *testing.T) {
	t.Parallel()
	set, entry := hintKeys(t)
	claims := baseHintClaims()
	claims.Audience = []string{hintClientID}
	raw := signHint(t, entry, claims)

	got, err := idtokenhint.Verify(context.Background(), set, hintIssuer, raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	wantAud := `"` + hintClientID + `"`
	if string(got.Audience) != wantAud {
		t.Errorf("aud=%s want %s", got.Audience, wantAud)
	}
}

// TestContains_AcceptsEitherAudienceShapeAndFailsClosed covers both
// RFC 7519 §4.1.3 forms and the inputs that must not match: an
// unparseable or absent audience answers "no" rather than erroring, so
// a caller cannot mistake an undecidable audience for a match.
func TestContains_AcceptsEitherAudienceShapeAndFailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  json.RawMessage
		want string
		ok   bool
	}{
		{
			name: "bare string names the wanted party",
			raw:  json.RawMessage(`"client-hint"`),
			want: hintClientID,
			ok:   true,
		},
		{
			name: "bare string names another party",
			raw:  json.RawMessage(`"someone-else"`),
			want: hintClientID,
			ok:   false,
		},
		{
			name: "array holds the wanted party",
			raw:  json.RawMessage(`["someone-else","client-hint"]`),
			want: hintClientID,
			ok:   true,
		},
		{
			name: "array holds only other parties",
			raw:  json.RawMessage(`["someone-else","yet-another"]`),
			want: hintClientID,
			ok:   false,
		},
		{
			name: "empty want matches nothing",
			raw:  json.RawMessage(`"client-hint"`),
			want: "",
			ok:   false,
		},
		{
			name: "absent claim",
			raw:  nil,
			want: hintClientID,
			ok:   false,
		},
		{
			name: "neither a string nor an array of strings",
			raw:  json.RawMessage(`{"aud":"client-hint"}`),
			want: hintClientID,
			ok:   false,
		},
		{
			name: "array of non-strings",
			raw:  json.RawMessage(`[1,2]`),
			want: hintClientID,
			ok:   false,
		},
		{
			name: "empty array",
			raw:  json.RawMessage(`[]`),
			want: hintClientID,
			ok:   false,
		},
		{
			name: "empty first element",
			raw:  json.RawMessage(`["",""]`),
			want: hintClientID,
			ok:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := idtokenhint.Contains(tc.raw, tc.want); got != tc.ok {
				t.Errorf("Contains(%s, %q)=%v want %v", tc.raw, tc.want, got, tc.ok)
			}
		})
	}
}

// TestFirst_ReadsEitherAudienceShape pins that the caller which
// identifies a client from the audience reads the same value out of
// both RFC 7519 §4.1.3 forms.
func TestFirst_ReadsEitherAudienceShape(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{
			name: "bare string",
			raw:  json.RawMessage(`"client-hint"`),
			want: hintClientID,
		},
		{
			name: "array takes its first entry",
			raw:  json.RawMessage(`["client-hint","other-audience"]`),
			want: hintClientID,
		},
		{
			name: "single-element array",
			raw:  json.RawMessage(`["client-hint"]`),
			want: hintClientID,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := idtokenhint.First(tc.raw)
			if err != nil {
				t.Fatalf("First(%s): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("First(%s)=%q want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestFirst_RejectsAudienceNamingNobody pins that every shape which
// fails to name a party is an error rather than an empty string: the
// caller derives a client_id from this value, and an empty client_id
// would be carried onward as if it had been read from the token.
func TestFirst_RejectsAudienceNamingNobody(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  json.RawMessage
	}{
		{name: "absent claim", raw: nil},
		{name: "empty bare string", raw: json.RawMessage(`""`)},
		{name: "empty array", raw: json.RawMessage(`[]`)},
		{name: "empty first element", raw: json.RawMessage(`["","other-audience"]`)},
		{name: "neither a string nor an array of strings", raw: json.RawMessage(`{"aud":"client-hint"}`)},
		{name: "array of non-strings", raw: json.RawMessage(`[1,2]`)},
		{name: "not JSON at all", raw: json.RawMessage(`}{`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := idtokenhint.First(tc.raw)
			if !errors.Is(err, idtokenhint.ErrMalformed) {
				t.Fatalf("err=%v want %v", err, idtokenhint.ErrMalformed)
			}
			if got != "" {
				t.Errorf("aud=%q want empty on rejection", got)
			}
		})
	}
}
