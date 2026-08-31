package devicecodeendpoint_test

// /device_authorization requires client authentication, so any durable
// write it performs before that credential is checked turns an
// attacker's request rate directly into storage cost. The DPoP replay
// marker (RFC 9449 §11.1) is the only such write on the path: proof
// verification has to run first so the §8 use_dpop_nonce challenge fires
// before a client_assertion jti is consumed, but the marker itself does
// not, and a marker written on a request that never authenticated would
// make the legitimate retry surface as a replay.
//
// These tests drive the handler against an observable ConsumedJTIStore
// rather than inspecting call order, so they measure the property that
// matters (a write happened) instead of the shape of the code that
// produces it.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/devicecodeendpoint"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// writeGateEndpoint is the request target the tests POST to. The
// proof's "htu" claim has to name the same URL the handler canonicalises
// from the request, and [httptest.NewRequestWithContext] fills the host
// with "example.com" over plain HTTP.
//
// The identifier carries no "dpopWrite" prefix on purpose: gosec's
// hardcoded-credential name pattern matches the "pw" inside it and
// would fault this URL as a secret.
const writeGateEndpoint = "http://example.com/device_authorization"

// Credentials for the confidential client the write-gate tests
// authenticate as.
const (
	dpopGateClientID     = "device-dpop-client"
	dpopGateSecret       = "correct-secret"
	dpopGateStoredSecret = "stored-secret-digest"
)

// countingJTIs is a [store.ConsumedJTIStore] decorator that counts Mark
// calls. Every call is forwarded, so replay semantics are the real
// in-memory ones and only the observation is added.
type countingJTIs struct {
	inner store.ConsumedJTIStore
	marks atomic.Int64
}

func (c *countingJTIs) Mark(ctx context.Context, jti string, expiresAt time.Time) error {
	c.marks.Add(1)
	return c.inner.Mark(ctx, jti, expiresAt)
}

func (c *countingJTIs) Has(ctx context.Context, jti string) (bool, error) {
	return c.inner.Has(ctx, jti)
}

// dpopWriteGateFixture bundles a DPoP-enabled /device_authorization
// handler whose consumed-jti writes are observable, plus the key its
// proofs are signed with.
type dpopWriteGateFixture struct {
	deps  devicecodeendpoint.Deps
	marks *countingJTIs
	now   time.Time
	key   *ecdsa.PrivateKey
	jwk   josev4.JSONWebKey
}

func newDPoPWriteGateFixture(t *testing.T) *dpopWriteGateFixture {
	t.Helper()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	st, deps := newFixture(t, now, store.Client{
		ID:                      dpopGateClientID,
		TokenEndpointAuthMethod: string(clientauth.MethodSecretPost),
		SecretHash:              dpopGateStoredSecret,
		GrantTypes:              []string{grant.DeviceCode.String()},
		Scopes:                  []string{"openid"},
	})
	deps.SecretVerifier = exactSecretVerifier{
		wantPresented: dpopGateSecret,
		wantStored:    dpopGateStoredSecret,
	}
	marks := &countingJTIs{inner: st.ConsumedJTIs()}
	verifier, err := dpop.NewVerifier(dpop.VerifierConfig{JTIs: marks, Clock: fixedClock(now)})
	if err != nil {
		t.Fatalf("dpop.NewVerifier: %v", err)
	}
	deps.DPoP = verifier

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return &dpopWriteGateFixture{
		deps:  deps,
		marks: marks,
		now:   now,
		key:   priv,
		jwk:   josev4.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(josev4.ES256), Use: "sig"},
	}
}

// proof builds an RFC 9449 §4.2 proof for a POST to the fixture's
// endpoint. jti is explicit so a caller can choose whether two requests
// share one; htm is explicit so a caller can deliberately break the
// request binding.
func (f *dpopWriteGateFixture) proof(t *testing.T, jti, htm string) string {
	t.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: f.key},
		(&josev4.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", f.jwk),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	token, err := jwt.Signed(signer).Claims(map[string]any{
		"htm": htm,
		"htu": writeGateEndpoint,
		"iat": f.now.Unix(),
		"jti": jti,
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return token
}

// post submits a device-authorization request with the supplied DPoP
// proof and client_secret_post credentials.
func (f *dpopWriteGateFixture) post(t *testing.T, proof, secret string) *httptest.ResponseRecorder {
	t.Helper()
	return f.postProofValues(t, secret, proof)
}

// postProofValues is [dpopWriteGateFixture.post] with explicit control
// over the "DPoP" header values: one header value per entry in proofs,
// so a caller can reproduce the multi-value shape RFC 9449 §4.1 forbids.
func (f *dpopWriteGateFixture) postProofValues(t *testing.T, secret string, proofs ...string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"client_id":     {dpopGateClientID},
		"client_secret": {secret},
	}
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		writeGateEndpoint,
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, proof := range proofs {
		req.Header.Add("DPoP", proof)
	}
	rec := httptest.NewRecorder()
	devicecodeendpoint.Handler(f.deps).ServeHTTP(rec, req)
	return rec
}

// decodeDPoPEnvelope decodes the OAuth error envelope, including the
// description the DPoP boundary mapping carries.
func decodeDPoPEnvelope(t *testing.T, rec *httptest.ResponseRecorder) (code, description string) {
	t.Helper()
	var env struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v: %s", err, rec.Body.String())
	}
	return env.Error, env.Description
}

// TestDeviceAuthorization_UnauthenticatedDPoPRequestPerformsNoDurableWrite
// is the gate: a request carrying a perfectly valid proof but the wrong
// client secret must be refused without touching the consumed-jti table.
func TestDeviceAuthorization_UnauthenticatedDPoPRequestPerformsNoDurableWrite(t *testing.T) {
	t.Parallel()

	f := newDPoPWriteGateFixture(t)
	rec := f.post(t, f.proof(t, "jti-unauthenticated", http.MethodPost), "wrong-secret")

	assertOAuthError(t, rec, http.StatusUnauthorized, "invalid_client")
	if got := f.marks.marks.Load(); got != 0 {
		t.Fatalf("consumed-jti writes = %d, want 0; an unauthenticated request must not reach durable storage", got)
	}
}

// TestDeviceAuthorization_AuthenticatedDPoPRequestMarksProofOnce is the
// control: the deferral must not have removed the replay marker, only
// moved it behind the credential.
func TestDeviceAuthorization_AuthenticatedDPoPRequestMarksProofOnce(t *testing.T) {
	t.Parallel()

	f := newDPoPWriteGateFixture(t)
	rec := f.post(t, f.proof(t, "jti-authenticated", http.MethodPost), dpopGateSecret)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := f.marks.marks.Load(); got != 1 {
		t.Fatalf("consumed-jti writes = %d, want 1; the proof must still be marked single-use", got)
	}
}

// TestDeviceAuthorization_ReplayedProofStillRejected pins the property
// the deferral is only allowed to preserve: a second authenticated use
// of the same proof is refused.
func TestDeviceAuthorization_ReplayedProofStillRejected(t *testing.T) {
	t.Parallel()

	f := newDPoPWriteGateFixture(t)
	proof := f.proof(t, "jti-replayed", http.MethodPost)

	first := f.post(t, proof, dpopGateSecret)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200; body = %s", first.Code, first.Body.String())
	}

	second := f.post(t, proof, dpopGateSecret)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("second status = %d, want 400; body = %s", second.Code, second.Body.String())
	}
	code, description := decodeDPoPEnvelope(t, second)
	if code != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", code)
	}
	if description != "DPoP proof replayed" {
		t.Errorf("error_description = %q, want %q", description, "DPoP proof replayed")
	}
}

// TestDeviceAuthorization_EmptyLeadingDPoPValueDoesNotDowngradeToBearer
// drives the presence test with a "DPoP" header whose first value is
// empty and whose second carries a real proof. A presence test that
// reads only the first value reports "no proof" and issues an unbound
// device_code, silently dropping the sender constraint the client asked
// for. RFC 9449 §4.1 allows exactly one proof, so the request is
// refused instead.
func TestDeviceAuthorization_EmptyLeadingDPoPValueDoesNotDowngradeToBearer(t *testing.T) {
	t.Parallel()

	f := newDPoPWriteGateFixture(t)
	rec := f.postProofValues(t, dpopGateSecret, "", f.proof(t, "jti-empty-leading", http.MethodPost))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	code, description := decodeDPoPEnvelope(t, rec)
	if code != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", code)
	}
	if description != "DPoP proof malformed" {
		t.Errorf("error_description = %q, want %q", description, "DPoP proof malformed")
	}
	if got := f.marks.marks.Load(); got != 0 {
		t.Errorf("consumed-jti writes = %d, want 0; a rejected proof must not be marked", got)
	}
}

// TestDeviceAuthorization_InvalidProofRejectedBeforeClientAuthentication
// pins the other half of the ordering: the proof gate still runs first,
// so a request whose proof does not bind to it is faulted on the proof
// even when the credentials would also have failed.
func TestDeviceAuthorization_InvalidProofRejectedBeforeClientAuthentication(t *testing.T) {
	t.Parallel()

	f := newDPoPWriteGateFixture(t)
	rec := f.post(t, f.proof(t, "jti-bad-htm", http.MethodGet), "wrong-secret")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	code, description := decodeDPoPEnvelope(t, rec)
	if code != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request (client authentication answered first)", code)
	}
	if description != "DPoP proof does not bind to this request" {
		t.Errorf("error_description = %q, want the request-binding failure", description)
	}
	if got := f.marks.marks.Load(); got != 0 {
		t.Fatalf("consumed-jti writes = %d, want 0; a rejected proof must not be marked", got)
	}
}
