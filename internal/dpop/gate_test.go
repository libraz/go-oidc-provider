package dpop_test

// The Gate is the single implementation of the DPoP request lifecycle
// every proof-accepting endpoint drives: presence test → stateless
// verification → client authentication → replay commit → wire mapping.
// The cases here own the lifecycle properties, so an endpoint test only
// has to assert that it reaches the gate.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

// gateNow is the deterministic clock anchor every gate case verifies
// against; the proofs carry the same "iat".
var gateNow = time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

// gateEndpoint is the request target every gate case POSTs to. The
// identifier deliberately avoids naming the token endpoint: gosec's
// hardcoded-credential pattern matches a "Token" in the name and would
// fault this URL as a secret.
const gateEndpoint = "https://op.example/oidc/token"

// gateFixture bundles a gate with the replay store behind it, so a case
// can assert on the durable write the commit phase performs rather than
// on call order.
type gateFixture struct {
	gate dpop.Gate
	jtis *memJTIStore
}

func newGateFixture(t testing.TB) gateFixture {
	t.Helper()
	jtis := newMemJTIStore()
	v, err := dpop.NewVerifier(dpop.VerifierConfig{JTIs: jtis, Clock: fixedClock{now: gateNow}})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return gateFixture{gate: dpop.Gate{Verifier: v}, jtis: jtis}
}

// gateProof signs a proof bound to a POST at [gateEndpoint].
func gateProof(t testing.TB, jti string) string {
	t.Helper()
	claims := goodClaims(gateNow)
	claims["jti"] = jti
	claims["htu"] = gateEndpoint
	return signProof(t, newES256Key(t), claims, "")
}

// gateRequest builds the POST the gate verifies, carrying one "DPoP"
// header value per entry in proofs (none for a bearer request).
func gateRequest(t testing.TB, proofs ...string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, gateEndpoint, http.NoBody)
	for _, p := range proofs {
		req.Header.Add("DPoP", p)
	}
	return req
}

// gateErrorEnvelope decodes the OAuth error envelope the gate writes.
func gateErrorEnvelope(t testing.TB, rec *httptest.ResponseRecorder) (code, description string) {
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

func TestGateAuthenticate_NilVerifier_AdmitsRequestWithoutProof(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	authenticated := false
	// A proof rides along, but the feature is off: the gate must not
	// look at it, and the caller gets the bearer-path nil proof.
	checked, ok := dpop.Gate{}.Authenticate(context.Background(), rec, gateRequest(t, gateProof(t, "jti-off")),
		func() bool { authenticated = true; return true })
	if !ok {
		t.Fatalf("ok=false, want true (a nil verifier disables DPoP)")
	}
	if !authenticated {
		t.Error("the authenticate callback did not run")
	}
	if checked != nil {
		t.Errorf("checked=%+v, want nil", checked)
	}
	if got := checked.Thumbprint(); got != "" {
		t.Errorf("Thumbprint()=%q, want empty", got)
	}
}

func TestGateAuthenticate_NoProofHeader_AdmitsRequestOnBearerPath(t *testing.T) {
	t.Parallel()
	f := newGateFixture(t)
	rec := httptest.NewRecorder()
	authenticated := false
	checked, ok := f.gate.Authenticate(context.Background(), rec, gateRequest(t),
		func() bool { authenticated = true; return true })
	if !ok || !authenticated {
		t.Fatalf("ok=%v authenticated=%v, want true/true", ok, authenticated)
	}
	if checked != nil {
		t.Errorf("checked=%+v, want nil (no proof was presented)", checked)
	}
	if got := f.jtis.len(); got != 0 {
		t.Errorf("replay markers=%d, want 0", got)
	}
}

func TestGateAuthenticate_ValidProof_CommitsAfterAuthenticate(t *testing.T) {
	t.Parallel()
	f := newGateFixture(t)
	rec := httptest.NewRecorder()
	marksDuringAuth := -1
	checked, ok := f.gate.Authenticate(context.Background(), rec, gateRequest(t, gateProof(t, "jti-happy")),
		func() bool {
			// The replay marker is the endpoint's only durable write
			// on this path, and it must not exist yet: an
			// unauthenticated request rate would otherwise translate
			// into storage cost.
			marksDuringAuth = f.jtis.len()
			return true
		})
	if !ok {
		t.Fatalf("ok=false (body=%s)", rec.Body.String())
	}
	if checked.Thumbprint() == "" {
		t.Error("Thumbprint() is empty, want the proof's jkt")
	}
	if marksDuringAuth != 0 {
		t.Errorf("replay markers during authentication=%d, want 0 (commit must run last)", marksDuringAuth)
	}
	if got := f.jtis.len(); got != 1 {
		t.Errorf("replay markers after Authenticate=%d, want 1", got)
	}
}

func TestGateAuthenticate_AuthenticateRejects_LeavesProofUnmarked(t *testing.T) {
	t.Parallel()
	f := newGateFixture(t)
	rec := httptest.NewRecorder()
	_, ok := f.gate.Authenticate(context.Background(), rec, gateRequest(t, gateProof(t, "jti-unauthenticated")),
		func() bool { return false })
	if ok {
		t.Fatal("ok=true, want false when authentication fails")
	}
	if got := f.jtis.len(); got != 0 {
		t.Errorf("replay markers=%d, want 0; a request that cannot authenticate must not burn its proof", got)
	}
}

func TestGateAuthenticate_InvalidProof_RejectsBeforeAuthenticating(t *testing.T) {
	t.Parallel()
	f := newGateFixture(t)
	rec := httptest.NewRecorder()
	// The proof binds to a different URL, so the §4.3 htu gate fails.
	claims := goodClaims(gateNow)
	claims["htu"] = "https://op.example/oidc/userinfo"
	proof := signProof(t, newES256Key(t), claims, "")

	authenticated := false
	_, ok := f.gate.Authenticate(context.Background(), rec, gateRequest(t, proof),
		func() bool { authenticated = true; return true })
	if ok {
		t.Fatal("ok=true, want false for a proof that does not bind to the request")
	}
	if authenticated {
		t.Error("the authenticate callback ran; verification must answer first")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
	code, description := gateErrorEnvelope(t, rec)
	if code != "invalid_request" {
		t.Errorf("error=%q, want invalid_request", code)
	}
	if description != "DPoP proof does not bind to this request" {
		t.Errorf("error_description=%q, want the request-binding failure", description)
	}
}

func TestGateAuthenticate_ReplayedProof_RejectsOnCommit(t *testing.T) {
	t.Parallel()
	f := newGateFixture(t)
	proof := gateProof(t, "jti-replayed")
	accept := func() bool { return true }

	first := httptest.NewRecorder()
	if _, ok := f.gate.Authenticate(context.Background(), first, gateRequest(t, proof), accept); !ok {
		t.Fatalf("first Authenticate failed (body=%s)", first.Body.String())
	}

	second := httptest.NewRecorder()
	if _, ok := f.gate.Authenticate(context.Background(), second, gateRequest(t, proof), accept); ok {
		t.Fatal("second Authenticate succeeded; a proof is single-use")
	}
	code, description := gateErrorEnvelope(t, second)
	if code != "invalid_request" {
		t.Errorf("error=%q, want invalid_request", code)
	}
	if description != "DPoP proof replayed" {
		t.Errorf("error_description=%q, want %q", description, "DPoP proof replayed")
	}
}

// TestGateAuthenticate_EmptyLeadingProofValue_DoesNotFallThroughToBearer
// pins the presence test against the shape that defeats a value-content
// check: a first "DPoP" header value that is empty, followed by a real
// proof. Reading only the first value would report "no proof" and admit
// the request onto the unbound bearer path — a silent downgrade of the
// sender-constraint the client asked for. RFC 9449 §4.1 allows exactly
// one proof, so the correct answer is a rejection.
func TestGateAuthenticate_EmptyLeadingProofValue_DoesNotFallThroughToBearer(t *testing.T) {
	t.Parallel()
	f := newGateFixture(t)
	rec := httptest.NewRecorder()
	authenticated := false
	checked, ok := f.gate.Authenticate(context.Background(), rec,
		gateRequest(t, "", gateProof(t, "jti-empty-leading")),
		func() bool { authenticated = true; return true })
	if ok {
		t.Fatalf("ok=true with checked=%+v; the request was admitted without a verified proof", checked)
	}
	if authenticated {
		t.Error("the authenticate callback ran; the multi-value header must be refused first")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
	code, description := gateErrorEnvelope(t, rec)
	if code != "invalid_request" {
		t.Errorf("error=%q, want invalid_request", code)
	}
	if description != "DPoP proof malformed" {
		t.Errorf("error_description=%q, want %q", description, "DPoP proof malformed")
	}
}

// TestGateAuthenticate_SoleEmptyProofValue_IsNotAbsent covers the
// degenerate half of the same shape: a single empty "DPoP" header is a
// presented-but-unparseable proof, not an absent one.
func TestGateAuthenticate_SoleEmptyProofValue_IsNotAbsent(t *testing.T) {
	t.Parallel()
	f := newGateFixture(t)
	rec := httptest.NewRecorder()
	if _, ok := f.gate.Authenticate(context.Background(), rec, gateRequest(t, ""),
		func() bool { return true }); ok {
		t.Fatal("ok=true; an empty DPoP header must not read as a bearer request")
	}
	if code, _ := gateErrorEnvelope(t, rec); code != "invalid_request" {
		t.Errorf("error=%q, want invalid_request", code)
	}
}

func TestHasProof(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		values []string
		want   bool
	}{
		{name: "no header", values: nil, want: false},
		{name: "one proof", values: []string{"proof"}, want: true},
		{name: "sole empty value", values: []string{""}, want: true},
		{name: "empty value then proof", values: []string{"", "proof"}, want: true},
		{name: "two proofs", values: []string{"proof-a", "proof-b"}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := dpop.HasProof(gateRequest(t, tc.values...)); got != tc.want {
				t.Errorf("HasProof()=%v, want %v", got, tc.want)
			}
		})
	}
	if dpop.HasProof(nil) {
		t.Error("HasProof(nil)=true, want false")
	}
}
