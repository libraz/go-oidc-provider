// White-box tests for the JARM encrypt-after-sign splice. The cases
// drive [jarmEmitSuccess] / [jarmEmitError] (and their public
// wrappers [emitAuthorizeSuccess] / [emitAuthorizeError]) directly so
// the assertions can inspect the wire shape (3-segment JWS vs
// 5-segment JWE) without booting the full HTTP harness.
//
//nolint:testpackage // intentional white-box test for unexported splice helpers.
package authorizeendpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/jarm"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// stubClientStore is the minimal [store.ClientStore] implementation
// the splice tests need: a single id → client mapping with no fancier
// shape than a map lookup. The struct lives in this file (not the
// _test.go siblings) because the splice tests run in the
// authorizeendpoint package itself for white-box access.
type stubClientStore struct {
	clients map[string]*store.Client
}

func (s *stubClientStore) GetClient(_ context.Context, id string) (*store.Client, error) {
	if c, ok := s.clients[id]; ok {
		return c, nil
	}
	return nil, store.ErrNotFound
}

// jarmTestFixture bundles the per-test setup so each table row can
// drive [emitAuthorizeSuccess] / [emitAuthorizeError] without
// repeating the signer / resolver / store wiring. Tests construct it
// once via [newJARMTestFixture] and then mutate per case (the client's
// encryption metadata, in particular).
type jarmTestFixture struct {
	signer   *jarm.Signer
	resolver *clientencjwks.Resolver
	store    *stubClientStore
	rsaKey   *rsa.PrivateKey
	clientID string
}

// fixedJARMClock returns a deterministic clock so JARM "exp" / "iat"
// computation is reproducible across test runs.
type fixedJARMClock struct{ now time.Time }

func (f fixedJARMClock) Now() time.Time { return f.now }

func newJARMTestFixture(t *testing.T, withEncMetadata, withEncKey bool) *jarmTestFixture {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	signer, err := jarm.NewSigner(jarm.SignerConfig{
		Key:    tokens.SigningKey{KeyID: "op-jarm-kid", Signer: priv},
		Issuer: "https://op.example.com",
		Clock:  fixedJARMClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatalf("jarm.NewSigner: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	const cid = "rp-jarm"
	client := &store.Client{
		ID:           cid,
		RedirectURIs: []string{"https://rp.example.com/callback"},
		Scopes:       []string{"openid"},
	}
	if withEncMetadata {
		client.AuthorizationEncryptedResponseAlg = "RSA-OAEP-256"
		client.AuthorizationEncryptedResponseEnc = "A256GCM"
	}
	if withEncKey {
		jwk := josev4.JSONWebKey{
			Key:       &rsaKey.PublicKey,
			KeyID:     "rp-enc-1",
			Use:       "enc",
			Algorithm: "RSA-OAEP-256",
		}
		body, mErr := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{jwk}})
		if mErr != nil {
			t.Fatalf("marshal jwks: %v", mErr)
		}
		client.JWKs = body
	}

	return &jarmTestFixture{
		signer:   signer,
		resolver: clientencjwks.New(clientencjwks.Config{}),
		store: &stubClientStore{clients: map[string]*store.Client{
			cid: client,
		}},
		rsaKey:   rsaKey,
		clientID: cid,
	}
}

// resolved returns the [resolved] view the splice helpers consume.
// All four production fields used on the JARM emit path are populated;
// the rest are left at zero value because the splice does not touch
// them.
func (f *jarmTestFixture) resolved() resolved {
	return resolved{Deps: Deps{
		Clients:       f.store,
		JARM:          f.signer,
		ClientEncJWKs: f.resolver,
		Issuer:        "https://op.example.com",
	}}
}

// authorizeRequest returns a canonical JARM /authorize request with
// the supplied response_mode.
func (f *jarmTestFixture) authorizeRequest(mode string) *authorize.Request {
	return &authorize.Request{
		ClientID:     f.clientID,
		ResponseType: "code",
		RedirectURI:  "https://rp.example.com/callback",
		ResponseMode: mode,
		State:        "state-abc",
	}
}

// extractResponseFromQuery pulls the "response" query-string parameter
// from a 302 Location header. The helper fails the test on any
// missing piece so call sites stay focused on the assertion under
// test.
func extractResponseFromQuery(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatal("Location header missing")
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", loc, err)
	}
	got := u.Query().Get("response")
	if got == "" {
		t.Fatalf("response missing in Location=%s", loc)
	}
	return got
}

// dispatchSuccess runs [emitAuthorizeSuccess] against the supplied
// fixture / request and returns the recorded response.
func dispatchSuccess(f *jarmTestFixture, req *authorize.Request, code string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize", nil)
	emitAuthorizeSuccess(w, r, f.resolved(), req, code)
	return w
}

// dispatchError runs [emitAuthorizeError] against the supplied
// fixture / request and returns the recorded response.
func dispatchError(f *jarmTestFixture, req *authorize.Request, code, description string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize", nil)
	emitAuthorizeError(w, r, f.resolved(), req, code, description)
	return w
}

func TestJARMEncrypt_NoMetadata_EmitsSignedJWS(t *testing.T) {
	t.Parallel()

	f := newJARMTestFixture(t, false, false)
	req := f.authorizeRequest("query.jwt")
	w := dispatchSuccess(f, req, "code-1")

	got := extractResponseFromQuery(t, w)
	if segs := strings.Count(got, "."); segs != 2 {
		t.Fatalf("response param: want 3-segment JWS (2 dots), got %d dots in %q", segs, got)
	}
}

func TestJARMEncrypt_WithMetadataAndKey_EmitsNestedJWE(t *testing.T) {
	t.Parallel()

	f := newJARMTestFixture(t, true, true)
	req := f.authorizeRequest("query.jwt")
	w := dispatchSuccess(f, req, "code-2")

	got := extractResponseFromQuery(t, w)
	if segs := strings.Count(got, "."); segs != 4 {
		t.Fatalf("response param: want 5-segment JWE (4 dots), got %d dots in %q", segs, got)
	}

	// Decrypt and verify the inner JWS.
	parsed, err := josev4.ParseEncrypted(got,
		[]josev4.KeyAlgorithm{josev4.RSA_OAEP_256},
		[]josev4.ContentEncryption{josev4.A256GCM})
	if err != nil {
		t.Fatalf("ParseEncrypted: %v", err)
	}
	if cty, ok := parsed.Header.ExtraHeaders[josev4.HeaderContentType]; !ok || cty != "JWT" {
		t.Errorf("inner cty=%v want JWT (extra=%v)", cty, parsed.Header.ExtraHeaders)
	}
	plaintext, err := parsed.Decrypt(f.rsaKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	innerJWS := string(plaintext)
	if segs := strings.Count(innerJWS, "."); segs != 2 {
		t.Fatalf("inner JWS: want 2 dots, got %d in %q", segs, innerJWS)
	}
	// The inner JWS must carry the canonical JARM claims (we don't
	// re-verify the signature here — the JARM encoder tests cover
	// that — but we do confirm payload shape).
	parts := strings.Split(innerJWS, ".")
	payload, err := decodeBase64URLSegment(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if uErr := json.Unmarshal(payload, &claims); uErr != nil {
		t.Fatalf("unmarshal claims: %v", uErr)
	}
	if claims["code"] != "code-2" {
		t.Errorf("claims[code]=%v want code-2", claims["code"])
	}
	if claims["state"] != "state-abc" {
		t.Errorf("claims[state]=%v want state-abc", claims["state"])
	}
	if claims["aud"] != f.clientID {
		t.Errorf("claims[aud]=%v want %s", claims["aud"], f.clientID)
	}
}

func TestJARMEncrypt_MetadataButNoEncKey_SuccessFallsBackToServerError(t *testing.T) {
	t.Parallel()

	// Client registered alg/enc but JWKs is empty: ResolveRecipient
	// surfaces ErrJWKSConfigured. Per the documented success-path
	// policy, the splice MUST NOT downgrade to a plain "?code=..."
	// redirect (that would leak the code through a channel the client
	// contracted out of). Instead it emits server_error.
	f := newJARMTestFixture(t, true, false)
	req := f.authorizeRequest("query.jwt")
	w := dispatchSuccess(f, req, "code-3")

	if w.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	q := loc.Query()
	if got := q.Get("error"); got != "server_error" {
		t.Errorf("error=%q want server_error", got)
	}
	if got := q.Get("error_description"); got != "jarm_response_encryption_failed" {
		t.Errorf("error_description=%q want jarm_response_encryption_failed", got)
	}
	if got := q.Get("code"); got != "" {
		t.Errorf("code leaked on encryption-failure path: %q (Location=%s)", got, loc.String())
	}
	if got := q.Get("response"); got != "" {
		t.Errorf("response param leaked on encryption-failure path: %q", got)
	}
	if got := q.Get("state"); got != "state-abc" {
		t.Errorf("state=%q want state-abc", got)
	}
}

func TestJARMEncrypt_MetadataButNoEncKey_ErrorFallsBackToSignedOnly(t *testing.T) {
	t.Parallel()

	// Same misconfiguration as the success-path case, but on the
	// error path the splice's policy is to emit the original
	// signed-only JARM error response. The error itself is a failure
	// path; signing without encryption preserves authenticity at the
	// cost of confidentiality of the error code, which is a strictly
	// better fallback than stranding the user on a second
	// server_error.
	f := newJARMTestFixture(t, true, false)
	req := f.authorizeRequest("query.jwt")
	w := dispatchError(f, req, "invalid_scope", "scope rejected")

	got := extractResponseFromQuery(t, w)
	if segs := strings.Count(got, "."); segs != 2 {
		t.Fatalf("response param: want 3-segment JWS (signed-only fallback), got %d dots in %q", segs, got)
	}
	// Confirm the signed-only error JWT carries the error claim
	// (defence against "did we accidentally encrypt-and-strip?").
	parts := strings.Split(got, ".")
	payload, err := decodeBase64URLSegment(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if uErr := json.Unmarshal(payload, &claims); uErr != nil {
		t.Fatalf("unmarshal claims: %v", uErr)
	}
	if claims["error"] != "invalid_scope" {
		t.Errorf("claims[error]=%v want invalid_scope", claims["error"])
	}
}

func TestJARMEncrypt_NonJARMResponseMode_IgnoresEncryptionMetadata(t *testing.T) {
	t.Parallel()

	// Client registered encryption metadata but the request did not
	// opt into JARM. The splice MUST NOT engage: encryption is JARM-
	// scoped, and a legacy response_mode means the OP emits the
	// classic "?code=..." redirect verbatim.
	f := newJARMTestFixture(t, true, true)
	req := f.authorizeRequest("") // empty == legacy default for response_type=code
	w := dispatchSuccess(f, req, "code-4")

	if w.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	q := loc.Query()
	if got := q.Get("code"); got != "code-4" {
		t.Errorf("code=%q want code-4", got)
	}
	if got := q.Get("response"); got != "" {
		t.Errorf("response param leaked on legacy redirect: %q", got)
	}
	if got := q.Get("state"); got != "state-abc" {
		t.Errorf("state=%q want state-abc", got)
	}
}

// decodeBase64URLSegment decodes a single base64url-encoded JWS
// segment without padding. The helper is local to this file so the
// splice tests do not depend on the jose package's unexported shape.
func decodeBase64URLSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
