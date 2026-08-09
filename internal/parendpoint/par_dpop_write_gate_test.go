package parendpoint_test

// /par is reachable without a credential, so any durable write it
// performs before client authentication turns an attacker's request
// rate directly into storage cost. The DPoP replay marker (RFC 9449
// §11.1) is the only such write on the path: proof verification has to
// run first so the §8 use_dpop_nonce challenge fires before a
// client_assertion jti is consumed, but the marker itself does not.
//
// These tests drive the wire endpoint against an observable
// ConsumedJTIStore rather than inspecting call order, so they measure
// the property that matters (a write happened) instead of the shape of
// the code that produces it.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
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

// observedStore is the [store.Store] the OP under test is built on: the
// in-memory reference implementation with its consumed-jti substore
// wrapped by [countingJTIs].
type observedStore struct {
	*inmem.Store
	jtis *countingJTIs
}

func (s observedStore) ConsumedJTIs() store.ConsumedJTIStore { return s.jtis }

// dpopWriteGateFixture bundles a DPoP + PAR provider whose consumed-jti
// writes are observable, along with the confidential client the tests
// authenticate as.
type dpopWriteGateFixture struct {
	prov     *testkit.Provider
	endpoint string
	marks    *countingJTIs
	clock    fixedClock
	client   *store.Client
	secret   string
	key      *ecdsa.PrivateKey
	jwk      josev4.JSONWebKey
}

func newDPoPWriteGateFixture(tb testing.TB) *dpopWriteGateFixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	inner := inmem.New(inmem.WithClock(clock))
	observed := observedStore{
		Store: inner,
		jtis:  &countingJTIs{inner: inner.ConsumedJTIs()},
	}

	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := &store.Client{
		ID:                      "client-conf-dpop-par",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
	}
	// The provider is built on the wrapped store, so the client has to
	// be registered there rather than through the testkit's own handle.
	if rerr := inner.RegisterClient(context.Background(), client); rerr != nil {
		tb.Fatalf("RegisterClient: %v", rerr)
	}

	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithStore(observed),
			op.WithFeature(feature.PAR),
			op.WithFeature(feature.DPoP),
		),
	)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return &dpopWriteGateFixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/par",
		marks:    observed.jtis,
		clock:    clock,
		client:   client,
		secret:   secret,
		key:      priv,
		jwk:      josev4.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(josev4.ES256), Use: "sig"},
	}
}

// proof builds an RFC 9449 §4.2 proof for a POST to the fixture's /par
// endpoint. jti is explicit so a caller can choose whether two requests
// share one.
func (f *dpopWriteGateFixture) proof(tb testing.TB, jti string) string {
	tb.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: f.key},
		(&josev4.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", f.jwk),
	)
	if err != nil {
		tb.Fatalf("NewSigner: %v", err)
	}
	token, err := jwt.Signed(signer).Claims(map[string]any{
		"htm": http.MethodPost,
		"htu": f.endpoint,
		"iat": f.clock.now.Unix(),
		"jti": jti,
	}).Serialize()
	if err != nil {
		tb.Fatalf("Serialize: %v", err)
	}
	return token
}

// post submits the canonical authorization form with the supplied DPoP
// proof and Basic credentials. The request is built here rather than
// through the shared helper because the proof rides on a header the
// helper does not expose.
func (f *dpopWriteGateFixture) post(tb testing.TB, proof, basicSecret string) *http.Response {
	tb.Helper()
	form := goodAuthorizeForm(f.client.ID, f.client.RedirectURIs[0])
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		f.endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.client.ID, basicSecret)
	req.Header.Set("DPoP", proof)
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("POST /par: %v", err)
	}
	return resp
}

// TestPAR_UnauthenticatedDPoPRequestPerformsNoDurableWrite is the gate:
// a request carrying a perfectly valid proof but the wrong client
// secret must be refused without touching the consumed-jti table.
func TestPAR_UnauthenticatedDPoPRequestPerformsNoDurableWrite(t *testing.T) {
	t.Parallel()

	f := newDPoPWriteGateFixture(t)
	resp := f.post(t, f.proof(t, "jti-unauthenticated"), "wrong-secret")
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		t.Fatalf("status=201; the request authenticated with a wrong secret")
	}
	if got := f.marks.marks.Load(); got != 0 {
		t.Fatalf("consumed-jti writes=%d want 0; an unauthenticated request must not reach durable storage", got)
	}
}

// TestPAR_AuthenticatedDPoPRequestMarksProofOnce is the control: the
// deferral must not have removed the replay marker, only moved it
// behind the credential.
func TestPAR_AuthenticatedDPoPRequestMarksProofOnce(t *testing.T) {
	t.Parallel()

	f := newDPoPWriteGateFixture(t)
	resp := f.post(t, f.proof(t, "jti-authenticated"), f.secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d want 201 (body=%v)", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := f.marks.marks.Load(); got != 1 {
		t.Fatalf("consumed-jti writes=%d want 1; the proof must still be marked single-use", got)
	}
}

// TestPAR_ReplayedProofStillRejected pins the property the deferral is
// only allowed to preserve: a second authenticated use of the same
// proof is refused.
func TestPAR_ReplayedProofStillRejected(t *testing.T) {
	t.Parallel()

	f := newDPoPWriteGateFixture(t)
	proof := f.proof(t, "jti-replayed")

	first := f.post(t, proof, f.secret)
	defer first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first status=%d want 201 (body=%v)", first.StatusCode, decodeJSON(t, first))
	}

	second := f.post(t, proof, f.secret)
	defer second.Body.Close()
	if second.StatusCode == http.StatusCreated {
		t.Fatal("second status=201; a replayed DPoP proof must be refused")
	}
	body := decodeJSON(t, second)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
	if body["error_description"] != "DPoP proof replayed" {
		t.Errorf("error_description=%v want %q", body["error_description"], "DPoP proof replayed")
	}
}
