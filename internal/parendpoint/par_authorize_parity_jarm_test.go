package parendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// Whether a JARM response_mode is usable is decided by the OP's
// configuration and the pushed parameters alone — no session, no
// interaction state — so it belongs to the class of rules /par and
// /authorize MUST answer identically. The two failure modes this file
// pins are the ones that strand an RP: a request_uri minted for a
// response shape the OP cannot produce, and one minted for a request the
// active profile forbids. In both cases the RP spends its one-time value
// (RFC 9126 §2.2) only to be refused after the browser has already left,
// which is exactly what pushing was supposed to avoid — the RP asked for
// the synchronous JSON envelope (§2.3) so it could learn about a
// misconfiguration up front.
//
// Each test therefore asserts three things: the two endpoints agree, the
// verdict is the expected one, and /par persisted nothing on the way to
// its rejection.

// parSaveRecorder is a [store.Store] that remembers every PAR record the
// OP asked it to persist. It exists so a test can assert the negative —
// that a rejected push wrote nothing — which the wire response alone
// cannot show: a handler that persisted first and rejected afterwards
// would look identical from outside.
type parSaveRecorder struct {
	store.Store
	pars *recordingPARStore
}

// newParSaveRecorder wraps inner. The inner store MUST be transactional
// because the authorization endpoint commits code emission, grant
// upserts, and PAR consumption in one transaction.
func newParSaveRecorder(tb testing.TB, inner store.Store) *parSaveRecorder {
	tb.Helper()
	if _, ok := inner.(store.Transactional); !ok {
		tb.Fatalf("inner store %T is not transactional", inner)
	}
	return &parSaveRecorder{
		Store: inner,
		pars:  &recordingPARStore{PushedAuthRequestStore: inner.PushedAuthRequests()},
	}
}

func (s *parSaveRecorder) PushedAuthRequests() store.PushedAuthRequestStore { return s.pars }

// BeginTx forwards to the inner store. The transactional handle carries
// its own PAR substore, which the recorder does not observe: /par writes
// outside any transaction, so every record the endpoint mints passes
// through [recordingPARStore].
func (s *parSaveRecorder) BeginTx(ctx context.Context) (store.Tx, error) {
	return s.Store.(store.Transactional).BeginTx(ctx) //nolint:forcetypeassert // checked in newParSaveRecorder.
}

// saved returns the request_uri values persisted so far.
func (s *parSaveRecorder) saved() []string { return s.pars.snapshot() }

type recordingPARStore struct {
	store.PushedAuthRequestStore
	mu   sync.Mutex
	uris []string
}

func (s *recordingPARStore) Save(ctx context.Context, par *store.PushedAuthRequest) error {
	s.mu.Lock()
	s.uris = append(s.uris, par.URI)
	s.mu.Unlock()
	return s.PushedAuthRequestStore.Save(ctx, par)
}

func (s *recordingPARStore) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.uris...)
}

// jarmParityFixture pairs a provider whose store is observable with the
// signing material the FAPI 2.0 Message Signing configuration needs.
// The plain (non-profile) configuration leaves priv / kid unused.
type jarmParityFixture struct {
	*fixture
	recorder *parSaveRecorder
	inner    *inmem.Store
	client   *store.Client
	secret   string
	priv     *ecdsa.PrivateKey
	kid      string
}

// newRecorderProvider builds a testkit provider over a store the test can
// observe. The provider's own [testkit.Provider.Store] is left unused;
// clients are registered through the returned inner store so the OP and
// the test agree about the registry.
func newRecorderProvider(tb testing.TB, clock fixedClock, opts ...op.Option) (*testkit.Provider, *parSaveRecorder, *inmem.Store) {
	tb.Helper()
	inner := inmem.New(inmem.WithClock(clock))
	recorder := newParSaveRecorder(tb, inner)
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(append([]op.Option{op.WithStore(recorder)}, opts...)...),
	)
	return prov, recorder, inner
}

// newJARMOffParityFixture builds a PAR-enabled OP with no JARM signer:
// [feature.JARM] is deliberately absent so the four JARM response_mode
// values name a response shape this OP cannot produce.
func newJARMOffParityFixture(tb testing.TB) *jarmParityFixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov, recorder, inner := newRecorderProvider(tb, clock, op.WithFeature(feature.PAR))
	client, secret := registerParitySecretClient(tb, inner)
	return &jarmParityFixture{
		fixture:  &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/par", clock: clock},
		recorder: recorder,
		inner:    inner,
		client:   client,
		secret:   secret,
	}
}

// registerParitySecretClient seeds a client_secret_basic client directly
// on the store the OP reads, returning it alongside the plain secret.
func registerParitySecretClient(tb testing.TB, st *inmem.Store) (*store.Client, string) {
	tb.Helper()
	const secret = "parity-jarm-secret" //nolint:gosec // test fixture, not a real credential.
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Hash: %v", err)
	}
	client := &store.Client{
		ID:                      "client-parity-jarm",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
	}
	if err := st.RegisterClient(context.Background(), client); err != nil {
		tb.Fatalf("RegisterClient: %v", err)
	}
	return client, secret
}

// TestPARAuthorizeParity_JARMModeWithoutSignerMintsNothing drives a
// request that asks for a JARM response_mode at an OP that has no JARM
// signer. Both endpoints must refuse it with unsupported_response_mode,
// and /par must refuse it without minting a request_uri: a record here
// is a one-time value the RP would spend on a request /authorize is
// certain to reject.
func TestPARAuthorizeParity_JARMModeWithoutSignerMintsNothing(t *testing.T) {
	t.Parallel()

	f := newJARMOffParityFixture(t)
	form := parityForm(f.client.ID, f.client.RedirectURIs[0], map[string]string{"response_mode": "jwt"})

	atPAR := parVerdict(t, f.fixture, f.client.ID, f.secret, form)
	atAuthorize := authorizeVerdict(t, f.fixture, form)
	if atPAR != atAuthorize {
		t.Fatalf("/par %s but /authorize %s; the RP would spend its one-time request_uri on a request /authorize refuses",
			atPAR, atAuthorize)
	}
	if want := (verdict{errCode: "unsupported_response_mode"}); atPAR != want {
		t.Errorf("both endpoints %s, want %s", atPAR, want)
	}
	if minted := f.recorder.saved(); len(minted) != 0 {
		t.Errorf("/par persisted %d record(s) %v for a request it refused", len(minted), minted)
	}
}

// TestPARAuthorizeParity_MessageSigningWithoutJARMModeMintsNothing is the
// mirror image: the OP has JARM and the profile requires every
// authorization response to be JARM-wrapped (FAPI 2.0 Message Signing
// §5.5), so a request that omits response_mode is the one that cannot be
// served. The control row pushes the identical request object with
// response_mode=jwt and follows the minted request_uri through
// /authorize, which pins that the rejection is attributable to the
// response_mode and not to some other rule the profile imposes.
func TestPARAuthorizeParity_MessageSigningWithoutJARMModeMintsNothing(t *testing.T) {
	t.Parallel()

	f := newMessageSigningParityFixture(t)

	// Control: with a JARM response_mode the push is accepted and the
	// minted request_uri carries the request through /authorize.
	control := f.requestObjectClaims()
	control["response_mode"] = "jwt"
	atPAR, requestURI := f.push(t, control)
	if want := (verdict{accepted: true}); atPAR != want {
		t.Fatalf("control push %s, want %s; the fixture cannot exercise the gate", atPAR, want)
	}
	if atAuthorize := f.authorize(t, requestURI); atAuthorize != atPAR {
		t.Fatalf("control: /par %s but /authorize %s", atPAR, atAuthorize)
	}
	before := len(f.recorder.saved())

	// The same request without response_mode: the profile forbids the
	// plain response shape it would take.
	atPAR, requestURI = f.push(t, f.requestObjectClaims())
	if requestURI != "" {
		atAuthorize := f.authorize(t, requestURI)
		if atPAR != atAuthorize {
			t.Fatalf("/par %s but /authorize %s; the RP spent its one-time request_uri on a request /authorize refuses",
				atPAR, atAuthorize)
		}
	}
	if want := (verdict{errCode: "unsupported_response_mode"}); atPAR != want {
		t.Errorf("/par %s, want %s", atPAR, want)
	}
	if minted := f.recorder.saved()[before:]; len(minted) != 0 {
		t.Errorf("/par persisted %d record(s) %v for a request it refused", len(minted), minted)
	}
}

// newMessageSigningParityFixture builds an OP under
// [profile.FAPI2MessageSigning]. The profile auto-enables PAR / JAR /
// JARM; DPoP plus a nonce source satisfy the disjunctive
// sender-constrained-token requirement (FAPI 2.0 §3.1.4 / §5.3.4). The
// client authenticates with private_key_jwt and signs its request
// objects with the same key, which is what the profile admits.
func newMessageSigningParityFixture(tb testing.TB) *jarmParityFixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov, recorder, inner := newRecorderProvider(tb, clock,
		op.WithProfile(profile.FAPI2MessageSigning),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(staticDPoPNonces{}),
	)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("GenerateKey: %v", err)
	}
	const kid = "rp-parity-ms"
	jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key:       &priv.PublicKey,
		KeyID:     kid,
		Algorithm: string(josev4.ES256),
		Use:       "sig",
	}}})
	if err != nil {
		tb.Fatalf("Marshal JWKS: %v", err)
	}
	//nolint:gosec // G101: "private_key_jwt" is the auth-method name, not a credential.
	client := &store.Client{
		ID:                      "client-parity-ms",
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKs:                    jwks,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
	}
	if err := inner.RegisterClient(context.Background(), client); err != nil {
		tb.Fatalf("RegisterClient: %v", err)
	}
	return &jarmParityFixture{
		fixture:  &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/par", clock: clock},
		recorder: recorder,
		inner:    inner,
		client:   client,
		priv:     priv,
		kid:      kid,
	}
}

// staticDPoPNonces is the RFC 9449 §8 nonce source the profile requires
// the OP to wire. The bound tests present no DPoP proof, so the value
// only has to be stable.
type staticDPoPNonces struct{}

func (staticDPoPNonces) IssueNonce() string         { return "parity-nonce" }
func (staticDPoPNonces) Validate(nonce string) bool { return nonce == "parity-nonce" }

// requestObjectClaims returns the canonical signed-request-object claim
// set, deliberately without a response_mode so callers add the one the
// row is about.
func (f *jarmParityFixture) requestObjectClaims() map[string]any {
	_, challenge := pkcePair()
	return map[string]any{
		"iss":                   f.client.ID,
		"aud":                   f.prov.Issuer,
		"exp":                   f.clock.now.Add(5 * time.Minute).Unix(),
		"iat":                   f.clock.now.Unix(),
		"nbf":                   f.clock.now.Unix(),
		"jti":                   freshJTI(),
		"client_id":             f.client.ID,
		"response_type":         "code",
		"redirect_uri":          f.client.RedirectURIs[0],
		"scope":                 "openid profile email",
		"state":                 "parity-ms-state",
		"nonce":                 "parity-ms-nonce",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}
}

// push signs claims into a request object, POSTs it at /par with a
// private_key_jwt assertion, and reduces the response to a [verdict]
// plus the minted request_uri ("" on a rejection).
func (f *jarmParityFixture) push(tb testing.TB, claims map[string]any) (verdict, string) {
	tb.Helper()
	form := url.Values{
		"client_id":             {f.client.ID},
		"request":               {f.signES256(tb, claims, "oauth-authz-req+jwt")},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {f.clientAssertion(tb)},
	}
	resp := postPARForm(tb, f.prov.HTTPClient(nil), f.endpoint, form, "", "")
	defer resp.Body.Close()
	body := decodeJSON(tb, resp)
	if resp.StatusCode == http.StatusCreated {
		uri, _ := body["request_uri"].(string)
		if uri == "" {
			tb.Fatalf("/par 201 carried no request_uri: %v", body)
		}
		return verdict{accepted: true}, uri
	}
	code, _ := body["error"].(string)
	if code == "" {
		tb.Fatalf("/par status=%d carried no error code: %v", resp.StatusCode, body)
	}
	return verdict{errCode: code}, ""
}

// authorize presents the minted request_uri at /authorize and reduces
// the response to a [verdict].
func (f *jarmParityFixture) authorize(tb testing.TB, requestURI string) verdict {
	tb.Helper()
	resp := getAuthorize(tb, f.prov, f.client.ID, requestURI)
	defer resp.Body.Close()
	return authorizeResponseVerdict(tb, resp)
}

// clientAssertion mints the private_key_jwt credential. The audience is
// the issuer, which the verifier accepts alongside the token-endpoint
// URL.
func (f *jarmParityFixture) clientAssertion(tb testing.TB) string {
	tb.Helper()
	return f.signES256(tb, map[string]any{
		"iss": f.client.ID,
		"sub": f.client.ID,
		"aud": f.prov.Issuer,
		"jti": freshJTI(),
		"iat": f.clock.now.Unix(),
		"exp": f.clock.now.Add(2 * time.Minute).Unix(),
	}, "JWT")
}

// signES256 serialises claims as a compact ES256 JWS with the fixture's
// key under the supplied "typ" header.
func (f *jarmParityFixture) signES256(tb testing.TB, claims map[string]any, typ string) string {
	tb.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{
			Algorithm: josev4.ES256,
			Key: josev4.JSONWebKey{
				Key:       f.priv,
				KeyID:     f.kid,
				Algorithm: string(josev4.ES256),
				Use:       "sig",
			},
		},
		(&josev4.SignerOptions{}).WithType(josev4.ContentType(typ)),
	)
	if err != nil {
		tb.Fatalf("NewSigner ES256: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		tb.Fatalf("Serialize ES256: %v", err)
	}
	return out
}
