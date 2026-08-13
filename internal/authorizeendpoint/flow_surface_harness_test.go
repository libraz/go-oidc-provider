package authorizeendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// This file hosts the two-surface harness the authentication-freshness
// tests drive. The testkit cannot supply it: testkit.NewProvider
// pre-installs op.WithAuthenticators, which op.New rejects alongside
// op.WithLoginFlow, so a LoginFlow-configured Provider has to be built
// through op.New directly. Building both surfaces from one helper is
// what lets a test assert that the recommended seam (LoginFlow) and the
// legacy seam (Authenticators) reach the same verdict for the same
// request.

// authnSurface names the factor-configuration seam a Provider is built
// on. The freshness rules are surface-independent, so every test that
// covers one runs both.
type authnSurface int

const (
	// surfaceLoginFlow builds the Provider with op.WithLoginFlow.
	surfaceLoginFlow authnSurface = iota
	// surfaceAuthenticators builds it with op.WithAuthenticators.
	surfaceAuthenticators
)

func (s authnSurface) String() string {
	if s == surfaceLoginFlow {
		return "LoginFlow"
	}
	return "Authenticators"
}

// movableClock is an op.Clock whose reading the test advances between
// hops. Freshness assertions need it: with a frozen clock, an auth_time
// forged from the interaction's creation time is indistinguishable from
// an auth_time stamped when the credential was actually presented.
type movableClock struct {
	mu  sync.Mutex
	now time.Time
}

func newMovableClock(start time.Time) *movableClock {
	return &movableClock{now: start}
}

func (c *movableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *movableClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// passwordEchoAuthenticator is a test-only credential factor. It echoes
// whatever subject the submission carries — like
// testkit.SubjectAuthenticator — but reports op.FactorPassword so the
// aggregate produces amr ["pwd"]. Tests that assert "a credential was
// actually presented" need a non-nil amr to assert on, which the
// testkit authenticator's empty AMR cannot provide.
//
// Result.AuthTime is stamped from the fixture clock at Continue rather
// than echoed from ContinueInput.AuthTime (documented as the attempt's
// reference time, i.e. when the interaction record was created). The
// distinction is what gives an auth_time assertion any power: a chain
// that never ran a factor still carries the interaction's creation
// time, so echoing it back would make the honest and the forged value
// identical.
type passwordEchoAuthenticator struct {
	clock *movableClock
}

func (passwordEchoAuthenticator) Type() op.FactorType { return op.FactorPassword }
func (passwordEchoAuthenticator) AAL() op.AAL         { return op.AAL1 }
func (passwordEchoAuthenticator) AMR() string         { return "pwd" }
func (passwordEchoAuthenticator) Prompts() []string {
	return []string{testkit.SubjectPromptType}
}

func (passwordEchoAuthenticator) Begin(context.Context, op.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: &interaction.Prompt{
		Type: testkit.SubjectPromptType,
		Inputs: []interaction.FieldSpec{{
			Name:     testkit.SubjectFieldName,
			Kind:     interaction.FieldText,
			Required: true,
			MinLen:   1,
			MaxLen:   256,
		}},
	}}, nil
}

func (a passwordEchoAuthenticator) Continue(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
	sub, ok := in.Submission.Values[testkit.SubjectFieldName]
	if !ok || sub == "" {
		return interaction.Step{}, testkit.ErrSubjectMissing
	}
	confirmed := in.AuthTime
	if a.clock != nil {
		confirmed = a.clock.Now()
	}
	return interaction.Step{Result: &interaction.Result{Subject: sub, AuthTime: confirmed}}, nil
}

var _ op.Authenticator = passwordEchoAuthenticator{}

// flowFixture is the running Provider plus the handles a multi-hop
// browser test needs.
type flowFixture struct {
	server *httptest.Server
	store  *inmem.Store
	client *store.Client
	clock  *movableClock
	issuer string
	secret string
}

// httpClient returns a redirect-suppressing client that trusts the
// fixture's certificate, so each hop is inspected individually.
func (f *flowFixture) httpClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{
		Transport: f.server.Client().Transport,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newFlowFixture builds a Provider on the requested surface. Both
// surfaces get the same credential factor, the same clock, the same
// store and the same registered client, so a behavioural difference
// between them is a difference in the dispatch rules and nothing else.
func newFlowFixture(t *testing.T, surface authnSurface, clock *movableClock, extra ...op.Option) *flowFixture {
	t.Helper()
	st := inmem.New(inmem.WithClock(clock))

	const secret = "rp-flow-secret" // test fixture, not a real credential.
	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	rp := &store.Client{
		ID:                      "rp-flow",
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              hash,
	}
	if err := st.RegisterClient(context.Background(), rp); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	opts := []op.Option{
		op.WithIssuer(testkit.DefaultIssuer),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{newFlowSigningKey(t)}),
		op.WithCookieKeys(newFlowCookieKey(t)),
		op.WithInteractionDriver(testkit.AutoConsentDriver{}),
		op.WithClock(clock),
	}
	switch surface {
	case surfaceLoginFlow:
		opts = append(opts, op.WithLoginFlow(op.LoginFlow{
			Primary: op.ExternalStep{
				Authenticator: passwordEchoAuthenticator{clock: clock},
				KindLabel:     op.StepKind("test.primary"),
			},
		}))
	case surfaceAuthenticators:
		opts = append(opts, op.WithAuthenticators(passwordEchoAuthenticator{clock: clock}))
	}
	opts = append(opts, extra...)

	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New (%s): %v", surface, err)
	}
	srv := httptest.NewTLSServer(provider)
	t.Cleanup(srv.Close)

	return &flowFixture{
		server: srv,
		store:  st,
		client: rp,
		clock:  clock,
		issuer: testkit.DefaultIssuer,
		secret: secret,
	}
}

func newFlowSigningKey(tb testing.TB) op.SigningKey {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate signing key: %v", err)
	}
	return op.SigningKey{KeyID: "flow-sig-1", Signer: priv}
}

func newFlowCookieKey(tb testing.TB) []byte {
	tb.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		tb.Fatalf("generate cookie key: %v", err)
	}
	return key
}
