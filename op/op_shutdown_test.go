// Test file exercises the unexported back-channel coordinator handle
// that op.New records on the config.
//
//nolint:testpackage // exercises unexported config fields
package op

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// shutdownFixtureAuthenticator is the minimal [Authenticator] that
// satisfies the login configuration [New] requires alongside the
// authorization_code grant. The drain tests never run the chain, so
// Begin / Continue return zero values.
type shutdownFixtureAuthenticator struct{}

func (shutdownFixtureAuthenticator) Type() FactorType { return "fixture.primary" }
func (shutdownFixtureAuthenticator) AAL() AAL         { return AAL1 }
func (shutdownFixtureAuthenticator) AMR() string      { return "pwd" }
func (shutdownFixtureAuthenticator) Prompts() []string {
	return []string{"auth.password"}
}

func (shutdownFixtureAuthenticator) Begin(_ context.Context, _ BeginInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

func (shutdownFixtureAuthenticator) Continue(_ context.Context, _ ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, nil
}

// shutdownFixtureIssuer is the issuer stamped onto the Logout Tokens the
// drain tests sign. Nothing verifies them — the wedge sits in the
// deliverer — but the coordinator requires a non-empty value.
const shutdownFixtureIssuer = "https://op.shutdown.test"

// drainWaitContext reports the moment [backchannel.Coordinator.Drain]
// begins waiting. Drain evaluates ctx.Done() when it enters its select,
// so a Done call is proof that [Provider.Shutdown] reached the drain
// instead of returning early. The drain test releases its wedged
// deliverer off that signal, which is what makes "Shutdown waited"
// observable without measuring elapsed time: a Shutdown that skipped
// the drain never calls Done, so the wedge is never released and the
// delivery never completes.
type drainWaitContext struct {
	context.Context

	once    sync.Once
	waiting chan struct{}
}

func newDrainWaitContext() *drainWaitContext {
	return &drainWaitContext{
		Context: context.Background(),
		waiting: make(chan struct{}),
	}
}

func (c *drainWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

// shutdownFixtureClients answers every lookup with one relying party
// that has a backchannel_logout_uri registered, so a notice always
// resolves to exactly one delivery target.
type shutdownFixtureClients struct {
	store.ClientStore
}

func (shutdownFixtureClients) GetClient(_ context.Context, id string) (*store.Client, error) {
	return &store.Client{ID: id, BackchannelLogoutURI: "https://rp.example/backchannel-logout"}, nil
}

// shutdownFixtureGrants answers the audience enumeration with a single
// client ID and no further page.
type shutdownFixtureGrants struct {
	store.GrantClientLister
}

func (shutdownFixtureGrants) ListClientIDsBySubject(
	_ context.Context,
	_, _ string,
	_ int,
) (store.GrantClientPage, error) {
	return store.GrantClientPage{ClientIDs: []string{"rp-a"}}, nil
}

// newShutdownFixture returns a Provider whose config carries a
// coordinator wired to deliver, mirroring what op.New records for an
// interactive configuration.
func newShutdownFixture(t *testing.T, deliver backchannel.DelivererFunc) *Provider {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fixed := time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC)
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:    shutdownFixtureIssuer,
		Signing:   backchannel.SigningKey{KeyID: "sig-1", Signer: priv},
		Clients:   shutdownFixtureClients{},
		Grants:    shutdownFixtureGrants{},
		Deliverer: deliver,
		Clock:     timex.ClockFunc(func() time.Time { return fixed }),
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	return &Provider{cfg: &config{backchannelCoordinator: coord}}
}

// TestProviderShutdown_DrainsInFlightFanOut is the test that fails if
// Shutdown stops routing to the coordinator's drain. The deliverer is
// wedged and is released only once Drain is observed waiting, so the
// delivery can complete for exactly one reason: Shutdown waited for it.
// A Shutdown that returned without draining leaves the wedge closed and
// the assertion unmet.
func TestProviderShutdown_DrainsInFlightFanOut(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseOnce)
	delivered := make(chan struct{})

	provider := newShutdownFixture(t, func(_ context.Context, _ backchannel.Target, _ string) error {
		<-release
		close(delivered)
		return nil
	})
	provider.cfg.backchannelCoordinator.NotifyDetached(context.Background(), backchannel.Notice{Subject: "user-1"})

	ctx := newDrainWaitContext()
	go func() {
		<-ctx.waiting
		releaseOnce()
	}()

	if err := provider.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case <-delivered:
	default:
		t.Fatal("Shutdown returned while the logout token was still in flight")
	}
}

// TestProviderShutdown_HonoursDeadline pins the second half of the
// contract: a fan-out that will not finish must not hold the caller
// forever. The deliverer stays wedged for the whole test, so the only
// way out of the drain is the expired context — and a Shutdown that
// skipped the drain would return nil instead of the context error.
func TestProviderShutdown_HonoursDeadline(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	provider := newShutdownFixture(t, func(_ context.Context, _ backchannel.Target, _ string) error {
		<-release
		return nil
	})
	provider.cfg.backchannelCoordinator.NotifyDetached(context.Background(), backchannel.Notice{Subject: "user-1"})

	// A zero timeout yields an already-expired deadline, so the test
	// asserts on the returned error rather than on how long it waited.
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	err := provider.Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want context.DeadlineExceeded", err)
	}
}

// TestProviderShutdown_RepeatsAndDoesNotSeal pins the two semantics an
// embedder wiring Shutdown into a signal handler cannot control the
// ordering of: calling it more than once is safe, and it does not stop
// the Provider from starting further fan-outs. The second drain proves
// the second fan-out was waited for, not merely tolerated.
func TestProviderShutdown_RepeatsAndDoesNotSeal(t *testing.T) {
	t.Parallel()

	var delivered atomic.Int32
	provider := newShutdownFixture(t, func(_ context.Context, _ backchannel.Target, _ string) error {
		delivered.Add(1)
		return nil
	})
	coord := provider.cfg.backchannelCoordinator

	coord.NotifyDetached(context.Background(), backchannel.Notice{Subject: "user-1"})
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	if got := delivered.Load(); got != 1 {
		t.Fatalf("deliveries after the first drain = %d, want 1", got)
	}

	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("repeated Shutdown on a quiet Provider: %v", err)
	}

	coord.NotifyDetached(context.Background(), backchannel.Notice{Subject: "user-2"})
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown after a post-drain fan-out: %v", err)
	}
	if got := delivered.Load(); got != 2 {
		t.Fatalf("deliveries after the second drain = %d, want 2", got)
	}
}

// TestProviderShutdown_WithoutCoordinator covers the shapes an embedder
// reaches by calling Shutdown unconditionally: a non-interactive
// configuration that never builds a coordinator, a Provider that failed
// to construct, and a nil receiver. None of them may panic or report an
// error the caller cannot act on.
func TestProviderShutdown_WithoutCoordinator(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		provider *Provider
	}{
		{"no coordinator", &Provider{cfg: &config{}}},
		{"no config", &Provider{}},
		{"nil receiver", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.provider.Shutdown(context.Background()); err != nil {
				t.Errorf("Shutdown = %v, want nil", err)
			}
		})
	}
}

// TestNew_RecordsBackchannelCoordinator pins the wiring the drain
// depends on: an interactive configuration must leave op.New with the
// same coordinator handle the /end_session handler dispatches to. A
// refactor that builds the coordinator without recording it would make
// every Shutdown call a silent no-op, which no behavioural test of
// Shutdown itself could catch.
func TestNew_RecordsBackchannelCoordinator(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		t.Fatalf("generate cookie key: %v", err)
	}
	provider, err := New(
		WithIssuer(shutdownFixtureIssuer),
		WithStore(inmem.New()),
		WithKeyset(Keyset{SigningKey{KeyID: "sig-1", Signer: priv}}),
		WithCookieKeys(cookieKey),
		WithAuthenticators(shutdownFixtureAuthenticator{}),
		WithBackchannelFanOutBudget(3*time.Second),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if provider.cfg.backchannelCoordinator == nil {
		t.Fatal("op.New did not record the back-channel coordinator; Provider.Shutdown would never drain")
	}
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown on an idle Provider: %v", err)
	}
}
