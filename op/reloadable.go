package op

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/libraz/go-oidc-provider/internal/metrics"
)

// ErrReloadIncompatible is returned by [Reloadable.Reload] when the new
// options change the issuer or the set of routes the [Provider] serves.
// Neither can change under a running process: relying parties pin the
// issuer, and an embedder that mounted the routes one by one (see
// [Provider.Routes]) cannot follow a route that appears or moves. Make
// such a change by restarting the process. The returned error wraps this
// value, so match it with [errors.Is].
//
// Stable since v1.5.
var ErrReloadIncompatible = &Error{
	Code:        codeConfiguration,
	Description: "reload cannot change the issuer or the route set; restart the process instead",
}

// Reloadable is an [http.Handler] that serves the current [Provider] and
// swaps it for a freshly built one on [Reloadable.Reload]. It is the
// supported way to pick up rotated signing, cookie and MFA keys — or any
// other option change — without restarting the process.
//
// Typical wiring re-reads the configuration on SIGHUP:
//
//	r, err := op.NewReloadable(buildOptions()...)
//	if err != nil {
//		log.Fatal(err)
//	}
//	srv := &http.Server{Addr: ":8080", Handler: r}
//
//	hup := make(chan os.Signal, 1)
//	signal.Notify(hup, syscall.SIGHUP)
//	go func() {
//		for range hup {
//			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
//			if err := r.Reload(ctx, buildOptions()...); err != nil {
//				slog.Error("reload rejected; the previous configuration keeps serving", "error", err)
//			}
//			cancel()
//		}
//	}()
//
// A router that mounts the OP pattern by pattern registers r rather than a
// Provider, so every pattern keeps reaching whichever Provider is current:
//
//	for _, pat := range r.Routes() {
//		mux.Handle(pat, r)
//	}
//
// Rules a reload depends on:
//
//   - Reload takes the complete option list, exactly as [New] does, not a
//     delta against the running configuration. Build it from the same
//     function that built the initial one.
//   - Pass the same store. Sessions, interactions, lockout counters and
//     every other persisted record survive a reload only because the new
//     Provider reads the store the old one wrote. Reconnecting to the same
//     database through a new handle is fine; pointing at a different
//     backend silently drops that state.
//   - Rotate cookie keys ([WithCookieKeys]) and MFA encryption keys
//     ([WithMFAEncryptionKeys]) by putting the new key first and keeping the retiring key as a later
//     entry. Dropping a key the running sessions or enrolled TOTP secrets
//     were sealed with makes them unreadable: every user is logged out and
//     enrolments must be redone. The same applies to [WithKeyset]: keep the
//     retiring signing key listed until tokens it signed have expired.
//   - State a Provider builds in memory does not carry over. A DPoP nonce
//     source constructed inside the option builder starts afresh (nonces
//     the old one issued stop verifying) and its rotation goroutine runs
//     until its context is cancelled. Construct the source once, outside
//     the builder, and pass the same instance to every build; that keeps
//     issued nonces valid across a reload. A closure handed to
//     [WithJWKSRotationActive] is whatever the new option list carries,
//     and the [WithPrometheus] counters restart from zero. Between the
//     outgoing collector being unregistered and the new one registered, a
//     scrape sees no series for the issuer; rate() treats the restart as a
//     counter reset.
//   - When a reload is refused with [ErrReloadIncompatible] because the
//     route set changed, the replacement Provider had already been built,
//     so new [WithStaticClients] seeds are already in the store. Restarting
//     with the same options applies the same seeds, so this is harmless,
//     but the store is not left exactly as it was.
//   - After the swap, Reload waits for the outgoing Provider's in-flight
//     back-channel logout deliveries ([Provider.Shutdown]) before it
//     returns. A slow relying party therefore delays Reload, and the next
//     Reload waits behind it. Bound the wait with ctx.
//   - Never expose Reload on an HTTP path. It rebuilds the security
//     configuration of the OP; trigger it from a signal, a file watcher or
//     an administrative process the OP's clients cannot reach.
//
// Requests already running on the outgoing Provider finish on it; the
// Provider is not sealed. A Reloadable is safe for concurrent use: any
// number of goroutines may serve through it while Reload runs, and Reload
// and [Reloadable.Shutdown] are serialized with each other.
//
// Stable since v1.5.
type Reloadable struct {
	mu  sync.Mutex
	cur atomic.Pointer[Provider]
}

// NewReloadable builds the initial [Provider] from opts with [New] and
// wraps it in a [Reloadable]. Construction errors are those of [New].
//
// Stable since v1.5.
func NewReloadable(opts ...Option) (*Reloadable, error) {
	p, err := New(opts...)
	if err != nil {
		return nil, err
	}
	r := &Reloadable{}
	r.cur.Store(p)
	return r, nil
}

// ServeHTTP serves the request on the current [Provider].
//
// Stable since v1.5.
func (r *Reloadable) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.cur.Load().ServeHTTP(w, req)
}

// Provider returns the [Provider] currently serving requests. The value
// may be replaced by a later [Reloadable.Reload]; read it again rather
// than holding on to it.
//
// Stable since v1.5.
func (r *Reloadable) Provider() *Provider {
	return r.cur.Load()
}

// Routes returns the current Provider's [Provider.Routes]. A successful
// [Reloadable.Reload] never changes the set, so mounting these patterns
// once at start-up stays correct across reloads.
//
// Stable since v1.5.
func (r *Reloadable) Routes() []string {
	return r.cur.Load().Routes()
}

// Reload builds a new [Provider] from opts and, if it is compatible,
// swaps it in for the current one. On any error the current Provider —
// including its [WithPrometheus] collectors — keeps serving unchanged.
//
// The steps, in order:
//
//  1. The options are applied and the issuer is compared with the current
//     one. A different issuer is refused with [ErrReloadIncompatible]
//     before anything outside the process is touched.
//  2. The current Provider's metric collectors are unregistered, so the
//     replacement can register the same issuer on the same registry.
//  3. The replacement is built with [New]. If that fails, the current
//     collectors are registered again and the build error is returned.
//  4. The route sets are compared. If they differ, the replacement's
//     collectors are unregistered, the current ones registered again, and
//     [ErrReloadIncompatible] is returned.
//  5. The replacement becomes current.
//  6. The outgoing Provider is drained with [Provider.Shutdown] under ctx.
//     A drain error is logged at WARN on the new Provider's logger rather
//     than returned, because the swap has already taken effect.
//
// Reloads are serialized. See [Reloadable] for what a reload keeps and
// what it loses.
//
// Stable since v1.5.
func (r *Reloadable) Reload(ctx context.Context, opts ...Option) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	old := r.cur.Load()
	cfg, err := newConfig(opts)
	if err != nil {
		return err
	}
	if cfg.issuer == "" {
		return ErrIssuerRequired
	}
	if cfg.issuer != old.cfg.issuer {
		return newConfigurationError("reload rejected: the issuer changed", ErrReloadIncompatible)
	}

	oldMetrics := old.cfg.metricsCollector
	oldMetrics.Unregister()
	next, err := New(opts...)
	if err != nil {
		return restoreMetrics(oldMetrics, err)
	}
	if !sameRouteSet(old.Routes(), next.Routes()) {
		next.cfg.metricsCollector.Unregister()
		return restoreMetrics(oldMetrics,
			newConfigurationError("reload rejected: the route set changed", ErrReloadIncompatible))
	}

	r.cur.Store(next)
	if err := old.Shutdown(ctx); err != nil {
		next.cfg.logger.WarnContext(ctx,
			"reload: the outgoing provider did not finish its back-channel logout deliveries",
			"error", err.Error(),
		)
	}
	return nil
}

// Shutdown drains the current [Provider] with [Provider.Shutdown]. It
// waits for a Reload in progress first, so the Provider it drains is the
// one left serving.
//
// Stable since v1.5.
func (r *Reloadable) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur.Load().Shutdown(ctx)
}

// restoreMetrics re-registers the outgoing collectors after a rejected
// reload and returns cause, joined with any re-registration failure.
func restoreMetrics(oldMetrics *metrics.Collector, cause error) error {
	if err := oldMetrics.Register(); err != nil {
		return newConfigurationError(
			"reload rejected and the current provider's metrics could not be re-registered",
			errors.Join(cause, err),
		)
	}
	return cause
}

// sameRouteSet reports whether a and b hold the same patterns, ignoring order.
func sameRouteSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
