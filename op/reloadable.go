package op

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/libraz/go-oidc-provider/internal/metrics"
)

// ErrReloadIncompatible is returned by [Reloadable.Reload] when the new
// options cannot replace the running ones without breaking what the
// running [Provider] already handed out: a changed issuer or route set, a
// dropped active cookie or signing key, a dropped MFA encryption key, or a
// different DPoP nonce source. [Reloadable] lists each rule. Make such a
// change by restarting the process. The returned error wraps this value,
// so match it with [errors.Is].
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
//   - Rotate cookie keys ([WithCookieKeys]) and signing keys ([WithKeyset])
//     by putting the new key first and keeping the running active key as a
//     later entry. Reload refuses a list that drops the running active key,
//     which would log every user out or leave issued tokens unverifiable;
//     retire it with the next reload, once its sessions and tokens expire.
//   - Reload refuses to drop any MFA encryption key, whether supplied
//     through [WithMFAEncryptionKeys] or a [StepTOTP]: TOTP secrets sealed
//     with it would become unreadable for good. Retire one by restarting
//     after every record has been re-sealed under the active key.
//   - Reload refuses a [WithDPoPNonceSource] that is not the instance the
//     running Provider holds, since a new one invalidates every nonce
//     issued and leaves the old one's rotation goroutine running.
//     Construct the source once, outside the option builder, and pass the
//     same instance to every build.
//   - Other state a Provider builds in memory does not carry over. A
//     closure handed to [WithJWKSRotationActive] is whatever the new
//     option list carries, and the [WithPrometheus] counters restart from
//     zero. Between the outgoing collector being unregistered and the new
//     one registered, a scrape sees no series for the issuer; rate()
//     treats the restart as a counter reset.
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
//  1. The options are applied and compared with the current ones. A
//     different issuer, or a key or nonce source [Reloadable] requires to
//     carry over, is refused with [ErrReloadIncompatible] before anything
//     outside the process is touched.
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
	if err := checkReloadContinuity(old.cfg, cfg); err != nil {
		return err
	}

	oldMetrics := old.cfg.metricsCollector
	oldMetrics.Unregister()
	next, err := New(opts...)
	if err != nil {
		return restoreMetrics(oldMetrics, err)
	}
	if !sameRouteSet(old.Routes(), next.Routes()) {
		// The rejected candidate has already started its background work
		// (the shared-signals push worker); stop it before discarding it.
		_ = next.Shutdown(ctx)
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

// checkReloadContinuity refuses a replacement configuration that would
// lose what the running Provider sealed, signed or issued with.
func checkReloadContinuity(cur, next *config) error {
	if len(cur.cookieKeys) > 0 && !slices.ContainsFunc(next.cookieKeys, bytesEqual(cur.cookieKeys[0])) {
		return reloadIncompatible("the active cookie key is missing from WithCookieKeys")
	}
	if len(cur.keyset) > 0 && !slices.ContainsFunc(next.keyset, sameSigningKey(cur.keyset[0])) {
		return reloadIncompatible("the active signing key is missing from WithKeyset")
	}
	nextMFA := mfaEncryptionKeys(next)
	for _, k := range mfaEncryptionKeys(cur) {
		if !slices.ContainsFunc(nextMFA, bytesEqual(k)) {
			return reloadIncompatible("an MFA encryption key the running configuration holds is missing")
		}
	}
	if cur.dpopNonces != nil && !sameNonceSource(cur.dpopNonces, next.dpopNonces) {
		return reloadIncompatible("WithDPoPNonceSource is not the same instance")
	}
	return nil
}

func reloadIncompatible(reason string) error {
	return newConfigurationError("reload rejected: "+reason, ErrReloadIncompatible)
}

func bytesEqual(want []byte) func([]byte) bool {
	return func(k []byte) bool { return bytes.Equal(k, want) }
}

// sameSigningKey matches a key with want's KeyID and public key: a KeyID
// reused for a different key leaves the tokens want signed unverifiable.
func sameSigningKey(want SigningKey) func(SigningKey) bool {
	wantPub, ok := want.Signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	return func(k SigningKey) bool {
		return k.KeyID == want.KeyID && ok && wantPub.Equal(k.Signer.Public())
	}
}

// mfaEncryptionKeys lists every key a TOTP secret may be sealed with: the
// Provider-level keys and the per-step keys of each [StepTOTP] in the flow.
func mfaEncryptionKeys(c *config) [][]byte {
	keys := slices.Clone(c.mfaEncryptionKeys)
	var walk func(Step)
	walk = func(step Step) {
		switch s := step.(type) {
		case StepTOTP:
			if len(s.EncryptionKey) > 0 {
				keys = append(keys, s.EncryptionKey)
			}
			keys = append(keys, s.EncryptionKeyPrev...)
		case StepOneOf:
			for _, inner := range s.Steps {
				walk(inner)
			}
		}
	}
	walk(c.loginFlow.Primary)
	for _, r := range c.loginFlow.Rules {
		walk(r.Then)
	}
	return keys
}

// sameNonceSource reports whether b is the very source a is. A source of a
// non-comparable type never matches, since identity cannot be established.
func sameNonceSource(a, b DPoPNonceSource) bool {
	if b == nil {
		return false
	}
	ta := reflect.TypeOf(a)
	return ta == reflect.TypeOf(b) && ta.Comparable() && any(a) == any(b)
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
