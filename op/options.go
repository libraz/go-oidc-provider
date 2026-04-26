package op

import (
	"log/slog"
	"net/url"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Option configures a [Provider] passed to [New]. Options compose: the order
// in which they appear in the New call determines the order in which they
// are applied. Where two options set the same field, the later one wins.
//
// Implementors of new options should construct an [Option] via the
// unexported optionFunc type below; users of the package do not implement
// the Option interface directly.
type Option interface {
	apply(*config) error
}

type optionFunc func(*config) error

func (f optionFunc) apply(c *config) error { return f(c) }

// config holds the validated configuration of a [Provider]. It is private so
// that callers can only build it through [Option] values, which lets us
// preserve invariants (no zero-value Provider, type-driven enums, etc.).
type config struct {
	issuer string
	store  store.Store
	clock  Clock
	logger *slog.Logger
}

// newConfig applies opts in order to a fresh config and returns the result
// or the first option error encountered. After every option has been
// applied, defaults are filled in for fields the caller chose to omit.
func newConfig(opts []Option) (*config, error) {
	c := &config{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt.apply(c); err != nil {
			return nil, err
		}
	}
	c.applyDefaults()
	return c, nil
}

// applyDefaults fills in optional fields with their library defaults.
func (c *config) applyDefaults() {
	if c.clock == nil {
		c.clock = timex.SystemClock
	}
	if c.logger == nil {
		c.logger = slog.New(discardHandler{})
	}
}

// validate checks that required fields are set and that combinations of
// options are internally consistent. It runs after applyDefaults so that
// "missing required" errors are not masked by a default value.
func (c *config) validate() error {
	if c.issuer == "" {
		return ErrIssuerRequired
	}
	if c.store == nil {
		return ErrStoreRequired
	}
	return nil
}

// WithIssuer sets the OP issuer URL. The value MUST be an absolute https URL
// with no query or fragment, per OpenID Connect Discovery 1.0 §3. The URL is
// parsed eagerly; malformed values fail [New] rather than the first request.
//
// Stable since v0.1.
func WithIssuer(issuer string) Option {
	return optionFunc(func(c *config) error {
		if issuer == "" {
			return ErrIssuerRequired
		}
		u, err := url.Parse(issuer)
		if err != nil || !u.IsAbs() || u.Scheme != "https" || u.RawQuery != "" || u.Fragment != "" {
			return ErrIssuerInvalid
		}
		c.issuer = issuer
		return nil
	})
}

// WithStore registers the storage backend the [Provider] uses to persist
// authorization codes, refresh tokens, grants, sessions, and other records.
// Callers MUST supply a non-nil [store.Store]; the library does not provide a
// default backend at this layer because the choice of persistence is part of
// the deployment shape rather than the library configuration.
//
// Stable since v0.1.
func WithStore(s store.Store) Option {
	return optionFunc(func(c *config) error {
		if s == nil {
			return ErrStoreRequired
		}
		c.store = s
		return nil
	})
}

// WithClock injects the wall-clock implementation used for token expiry,
// audit timestamps, and rate-limit windows. If unset, the [Provider] uses a
// real wall clock backed by [time.Now]. Tests SHOULD inject a deterministic
// clock so the whole flow shares the same fake time.
//
// Stable since v0.1.
func WithClock(clock Clock) Option {
	return optionFunc(func(c *config) error {
		c.clock = clock
		return nil
	})
}

// WithLogger injects the [*slog.Logger] the library uses for structured
// diagnostics. If unset, the [Provider] discards every record. Callers
// SHOULD pass a logger backed by their service's slog handler so OP events
// appear in the same stream as the rest of the application.
//
// Stable since v0.1.
func WithLogger(logger *slog.Logger) Option {
	return optionFunc(func(c *config) error {
		c.logger = logger
		return nil
	})
}
