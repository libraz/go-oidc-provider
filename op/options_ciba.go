package op

import (
	"context"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/cibaendpoint"
	"github.com/libraz/go-oidc-provider/op/grant"
)

// HintKind names which of the three CIBA Core 1.0 §7.1 hint
// parameters the inbound /bc-authorize request supplied. The type is
// closed: callers exhaustively switch on it and the linter flags any
// new case the caller forgets to handle.
//
// The values mirror the internal [ciba.HintKind] constants verbatim
// so a [HintResolver] implementation can compare without an explicit
// adapter.
type HintKind = ciba.HintKind

const (
	// HintNone is the zero value. The library never invokes a
	// [HintResolver] with this kind alongside a successful classify;
	// observing it indicates a bug in the dispatch.
	HintNone = ciba.HintNone

	// HintLoginHint means the request supplied a login_hint
	// parameter (an opaque identifier the embedder's resolver maps
	// to a stable subject).
	HintLoginHint = ciba.HintLoginHint

	// HintIDTokenHint means the request supplied an id_token_hint
	// parameter (a previously issued ID token whose sub claim
	// identifies the end-user).
	HintIDTokenHint = ciba.HintIDTokenHint

	// HintLoginHintToken means the request supplied a
	// login_hint_token parameter (a signed JWT the embedder's
	// resolver verifies and maps to a stable subject).
	HintLoginHintToken = ciba.HintLoginHintToken
)

// HintResolver maps an inbound CIBA hint to a stable end-user
// subject. The library invokes Resolve once per /bc-authorize POST
// after classifying which hint kind the client supplied.
//
// Implementations MUST:
//
//   - return a non-empty subject string on success;
//   - return [ErrUnknownCIBAUser] when the hint does not resolve to
//     a known end-user (the handler maps this to the unknown_user_id
//     wire code);
//   - return any other error to surface as login_required (the
//     handler treats non-[ErrUnknownCIBAUser] failures as an
//     authentication failure rather than a soft "no such user"
//     answer).
//
// Implementations are called from the request goroutine; they MUST
// be safe for concurrent use.
type HintResolver interface {
	Resolve(ctx context.Context, kind HintKind, value string) (subject string, err error)
}

// ErrUnknownCIBAUser is the sentinel a [HintResolver] returns to
// signal the hint did not match a known end-user. The /bc-authorize
// handler maps this to the unknown_user_id wire code; any other
// error from the resolver surfaces as login_required.
var ErrUnknownCIBAUser = cibaendpoint.ErrUnknownUser

// HintResolverFunc adapts a plain function into a [HintResolver].
type HintResolverFunc func(ctx context.Context, kind HintKind, value string) (string, error)

// Resolve implements [HintResolver] by invoking the underlying
// function.
func (f HintResolverFunc) Resolve(ctx context.Context, kind HintKind, value string) (string, error) {
	return f(ctx, kind, value)
}

// CIBAOption configures the CIBA grant beyond the bare [WithCIBA]
// opt-in. Pass values produced by the WithCIBA* helpers below.
type CIBAOption interface {
	applyCIBA(*config) error
}

type cibaOptionFunc func(*config) error

func (f cibaOptionFunc) applyCIBA(c *config) error { return f(c) }

// WithCIBAHintResolver registers the [HintResolver] the
// /bc-authorize handler invokes to map an inbound CIBA hint to a
// stable end-user subject. The resolver is REQUIRED — [WithCIBA]
// returns a configuration error when no resolver is supplied
// because the handler would otherwise return login_required for
// every request.
func WithCIBAHintResolver(r HintResolver) CIBAOption {
	return cibaOptionFunc(func(c *config) error {
		if r == nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCIBAHintResolver requires a non-nil HintResolver",
			}
		}
		c.cibaHintResolver = r
		return nil
	})
}

// WithCIBADefaultExpiresIn overrides the auth_req_id lifetime the
// OP advertises in the /bc-authorize response when the client did
// not supply requested_expiry. Zero or negative falls back to the
// library default (600 seconds, matching CIBA Core 1.0 §7.3).
func WithCIBADefaultExpiresIn(d time.Duration) CIBAOption {
	return cibaOptionFunc(func(c *config) error {
		if d < 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCIBADefaultExpiresIn must be zero or positive",
			}
		}
		c.cibaDefaultExpiresIn = d
		return nil
	})
}

// WithCIBAMaxExpiresIn caps the requested_expiry value the client
// supplies on /bc-authorize. Zero (the default) disables clamping;
// a positive value is the maximum auth_req_id lifetime the OP will
// honour regardless of the client's request. Negative values are
// rejected at the option site.
func WithCIBAMaxExpiresIn(d time.Duration) CIBAOption {
	return cibaOptionFunc(func(c *config) error {
		if d < 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCIBAMaxExpiresIn must be zero or positive",
			}
		}
		c.cibaMaxExpiresIn = d
		return nil
	})
}

// WithCIBAPollInterval overrides the `interval` value advertised on
// the /bc-authorize response (CIBA Core 1.0 §7.3). Zero or negative
// falls back to the library default (5 seconds).
func WithCIBAPollInterval(d time.Duration) CIBAOption {
	return cibaOptionFunc(func(c *config) error {
		if d < 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithCIBAPollInterval must be zero or positive",
			}
		}
		c.cibaPollInterval = d
		return nil
	})
}

// WithCIBA enables the CIBA Core 1.0 grant
// (urn:openid:params:grant-type:ciba). The option:
//
//   - appends [grant.CIBA] to the configured grant set when it is
//     not already present (idempotent so the embedder may also
//     include it via [WithGrants]);
//   - records the explicit opt-in so [op.New] can require a non-nil
//     [store.CIBARequestStore] substore at construction time —
//     starting the OP with the option but without the substore wired
//     surfaces as a configuration error rather than a runtime nil
//     panic on the first /bc-authorize POST;
//   - causes the discovery document to advertise the
//     `backchannel_authentication_endpoint`,
//     `backchannel_token_delivery_modes_supported`,
//     `backchannel_user_code_parameter_supported`, and (when JAR is
//     also enabled)
//     `backchannel_authentication_request_signing_alg_values_supported`
//     fields and the OP to mount /bc-authorize at the configured
//     endpoint path.
//
// At least one [WithCIBAHintResolver] sub-option MUST be supplied;
// [op.New] returns a configuration error otherwise. The resolver is
// the embedder's surface for mapping login_hint / id_token_hint /
// login_hint_token to a stable subject and is required for the
// endpoint to be useful.
//
// The library implements CIBA poll mode only; ping and push delivery
// modes are reserved for a future release. Discovery advertises
// `backchannel_token_delivery_modes_supported: ["poll"]` exclusively
// so a client cannot negotiate an unsupported delivery mode.
//
// Stable since v0.x.
func WithCIBA(opts ...CIBAOption) Option {
	return optionFunc(func(c *config) error {
		c.cibaGrantEnabled = true
		if !slices.Contains(c.grants, grant.CIBA) {
			c.grants = append(c.grants, grant.CIBA)
		}
		for _, sub := range opts {
			if err := sub.applyCIBA(c); err != nil {
				return err
			}
		}
		return nil
	})
}

// validateCIBAGrant enforces the substore-presence and
// resolver-presence invariants the dedicated [WithCIBA] option
// promises. An embedder that opts in MUST have a
// [store.CIBARequestStore] substore wired AND a [HintResolver]
// configured; otherwise the runtime path would either reach a nil
// substore on the first /bc-authorize POST or return login_required
// for every request. Embedders who include [grant.CIBA] only via
// [WithGrants] (without invoking [WithCIBA]) bypass this check; the
// runtime tokenendpoint path returns unsupported_grant_type when the
// substore is nil so the deployment surfaces the gap on first probe.
func (c *config) validateCIBAGrant() error {
	if !c.cibaGrantEnabled {
		return nil
	}
	if c.store == nil {
		// validateRequired has already failed; bail out so the
		// substore-nil branch does not panic on the nil store.
		return nil
	}
	if c.store.CIBARequests() == nil {
		return &Error{
			Code: codeConfiguration,
			Description: "WithCIBA requires the configured Store to provide " +
				"a non-nil CIBARequests substore (storeadapter/inmem ships one; " +
				"SQL / Redis adapters require an explicit implementation)",
		}
	}
	if c.cibaHintResolver == nil {
		return &Error{
			Code: codeConfiguration,
			Description: "WithCIBA requires a HintResolver; supply one through " +
				"WithCIBAHintResolver (the resolver maps login_hint / " +
				"id_token_hint / login_hint_token to a stable subject)",
		}
	}
	return nil
}

// cibaGrantConfigured reports whether the OP should mount the
// /bc-authorize endpoint and advertise it in discovery. The flag
// derives from either the explicit [WithCIBA] opt-in OR the
// presence of [grant.CIBA] in the configured grant set; either
// path is sufficient because the substore validation runs only on
// the explicit opt-in (so a [WithGrants] caller who forgets the
// substore gets unsupported_grant_type rather than a panic).
func (c *config) cibaGrantConfigured() bool {
	if c.cibaGrantEnabled {
		return true
	}
	return slices.Contains(c.grants, grant.CIBA)
}

// effectiveCIBADefaultExpiresIn returns the auth_req_id lifetime
// resolved against the library default (600 seconds). The helper
// exists so the router and the option-layer mirror produce the same
// fallback value.
func (c *config) effectiveCIBADefaultExpiresIn() time.Duration {
	if c.cibaDefaultExpiresIn > 0 {
		return c.cibaDefaultExpiresIn
	}
	return ciba.DefaultExpiresIn
}

// effectiveCIBAPollInterval returns the poll interval resolved
// against the library default (5 seconds).
func (c *config) effectiveCIBAPollInterval() time.Duration {
	if c.cibaPollInterval > 0 {
		return c.cibaPollInterval
	}
	return ciba.DefaultInterval
}
