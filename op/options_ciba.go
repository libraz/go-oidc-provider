package op

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/cibaendpoint"
	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	opciba "github.com/libraz/go-oidc-provider/op/ciba"
	"github.com/libraz/go-oidc-provider/op/grant"
)

// HintKind names which of the three CIBA Core 1.0 §7.1 hint
// parameters the inbound /bc-authorize request supplied. The type is
// closed: callers exhaustively switch on it and the linter flags any
// new case the caller forgets to handle.
//
// The declaration lives in
// [github.com/libraz/go-oidc-provider/op/ciba.HintKind]; this is a
// re-export so a [HintResolver] implementation stays on the op surface.
type HintKind = opciba.HintKind

const (
	// HintNone is the zero value. The library never invokes a
	// [HintResolver] with this kind alongside a successful classify;
	// observing it indicates a bug in the dispatch.
	HintNone = opciba.HintNone

	// HintLoginHint means the request supplied a login_hint
	// parameter (an opaque identifier the embedder's resolver maps
	// to a stable subject).
	HintLoginHint = opciba.HintLoginHint

	// HintIDTokenHint means the request supplied an id_token_hint
	// parameter: an ID Token this OP previously issued to the
	// requesting client.
	//
	// The OP verifies that token itself, as CIBA Core 1.0 §7.1
	// requires — signature against the OP keyset, iss equal to the
	// issuer, and an audience naming the authenticated client — before
	// any [HintResolver] runs. The value a resolver receives for this
	// kind is therefore the OP-verified "sub" claim, never the JWT.
	HintIDTokenHint = opciba.HintIDTokenHint

	// HintLoginHintToken means the request supplied a
	// login_hint_token parameter (a signed JWT the embedder's
	// resolver verifies and maps to a stable subject).
	HintLoginHintToken = opciba.HintLoginHintToken
)

// HintResolver maps an inbound CIBA hint to a stable end-user
// subject. The library invokes Resolve once per /bc-authorize POST
// after classifying which hint kind the client supplied.
//
// # What value arrives
//
// The meaning of value depends on kind, and the difference matters:
//
//   - [HintLoginHint] and [HintLoginHintToken] deliver the raw wire
//     parameter. The OP cannot interpret either, so an implementation
//     that accepts login_hint_token owns verifying that JWT's
//     signature, issuer, and audience before trusting it.
//   - [HintIDTokenHint] delivers the OP-verified "sub" claim, NOT the
//     JWT. The library has already verified the token's signature
//     against its own keyset, required iss to equal the issuer, and
//     required the audience to identify the client that authenticated
//     on the same request, per CIBA Core 1.0 §7.1. An implementation
//     therefore receives a subject the OP itself minted and can look
//     it up directly — it MUST NOT attempt to parse the value as a
//     JWT, and it MUST NOT re-derive identity from anything else.
//
// The library refuses id_token_hint from a client registered with
// subject_type=pairwise: its "sub" values are per-sector pseudonyms
// (OIDC Core 1.0 §8.1) with no reverse index, so a resolver could not
// map one back to an end-user. Such requests are rejected with
// invalid_request before Resolve is reached; pairwise clients use
// login_hint or login_hint_token instead.
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

// CIBAGrant configures the CIBA Core 1.0 grant enabled by
// [WithCIBAGrant]. Zero-valued fields keep the library defaults.
//
// Stable since v1.5.
type CIBAGrant struct {
	// HintResolver maps an inbound CIBA hint to a stable end-user
	// subject. REQUIRED — [New] returns a configuration error when it
	// is nil because the /bc-authorize handler would otherwise return
	// login_required for every request.
	HintResolver HintResolver

	// DefaultRequestTTL is the auth_req_id lifetime the OP advertises
	// in the /bc-authorize response when the client did not supply
	// requested_expiry. Zero falls back to the library default (600
	// seconds, matching CIBA Core 1.0 §7.3); a negative value is
	// rejected.
	//
	// The value must not exceed MaxRequestTTL when both are
	// configured; the combination fails [New]. When only the cap is
	// configured, the library default is clamped down to it. Under
	// the FAPI-CIBA profile a value above ten minutes fails [New].
	DefaultRequestTTL time.Duration

	// MaxRequestTTL caps the requested_expiry value the client
	// supplies on /bc-authorize. Zero (the default) disables clamping;
	// a positive value is the maximum auth_req_id lifetime the OP will
	// honour regardless of the client's request. A negative value is
	// rejected.
	//
	// The cap also bounds the lifetime applied when the client omits
	// requested_expiry: a lower cap clamps the library default, and an
	// explicitly configured DefaultRequestTTL above the cap fails
	// [New]. Under the FAPI-CIBA profile a value above ten minutes
	// fails [New].
	MaxRequestTTL time.Duration

	// PollInterval is the `interval` value advertised on the
	// /bc-authorize response (CIBA Core 1.0 §7.3). Zero falls back to
	// the library default (5 seconds); a negative value is rejected.
	PollInterval time.Duration

	// MaxPollViolations is the strike threshold above which the
	// /token endpoint locks a CIBA record by calling Deny with reason
	// "poll_abuse" (CIBA Core 1.0 §11 leaves the lockout cap
	// implementation-defined). Zero falls back to the library default
	// ([ciba.MaxPollViolations], currently 5).
	//
	// The knob exists for two reasons:
	//
	//  1. Conformance harnesses that exercise the slow_down ladder more
	//     times than the default cap permits (e.g. the OFCS fapi-ciba
	//     multiple-call-to-token-endpoint module) would otherwise see
	//     the request lock to access_denied mid-test.
	//  2. Embedders whose RP fleet legitimately races the slow_down
	//     interval (clock skew, retry storms after a transient outage)
	//     can raise the cap to absorb the bounce without revoking the
	//     auth_req_id.
	//
	// To disable the lockout effectively, pass 255 — the strike counter
	// is uint8 and never wraps past that value. Production embedders
	// SHOULD prefer a finite cap because the lockout is the only defence
	// against a client that ignores slow_down and burns through the
	// auth_req_id's TTL with rapid polls.
	MaxPollViolations uint8
}

// WithCIBAGrant enables the CIBA Core 1.0 grant
// (urn:openid:params:grant-type:ciba), configured by g. The option:
//
//   - adds [grant.CIBA] to the resolved grant set. The addition
//     composes rather than replaces: a deployment that calls only
//     this option keeps the default authorization_code +
//     refresh_token pair, and one that also calls [WithGrants] gets
//     the CIBA grant on top of the listed set regardless of which
//     option runs first. Naming [grant.CIBA] in [WithGrants] as well
//     is a no-op, not a duplicate;
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
// [CIBAGrant.HintResolver] MUST be set; [op.New] returns a
// configuration error otherwise. The resolver is the embedder's
// surface for mapping login_hint / id_token_hint / login_hint_token
// to a stable subject and is required for the endpoint to be useful.
//
// The library implements CIBA poll mode only; ping and push delivery
// modes are reserved for a future release. Discovery advertises
// `backchannel_token_delivery_modes_supported: ["poll"]` exclusively
// so a client cannot negotiate an unsupported delivery mode.
//
// WithCIBAGrant may be supplied at most once.
//
// Stable since v1.5.
func WithCIBAGrant(g CIBAGrant) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithCIBAGrant"); err != nil {
			return err
		}
		// A missing resolver surfaces in validateCIBAGrant; a typed nil
		// is a wiring slip caught here, where the option is named.
		if g.HintResolver != nil && nilcheck.IsNil(g.HintResolver) {
			return newConfigurationError("WithCIBAGrant: CIBAGrant.HintResolver must not be a typed nil", nil)
		}
		switch {
		case g.DefaultRequestTTL < 0:
			return newConfigurationError("WithCIBAGrant: CIBAGrant.DefaultRequestTTL must be zero or positive", nil)
		case g.MaxRequestTTL < 0:
			return newConfigurationError("WithCIBAGrant: CIBAGrant.MaxRequestTTL must be zero or positive", nil)
		case g.PollInterval < 0:
			return newConfigurationError("WithCIBAGrant: CIBAGrant.PollInterval must be zero or positive", nil)
		}
		// Only the opt-in bit and the settings are recorded here; the
		// grant set is assembled in [config.applyDefaults] once every
		// option has run, so the result cannot depend on whether this
		// option or [WithGrants] was applied first.
		c.cibaGrantEnabled = true
		c.cibaHintResolver = g.HintResolver
		c.cibaDefaultExpiresIn = g.DefaultRequestTTL
		c.cibaMaxExpiresIn = g.MaxRequestTTL
		c.cibaPollInterval = g.PollInterval
		c.cibaMaxPollViolations = g.MaxPollViolations
		return nil
	})
}

// validateCIBAGrant enforces the substore-presence and
// resolver-presence invariants the CIBA flow depends on: any
// embedder that activates the grant — through the dedicated
// [WithCIBAGrant] option OR by listing [grant.CIBA] in [WithGrants] —
// MUST have a [store.CIBARequestStore] substore wired AND a
// [HintResolver] configured. Without the substore the
// /bc-authorize handler's Save call would reach a nil substore on
// the first request, and without the resolver every request would
// surface login_required. Surfacing the gap at construction time
// is the same posture the rest of the options take.
func (c *config) validateCIBAGrant() error {
	if !c.grantEnabled(grant.CIBA) {
		return nil
	}
	if nilcheck.IsNil(c.store) {
		// validateRequired has already failed; bail out so the
		// substore-nil branch does not panic on the nil store.
		return nil
	}
	if nilcheck.IsNil(c.store.CIBARequests()) {
		return newConfigurationError("the CIBA grant requires the configured Store to provide "+
			"a non-nil CIBARequests substore (the inmem, sql and dynamodb adapters ship one; "+
			"the redis adapter does not — route this substore to another backend through storeadapter/composite)", nil)
	}
	if nilcheck.IsNil(c.cibaHintResolver) {
		return newConfigurationError("the CIBA grant requires a HintResolver; supply one through "+
			"WithCIBAGrant(CIBAGrant{HintResolver: ...}) (the resolver maps "+
			"login_hint / id_token_hint / login_hint_token to a stable subject)", nil)
	}
	// The cap only clamps a client-supplied requested_expiry, so a
	// default above it would hand every client that omits the
	// parameter a longer-lived auth_req_id than one that asks for the
	// maximum. An explicit inversion is a typo and fails here; the
	// library default exceeding a lowered cap is resolved by clamping
	// in [config.effectiveCIBADefaultExpiresIn], since the cap states
	// the intent unambiguously.
	if c.cibaMaxExpiresIn > 0 && c.cibaDefaultExpiresIn > c.cibaMaxExpiresIn {
		return newConfigurationError("CIBAGrant.DefaultRequestTTL must not exceed CIBAGrant.MaxRequestTTL; "+
			"the default applies when the client omits requested_expiry and "+
			"would otherwise outlive the value a client may ask for", nil)
	}
	return nil
}

// effectiveCIBADefaultExpiresIn returns the auth_req_id lifetime
// resolved against the library default (600 seconds). The helper
// exists so the router and the option-layer mirror produce the same
// fallback value. A configured maximum clamps the result: the cap is
// the ceiling a client may request, so the value applied when the
// client requests nothing must not sit above it.
func (c *config) effectiveCIBADefaultExpiresIn() time.Duration {
	d := ciba.DefaultExpiresIn
	if c.cibaDefaultExpiresIn > 0 {
		d = c.cibaDefaultExpiresIn
	}
	if c.cibaMaxExpiresIn > 0 && d > c.cibaMaxExpiresIn {
		return c.cibaMaxExpiresIn
	}
	return d
}

// effectiveCIBAPollInterval returns the poll interval resolved
// against the library default (5 seconds).
func (c *config) effectiveCIBAPollInterval() time.Duration {
	if c.cibaPollInterval > 0 {
		return c.cibaPollInterval
	}
	return ciba.DefaultInterval
}
