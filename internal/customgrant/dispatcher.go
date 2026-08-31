package customgrant

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Audit event names. Values come from the same registry as the public
// op.AuditCustomGrant* constants.
const (
	AuditEventRequested = string(auditevent.AuditCustomGrantRequested)
	AuditEventFailed    = string(auditevent.AuditCustomGrantFailed)
	// AuditEventRefreshDropped fires when a response asked the OP to
	// mint a refresh token but an issuance gate withheld it — the
	// Provider does not serve the refresh_token grant, the client is
	// not registered for it, or the response carries no material the OP
	// can persist as a chain root. The rest of the response is still
	// issued; the refresh token is omitted (RFC 6749 §6 gate) and the
	// event's extras name the gate under "reason".
	AuditEventRefreshDropped = string(auditevent.AuditCustomGrantRefreshDropped)
)

// Sentinel errors. Each value names a single dispatch failure mode
// the handler in tokenendpoint translates into the matching RFC 6749
// §5.2 wire code. Wrapping is intentional: a handler whose Handle
// method returns one of these (rather than a synthesised *op.Error)
// hits the same wire code as the dispatcher's own gate fired for the
// same reason.
var (
	// ErrUnknownGrant signals that no registered handler answered to
	// the request's grant_type. Maps to unsupported_grant_type.
	ErrUnknownGrant = errors.New("custom_grant: no handler registered for grant_type")

	// ErrUnknownParameter signals the request carried a parameter
	// the handler's [ParamPolicy.Allowed] list did not name. Maps
	// to invalid_request.
	ErrUnknownParameter = errors.New("custom_grant: parameter not allowed by handler policy")

	// ErrDuplicateParameter signals the request repeated a name
	// that was not in [ParamPolicy.DupesAllowed]. Maps to
	// invalid_request.
	ErrDuplicateParameter = errors.New("custom_grant: duplicate parameter not permitted by handler policy")

	// ErrDuplicateCapExceeded signals the request repeated a
	// dup-allowed name more than [DupCap] times. Maps to
	// invalid_request.
	ErrDuplicateCapExceeded = errors.New("custom_grant: duplicate parameter exceeds the per-name cap")

	// ErrClientGrantNotPermitted signals the authenticated client's
	// metadata does not list the request's grant_type in its
	// allowed-grants set. Maps to unauthorized_client.
	ErrClientGrantNotPermitted = errors.New("custom_grant: client is not authorized for this grant_type")

	// ErrEmptyAccessToken signals the handler returned neither an
	// AccessToken nor a BoundAccessToken. Maps to server_error; the
	// wire response carries no detail so a misbehaving handler cannot
	// probe for issuance internals.
	ErrEmptyAccessToken = errors.New("custom_grant: handler returned empty access_token")

	// ErrConflictingAccessTokenForms signals the handler set both
	// AccessToken and BoundAccessToken on the response. The two
	// fields are mutually exclusive: AccessToken delegates issuance
	// to the handler, BoundAccessToken delegates it to the OP.
	// Maps to server_error.
	ErrConflictingAccessTokenForms = errors.New("custom_grant: AccessToken and BoundAccessToken are mutually exclusive")

	// ErrEmptyBoundSubject signals the handler returned a
	// BoundAccessToken with no Subject, the response carried no
	// Subject either, AND the dispatch input carried no SubjectID.
	// The OP cannot synthesise a "sub" claim without a value from the
	// handler so the wire layer rejects the response. Maps to
	// server_error.
	ErrEmptyBoundSubject = errors.New("custom_grant: BoundAccessToken has no subject and none can be derived from the response or request")

	// ErrNegativeTTL signals the handler returned a negative
	// AccessTokenTTL. Maps to server_error; a negative TTL would
	// mint an already-expired token, which is almost always a bug
	// the handler should be told about (the audit record carries
	// the value).
	ErrNegativeTTL = errors.New("custom_grant: handler returned negative AccessTokenTTL")

	// ErrScopeNotAllowed signals the handler's response contained
	// a scope outside the authenticated client's registered set.
	// Maps to invalid_scope.
	ErrScopeNotAllowed = errors.New("custom_grant: response scope exceeds the client's allowed set")

	// ErrAudienceNotAllowed signals the handler's response named
	// an audience the client did not register as a resource. Maps
	// to invalid_target.
	ErrAudienceNotAllowed = errors.New("custom_grant: response audience exceeds the client's registered resources")

	// ErrPanic signals the handler's Handle method panicked. Maps
	// to server_error; the stacktrace is routed to the audit log
	// only and never leaks into the wire response.
	ErrPanic = errors.New("custom_grant: handler panicked")
)

// Dispatcher is the per-Provider routing table from grant_type to
// handler. The zero value rejects every grant; embedders construct
// a dispatcher via [New]. The type is safe for concurrent use after
// construction.
type Dispatcher struct {
	handlers     []Handler
	maxAccessTTL time.Duration
	now          func() time.Time
	auditEmit    audit.Emitter
}

// Option configures a [Dispatcher] at construction. Options are
// applied in order; later options override earlier ones.
type Option func(*Dispatcher)

// WithMaxAccessTTL sets the global cap the dispatcher applies to
// the handler-supplied [Response.AccessTokenTTL]. A zero or
// negative value disables the cap; the handler-supplied TTL flows
// through verbatim.
func WithMaxAccessTTL(d time.Duration) Option {
	return func(disp *Dispatcher) { disp.maxAccessTTL = d }
}

// WithClock sets the wall-clock function the dispatcher consults
// for audit timestamps. The dispatcher does not use the clock for
// cryptographic operations (those happen inside the handler); the
// hook exists so test fixtures see deterministic record times.
func WithClock(now func() time.Time) Option {
	return func(disp *Dispatcher) { disp.now = now }
}

// WithAudit installs the audit sink. A nil emitter falls back to
// [audit.Discard] so the dispatcher can call Emit unconditionally
// without a nil-check.
func WithAudit(em audit.Emitter) Option {
	return func(disp *Dispatcher) { disp.auditEmit = em }
}

// New constructs a [Dispatcher] from the supplied handler set. The
// handlers are stored in a defensive copy so a later mutation of
// the caller's slice cannot reshape the dispatch table at runtime.
// The order is preserved so duplicate-name diagnostics blame the
// later registrant; the option layer rejects duplicates before they
// reach the dispatcher, but the order discipline is documented for
// completeness.
func New(handlers []Handler, opts ...Option) *Dispatcher {
	stored := make([]Handler, len(handlers))
	copy(stored, handlers)
	disp := &Dispatcher{
		handlers:  stored,
		auditEmit: audit.Discard(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(disp)
		}
	}
	if disp.auditEmit == nil {
		disp.auditEmit = audit.Discard()
	}
	return disp
}

// HasHandler reports whether the dispatcher has a registration for
// the supplied grant_type. The discovery builder consults this so
// the OP advertises only the grants it can actually serve.
func (d *Dispatcher) HasHandler(grantType string) bool {
	if d == nil {
		return false
	}
	for _, h := range d.handlers {
		if h.Name() == grantType {
			return true
		}
	}
	return false
}

// Names returns the registered grant_type names in registration
// order. The discovery builder concatenates the slice with the
// built-in grant types when computing grant_types_supported.
func (d *Dispatcher) Names() []string {
	if d == nil || len(d.handlers) == 0 {
		return nil
	}
	out := make([]string, 0, len(d.handlers))
	for _, h := range d.handlers {
		out = append(out, h.Name())
	}
	return out
}

// DispatchInput is the per-request input the token endpoint passes
// to [Dispatcher.Dispatch]. The struct is the dispatcher's view of
// the request after client authentication, DPoP / mTLS verification,
// and form parsing have run; the dispatcher itself does not touch
// http.Request.
type DispatchInput struct {
	// GrantType is the value of the grant_type form parameter.
	// The dispatcher returns [ErrUnknownGrant] when no registered
	// handler answers to it.
	GrantType string

	// Client is the authenticated client. Non-nil; the caller
	// rejects unauthenticated requests before invoking Dispatch.
	Client *store.Client

	// SubjectID is forwarded verbatim to [Request.SubjectID];
	// see the field docs there.
	SubjectID string

	// AuthTime is forwarded verbatim to [Request.AuthTime].
	AuthTime time.Time

	// Form is the raw url.Values shape the token endpoint parsed
	// out of the request body. The dispatcher applies the policy
	// filter and copies the surviving subset into [Request.Form].
	Form url.Values

	// DPoPJKT / DPoPJTI / MTLSCert are forwarded verbatim into
	// [Request]; see those field docs.
	DPoPJKT  string
	DPoPJTI  string
	MTLSCert any
}

// Dispatch routes the request to the matching handler. The function
// returns either a validated [Response] (the caller writes the wire
// response from this) or one of the package sentinels (the caller
// translates the sentinel into the matching RFC 6749 §5.2 wire code).
// A non-sentinel error returned by the handler is propagated verbatim
// so a handler that returns its own *op.Error retains the wire shape
// it chose.
//
// Dispatch owns the audit emissions for the whole dispatch, and it is
// the only place either event is raised:
//
//   - [AuditEventRequested] fires once at entry, for every attempt that
//     reached a registered handler — successes and rejections alike. It
//     is the attempt count, so "failure rate = failed / requested" is a
//     ratio an operator can calibrate an alert on; emitting it only on
//     success would make the denominator the success count and let the
//     ratio exceed 1.
//   - [AuditEventFailed] fires at most once, from the single exit
//     below, whichever gate produced the rejection. A second emission
//     from inside a gate would double-count that gate's failure class
//     in oidc_custom_grant_events_total and break de-duplication keyed
//     on (request_id, event).
func (d *Dispatcher) Dispatch(ctx context.Context, in DispatchInput) (Response, error) {
	if d == nil || len(d.handlers) == 0 {
		return Response{}, ErrUnknownGrant
	}
	handler := d.lookup(in.GrantType)
	if handler == nil {
		return Response{}, ErrUnknownGrant
	}
	d.emitRequested(ctx, in)
	resp, fail, err := d.attempt(ctx, handler, in)
	if err != nil {
		d.emitFailed(ctx, in, fail)
		return Response{}, err
	}
	return resp, nil
}

// attempt runs the gates between entry and a validated response. Every
// rejection names itself through the returned [failure] instead of
// emitting, so the audit stream has exactly one record per dispatch
// outcome regardless of which gate fired.
func (d *Dispatcher) attempt(ctx context.Context, handler Handler, in DispatchInput) (Response, failure, error) {
	if !clientGrantPermitted(in.Client, in.GrantType) {
		return Response{}, failure{reason: "client_grant_not_permitted"}, ErrClientGrantNotPermitted
	}
	policy := handler.ParamPolicy()
	form, err := filterForm(in.Form, policy)
	if err != nil {
		return Response{}, failure{reason: "form_policy_violation"}, err
	}
	req := Request{
		Client:         in.Client,
		SubjectID:      in.SubjectID,
		AuthTime:       in.AuthTime,
		Form:           form,
		DPoPJKT:        in.DPoPJKT,
		DPoPJTI:        in.DPoPJTI,
		RequestedScope: parseScopeParam(in.Form),
	}
	if cert, ok := in.MTLSCert.(*x509.Certificate); ok {
		req.MTLSCert = cert
	}
	resp, fail, err := d.invokeHandler(ctx, handler, req)
	if err != nil {
		return Response{}, fail, err
	}
	if err := d.validateResponse(in.Client, &resp); err != nil {
		return Response{}, failure{reason: "response_invalid"}, err
	}
	return resp, failure{}, nil
}

// failure describes a rejected dispatch for the single audit emission
// [Dispatch] makes. reason is a stable enum the dispatcher selects from
// so SOC tooling can pre-aggregate without parsing free-form text;
// extras carries whatever the individual gate has to add.
type failure struct {
	reason string
	extras map[string]any
}

// lookup returns the handler registered for grantType, or nil when
// no match exists.
//
//nolint:ireturn,nolintlint // dispatcher intentionally returns the public Handler interface.
func (d *Dispatcher) lookup(grantType string) Handler {
	for _, h := range d.handlers {
		if h.Name() == grantType {
			return h
		}
	}
	return nil
}

// invokeHandler runs the handler with panic recovery. A recovered panic
// is converted into [ErrPanic] and described through the returned
// [failure], which carries the panic value and the stack trace onto the
// caller's single audit emission: the recover block deliberately emits
// nothing itself, because the non-nil error it returns already earns a
// record from [Dispatch] and a panic would otherwise be counted twice —
// once at Error level with reason "panic" and once at Info level with
// reason "handler_error".
//
// The stack rides on the audit record so SOC tooling can correlate the
// crash without it ever reaching the wire response.
func (d *Dispatcher) invokeHandler(ctx context.Context, h Handler, req Request) (resp Response, fail failure, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			fail = failure{
				reason: "panic",
				extras: map[string]any{
					"panic_value": fmt.Sprint(rec),
					"stack":       string(debug.Stack()),
				},
			}
			err = ErrPanic
		}
	}()
	resp, err = h.Handle(ctx, req)
	if err != nil {
		return resp, failure{reason: "handler_error"}, err
	}
	return resp, failure{}, nil
}

// validateResponse enforces the post-handler invariants the OP
// guarantees regardless of handler bugs: exactly one of AccessToken /
// BoundAccessToken is supplied, the lifetime is non-negative
// (truncated to the dispatcher's global cap on the way through),
// Scope is a subset of the client's allowed set, Audience (on both
// the response and the bound mint) is a subset of the client's
// registered resources. The function mutates *resp in place when a
// value is truncated so the caller writes the validated shape.
func (d *Dispatcher) validateResponse(client *store.Client, resp *Response) error {
	if err := d.validateAccessTokenShape(resp); err != nil {
		return err
	}
	if err := d.validateBoundAccessToken(client, resp); err != nil {
		return err
	}
	if !scopeSubset(resp.Scope, client.Scopes) {
		return ErrScopeNotAllowed
	}
	if !audienceSubset(resp.Audience, client.Resources) {
		return ErrAudienceNotAllowed
	}
	return nil
}

// validateAccessTokenShape rejects responses that set both forms of
// access token or neither, then applies the global TTL cap to the
// handler-supplied AccessTokenTTL. The function is the gate that runs
// before [validateBoundAccessToken] inspects the bound mint.
func (d *Dispatcher) validateAccessTokenShape(resp *Response) error {
	if resp.AccessToken != "" && resp.BoundAccessToken != nil {
		return ErrConflictingAccessTokenForms
	}
	if resp.AccessToken == "" && resp.BoundAccessToken == nil {
		return ErrEmptyAccessToken
	}
	if resp.AccessTokenTTL < 0 {
		return ErrNegativeTTL
	}
	if d.maxAccessTTL > 0 && resp.AccessTokenTTL > d.maxAccessTTL {
		resp.AccessTokenTTL = d.maxAccessTTL
	}
	return nil
}

// validateBoundAccessToken applies the TTL cap and audience subset
// gate to a non-nil BoundAccessToken. Nil short-circuits to a no-op
// so the caller can invoke it unconditionally.
func (d *Dispatcher) validateBoundAccessToken(client *store.Client, resp *Response) error {
	if resp.BoundAccessToken == nil {
		return nil
	}
	if resp.BoundAccessToken.TTL < 0 {
		return ErrNegativeTTL
	}
	if d.maxAccessTTL > 0 && resp.BoundAccessToken.TTL > d.maxAccessTTL {
		resp.BoundAccessToken.TTL = d.maxAccessTTL
	}
	if !audienceSubset(resp.BoundAccessToken.Audience, client.Resources) {
		return ErrAudienceNotAllowed
	}
	return nil
}

// filterForm applies the [ParamPolicy] to the inbound form. Unknown
// parameters trigger [ErrUnknownParameter]; duplicates trigger
// [ErrDuplicateParameter] unless the name is in [DupesAllowed],
// in which case the dispatcher caps the value count at [DupCap]
// before passing the slice through. Shared parameters every grant
// uses (grant_type, client_id, client_secret, client_assertion,
// client_assertion_type) are implicit and excluded from the
// "unknown parameter" check — they are consumed by the layers that
// run before Dispatch.
func filterForm(in url.Values, policy ParamPolicy) (map[string][]string, error) {
	allowed := make(map[string]bool, len(policy.Allowed))
	for _, name := range policy.Allowed {
		allowed[name] = true
	}
	dupes := make(map[string]bool, len(policy.DupesAllowed))
	for _, name := range policy.DupesAllowed {
		dupes[name] = true
	}
	out := make(map[string][]string, len(allowed))
	for name, values := range in {
		if isImplicitFormParameter(name) {
			continue
		}
		if !allowed[name] {
			return nil, fmt.Errorf("%w: %q", ErrUnknownParameter, name)
		}
		if len(values) > 1 && !dupes[name] {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateParameter, name)
		}
		if len(values) > DupCap {
			return nil, fmt.Errorf("%w: %q (%d values)", ErrDuplicateCapExceeded, name, len(values))
		}
		out[name] = slices.Clone(values)
	}
	return out, nil
}

// parseScopeParam reads the canonical RFC 6749 §3.3 space-delimited
// scope form value. The dispatcher exposes the parsed slice on
// [Request.RequestedScope] so handlers that participate in scope
// decisions (token-exchange) read a single normalised shape.
func parseScopeParam(in url.Values) []string {
	raw := in.Get("scope")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, " ")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// isImplicitFormParameter reports whether name is one of the
// shared-by-every-grant parameters the layers around Dispatch
// already consumed. The list is the union of the grant_type
// dispatch parameter, the client-authentication parameters
// (client_id / client_secret / client_assertion /
// client_assertion_type), and the OAuth scope parameter — the OP
// owns scope intersection so a handler that names "scope" in its
// Allowed list would receive an empty value.
func isImplicitFormParameter(name string) bool {
	switch name {
	case "grant_type",
		"client_id",
		"client_secret",
		"client_assertion",
		"client_assertion_type",
		"scope":
		return true
	default:
		return false
	}
}

// clientGrantPermitted reports whether client.GrantTypes lists the
// requested grant_type. An empty client.GrantTypes is treated as
// "no grants permitted"; the OP's option layer guarantees at least
// authorization_code is registered for every interactive client, so
// the empty case is a hand-built fixture mistake worth surfacing.
func clientGrantPermitted(client *store.Client, grantType string) bool {
	if client == nil {
		return false
	}
	return slices.Contains(client.GrantTypes, grantType)
}

// scopeSubset reports whether every entry of want is present in
// allowed. An empty want vacuously satisfies the check.
func scopeSubset(want, allowed []string) bool {
	for _, scope := range want {
		if !slices.Contains(allowed, scope) {
			return false
		}
	}
	return true
}

// audienceSubset reports whether every entry of want is present in
// allowed, under the OP-wide equality policy
// ([resourceindicator.ContainsLabel]): a handler that returns the
// canonical form for a resource indicator the embedder registered with
// a trailing slash (or a default port) still satisfies the allow-list,
// and a value carrying a fragment or userinfo satisfies nothing. An
// empty want vacuously satisfies the check.
func audienceSubset(want, allowed []string) bool {
	for _, aud := range want {
		if !resourceindicator.ContainsLabel(allowed, aud) {
			return false
		}
	}
	return true
}

// emitRequested records one dispatch attempt on the audit sink. The
// record carries the grant_type and client_id but never the raw form
// (which may include handler-private business data).
func (d *Dispatcher) emitRequested(ctx context.Context, in DispatchInput) {
	d.auditEmit.Emit(ctx, audit.Event{
		Name:     AuditEventRequested,
		Level:    audit.LevelInfo,
		Message:  "custom grant requested",
		ClientID: clientIDOf(in.Client),
		ActorID:  in.SubjectID,
		Extras: map[string]any{
			"grant_type": in.GrantType,
		},
	})
}

// emitFailed records a dispatch rejection on the audit sink. A panic is
// reported at Error level; every other rejection is an ordinary
// protocol outcome and stays at Info.
func (d *Dispatcher) emitFailed(ctx context.Context, in DispatchInput, fail failure) {
	extras := map[string]any{
		"grant_type": in.GrantType,
		"reason":     fail.reason,
	}
	for k, v := range fail.extras {
		extras[k] = v
	}
	level := audit.LevelInfo
	message := "custom grant rejected"
	if fail.reason == "panic" {
		level = audit.LevelError
		message = "custom grant handler panicked"
	}
	d.auditEmit.Emit(ctx, audit.Event{
		Name:     AuditEventFailed,
		Level:    level,
		Message:  message,
		ClientID: clientIDOf(in.Client),
		ActorID:  in.SubjectID,
		Extras:   extras,
	})
}

// clientIDOf returns the client_id string or the empty string when
// the input is nil. Centralised so the audit emitters do not
// duplicate the nil-check.
func clientIDOf(c *store.Client) string {
	if c == nil {
		return ""
	}
	return c.ID
}
