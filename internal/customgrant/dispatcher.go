package customgrant

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"runtime/debug"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Audit event names. The strings here MUST agree with the public
// op.AuditCustomGrant* constants in op/audit.go; the op_test package
// owns a guard that compares both lists.
const (
	AuditEventRequested = "custom_grant.requested"
	AuditEventFailed    = "custom_grant.failed"
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

	// ErrEmptyAccessToken signals the handler returned an empty
	// AccessToken. Maps to server_error; the wire response carries
	// no detail so a misbehaving handler cannot probe for issuance
	// internals.
	ErrEmptyAccessToken = errors.New("custom_grant: handler returned empty access_token")

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
func (d *Dispatcher) Dispatch(ctx context.Context, in DispatchInput) (Response, error) {
	if d == nil || len(d.handlers) == 0 {
		return Response{}, ErrUnknownGrant
	}
	handler := d.lookup(in.GrantType)
	if handler == nil {
		return Response{}, ErrUnknownGrant
	}
	if !clientGrantPermitted(in.Client, in.GrantType) {
		d.emitFailed(ctx, in, "client_grant_not_permitted")
		return Response{}, ErrClientGrantNotPermitted
	}
	policy := handler.ParamPolicy()
	form, err := filterForm(in.Form, policy)
	if err != nil {
		d.emitFailed(ctx, in, "form_policy_violation")
		return Response{}, err
	}
	req := Request{
		Client:    in.Client,
		SubjectID: in.SubjectID,
		AuthTime:  in.AuthTime,
		Form:      form,
		DPoPJKT:   in.DPoPJKT,
		DPoPJTI:   in.DPoPJTI,
	}
	if cert, ok := in.MTLSCert.(*x509.Certificate); ok {
		req.MTLSCert = cert
	}
	resp, err := d.invokeHandler(ctx, handler, req)
	if err != nil {
		d.emitFailed(ctx, in, "handler_error")
		return Response{}, err
	}
	if err := d.validateResponse(in.Client, &resp); err != nil {
		d.emitFailed(ctx, in, "response_invalid")
		return Response{}, err
	}
	d.emitRequested(ctx, in)
	return resp, nil
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

// invokeHandler runs the handler with panic recovery. A recovered
// panic is converted into [ErrPanic]; the stack trace rides on the
// audit emission via [emitFailed] so SOC tooling can correlate the
// crash without leaking it to the wire response.
func (d *Dispatcher) invokeHandler(ctx context.Context, h Handler, req Request) (resp Response, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			stack := debug.Stack()
			d.auditEmit.Emit(ctx, audit.Event{
				Name:     AuditEventFailed,
				Level:    audit.LevelError,
				Message:  "custom grant handler panicked",
				ClientID: clientIDOf(req.Client),
				Extras: map[string]any{
					"grant_type":  h.Name(),
					"reason":      "panic",
					"panic_value": fmt.Sprint(rec),
					"stack":       string(stack),
				},
			})
			err = ErrPanic
		}
	}()
	resp, err = h.Handle(ctx, req)
	return resp, err
}

// validateResponse enforces the post-handler invariants the OP
// guarantees regardless of handler bugs: AccessToken is non-empty,
// AccessTokenTTL is non-negative (truncated to the dispatcher's
// global cap on the way through), Scope is a subset of the client's
// allowed set, Audience is a subset of the client's registered
// resources. The function mutates *resp in place when a value is
// truncated so the caller writes the validated shape.
func (d *Dispatcher) validateResponse(client *store.Client, resp *Response) error {
	if resp.AccessToken == "" {
		return ErrEmptyAccessToken
	}
	if resp.AccessTokenTTL < 0 {
		return ErrNegativeTTL
	}
	if d.maxAccessTTL > 0 && resp.AccessTokenTTL > d.maxAccessTTL {
		resp.AccessTokenTTL = d.maxAccessTTL
	}
	if !scopeSubset(resp.Scope, client.Scopes) {
		return ErrScopeNotAllowed
	}
	if !audienceSubset(resp.Audience, client.Resources) {
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
// allowed. An empty want vacuously satisfies the check.
func audienceSubset(want, allowed []string) bool {
	for _, aud := range want {
		if !slices.Contains(allowed, aud) {
			return false
		}
	}
	return true
}

// emitRequested records a successful dispatch on the audit sink.
// The record carries the grant_type and client_id but never the
// raw form (which may include handler-private business data).
func (d *Dispatcher) emitRequested(ctx context.Context, in DispatchInput) {
	d.auditEmit.Emit(ctx, audit.Event{
		Name:     AuditEventRequested,
		Level:    audit.LevelInfo,
		Message:  "custom grant dispatched",
		ClientID: clientIDOf(in.Client),
		ActorID:  in.SubjectID,
		Extras: map[string]any{
			"grant_type": in.GrantType,
		},
	})
}

// emitFailed records a dispatch rejection on the audit sink. The
// reason string is a stable enum the dispatcher itself selects from
// so SOC tooling can pre-aggregate without parsing free-form text.
func (d *Dispatcher) emitFailed(ctx context.Context, in DispatchInput, reason string) {
	d.auditEmit.Emit(ctx, audit.Event{
		Name:     AuditEventFailed,
		Level:    audit.LevelInfo,
		Message:  "custom grant rejected",
		ClientID: clientIDOf(in.Client),
		ActorID:  in.SubjectID,
		Extras: map[string]any{
			"grant_type": in.GrantType,
			"reason":     reason,
		},
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
