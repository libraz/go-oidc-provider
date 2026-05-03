package op

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// CustomGrantHandler is the embedder-supplied component that backs an
// extension grant_type at the token endpoint. The interface is the
// single seam through which the OP routes a token request whose
// grant_type matches none of the built-in values
// (authorization_code / refresh_token / client_credentials /
// urn:ietf:params:oauth:grant-type:device_code). Embedders register
// handlers via [WithCustomGrant]; the OP runs client authentication,
// rate limiting, and DPoP / mTLS verification before invoking
// [Handle], so handlers receive a request that has already cleared
// the surface every grant shares.
//
// The interface is small on purpose. The OP keeps ownership of:
//
//   - parameter parsing, duplicate-key policy ([ParamPolicy]),
//   - access-token / refresh-token persistence, revocation, audit,
//   - id_token signing (the handler MAY return a pre-signed token,
//     otherwise the OP signs from [CustomGrantResponse.ExtraClaims]),
//   - scope / audience enforcement (the response is validated against
//     the client's allowed scopes and resource server policy),
//   - TTL bounds (handler-supplied TTL is truncated to the OP's
//     global cap before issuance).
//
// Handlers are invoked from the request goroutine and MUST be safe
// for concurrent use. A panic inside [Handle] is converted to an
// RFC 6749 server_error with the stack trace routed to the audit
// log only — the response body never leaks the panic message.
//
// Stable since v0.9.1.
type CustomGrantHandler interface {
	// Name returns the grant_type URN this handler answers to. The
	// value is matched byte-for-byte against the request's
	// grant_type parameter. RFC 6749 §4.5 strongly recommends URN
	// form ("urn:ietf:params:oauth:grant-type:..."), but the OP
	// does not enforce a syntactic shape — collisions with the
	// built-in grant types are rejected at [WithCustomGrant] time.
	Name() string

	// ParamPolicy returns the parameter handling policy the OP
	// applies to the token-endpoint form before [Handle] runs. The
	// value is consulted once at construction; mutating the
	// returned struct after registration has no effect.
	ParamPolicy() ParamPolicy

	// Handle executes the grant. The OP guarantees:
	//
	//   - req.Client is non-nil and matches the authenticated
	//     client; mutating it has no persistence effect (the OP
	//     reads from a defensive copy after the call).
	//   - req.Form contains every parameter the policy [Allowed]
	//     list named, and only those; values are guaranteed to be
	//     non-secret (RFC 6749 §3.2 secret-like names cannot be
	//     [DupesAllowed]).
	//   - req.DPoP / req.MTLSCert are populated whenever the client
	//     successfully presented the corresponding credential; nil
	//     otherwise. The values are independent of the active profile —
	//     the handler decides whether to bind the issued token (the OP
	//     does not synthesise cnf for handler-supplied tokens; see
	//     [CustomGrantResponse] for the binding contract).
	//
	// A non-nil error MUST be either an [*Error] (the wire envelope
	// the OP returns verbatim) or a generic Go error (mapped to
	// invalid_grant by default with the message redacted from the
	// response body).
	Handle(ctx context.Context, req CustomGrantRequest) (CustomGrantResponse, error)
}

// ParamPolicy declares how the OP parses the token-endpoint form
// before [CustomGrantHandler.Handle] runs. The two lists answer
// disjoint questions:
//
//   - Allowed names the parameters the handler reads. The OP rejects
//     unknown parameters with invalid_request before calling Handle.
//     The shared parameters every grant uses (grant_type, client_id,
//     client_secret, scope, ...) are implicit — list only the
//     handler-specific extras.
//   - DupesAllowed names the parameters where repeated occurrences
//     are accepted as a []string slice. RFC 6749 §3.2 forbids
//     duplicates by default; this list is the explicit per-handler
//     opt-in. The OP rejects any name that names a security-sensitive
//     parameter (grant_type / client_id / client_secret / code /
//     code_verifier / refresh_token / subject_token / actor_token /
//     password / client_assertion / client_assertion_type) at
//     [WithCustomGrant] time so a misconfigured handler cannot
//     downgrade the credential surface.
//
// A duplicate count above [CustomGrantDupCap] (default 32) yields
// invalid_request regardless of [DupesAllowed] — the cap exists so
// a misbehaving peer cannot exhaust memory by sending the same
// allowed-duplicate parameter thousands of times.
//
// Stable since v0.9.1.
type ParamPolicy struct {
	// Allowed is the closed list of handler-specific parameters
	// the OP exposes in [CustomGrantRequest.Form]. The names are
	// matched case-sensitively; RFC 6749 §3.2 leaves the case
	// question to the AS but case folding here would let a peer
	// smuggle a duplicate by varying the case.
	Allowed []string

	// DupesAllowed is the subset of [Allowed] that admits repeated
	// values. Names not present here are rejected with
	// invalid_request on the second occurrence.
	DupesAllowed []string
}

// CustomGrantDupCap is the hard cap on the number of values the OP
// accepts for any single duplicate-allowed parameter. The cap exists
// so a misbehaving peer cannot inflate memory by repeating the same
// name thousands of times; 32 is two orders of magnitude above the
// realistic upper bound for token-exchange-style multi-actor flows.
//
// Stable since v0.9.1.
const CustomGrantDupCap = 32

// CustomGrantRequest is the input the OP hands the handler. The struct
// is read-only by contract — handlers MUST NOT mutate the embedded
// values; the OP retains references to [Client] and [Form] for audit
// emission and may observe later mutations as racy reads.
//
// Stable since v0.9.1.
type CustomGrantRequest struct {
	// Client is the authenticated client record. Non-nil; the OP
	// has already verified credentials and policy gates by the time
	// [Handle] runs. Handlers MAY read scope / audience / metadata
	// off the client to derive the response shape.
	Client *store.Client

	// Subject is the resource owner the request acts on behalf of.
	// Nil for delegation-style grants where the client owns the
	// identity (token-exchange impersonation, client_credentials).
	// When non-nil, the OP has confirmed the subject exists and is
	// reachable through the configured [Store].
	Subject *Subject

	// AuthTime is the wall-clock time the subject most recently
	// authenticated. Zero when [Subject] is nil. Handlers SHOULD
	// thread this into the issued id_token's auth_time claim
	// (the OP does so automatically when [CustomGrantResponse.IDToken]
	// is empty).
	AuthTime time.Time

	// Form contains the parsed token-endpoint parameters the
	// [ParamPolicy] admitted. Single-value parameters appear with
	// a one-element slice; [DupesAllowed] parameters may appear
	// with up to [CustomGrantDupCap] values. The map is owned by
	// the OP — handlers MUST NOT mutate it.
	Form map[string][]string

	// DPoP is the projection of the verified RFC 9449 proof when
	// the client presented one; nil otherwise. The OP has verified
	// the proof and consumed the jti by the time Handle runs;
	// handlers that mint a JWT access token MUST embed cnf.jkt =
	// [DPoPProof.JKT] in the JWT claims to satisfy RFC 9449 §6.1.
	// Handlers that mint an opaque access token are responsible for
	// surfacing the binding through their own introspection backend —
	// the OP does not maintain a shadow row for handler-supplied
	// access tokens.
	DPoP *DPoPProof

	// MTLSCert is the client's leaf certificate when the request
	// was authenticated via [RFC 8705] mutual-TLS; nil otherwise.
	// The OP has already verified the chain and bound the client_id;
	// handlers that mint a JWT access token MUST embed cnf.x5t#S256
	// (the SHA-256 thumbprint of the certificate) in the JWT claims
	// to satisfy RFC 8705 §3.1. Handlers that mint an opaque access
	// token are responsible for surfacing the binding through their
	// own introspection backend.
	MTLSCert *x509.Certificate
}

// CustomGrantResponse is the result the handler returns. The OP
// validates and re-shapes the values before persisting and writing
// the wire response:
//
//   - [AccessTokenTTL] is truncated to the OP's global access-token
//     cap (default 1 hour); a longer value yields an audit warning
//     but never overrides the cap.
//   - [Scope] is intersected with the client's allowed scopes;
//     handler-introduced scopes outside that set yield invalid_scope.
//   - [Audience] entries are intersected with the resource servers
//     registered for the client; unknown audiences yield invalid_target.
//   - When [IDToken] is empty and [Scope] contains "openid", the OP
//     signs a fresh id_token from [ExtraClaims] merged with the
//     standard claim set (iss / sub / aud / iat / exp / auth_time).
//     [Subject] supplies the "sub" claim; an empty Subject in this
//     case yields server_error because OIDC Core 1.0 §2 requires the
//     claim. A non-empty [IDToken] is treated as embedder-signed and
//     copied to the response verbatim — [Subject] / [AuthTime] /
//     [ExtraClaims] are ignored on that path.
//
// Stable since v0.9.1.
type CustomGrantResponse struct {
	// AccessToken is the opaque or JWT-shape access token the OP
	// writes verbatim. Non-empty when [BoundAccessToken] is nil;
	// mutually exclusive with [BoundAccessToken] (setting both yields
	// server_error). Use this field when the handler signs with an
	// out-of-band key (HSM/KMS) or mints an opaque value backed by
	// its own introspection backend.
	AccessToken string

	// BoundAccessToken, when non-nil, instructs the OP to mint a JWT
	// access token using its active signing key and stamp the
	// request's cnf binding (cnf.jkt for DPoP, cnf.x5t#S256 for mTLS)
	// automatically. Mutually exclusive with [AccessToken] — setting
	// both yields server_error. Use this field when the handler has
	// no out-of-band signing key and wants the OP to enforce the
	// FAPI 2.0 §3.1.4 binding contract on its behalf.
	//
	// Stable since v0.9.1.
	BoundAccessToken *BoundAccessToken

	// AccessTokenTTL is the lifetime the OP advertises in the
	// expires_in field. A zero value falls back to the global
	// access-token TTL; a negative value is rejected at issuance.
	AccessTokenTTL time.Duration

	// RefreshToken is the optional refresh credential. An empty
	// value omits the field from the wire response. The OP does
	// not interpret the value beyond persisting it; rotation and
	// expiry remain a handler concern unless the handler is built
	// on top of the in-tree refresh-token store.
	RefreshToken string

	// IDToken, when non-empty, is the embedder-signed JWT the OP
	// returns verbatim. When empty and [Scope] contains "openid",
	// the OP signs a fresh id_token from [ExtraClaims].
	IDToken string

	// Subject is the OP-internal "sub" claim value the OP writes
	// into the id_token it signs when [IDToken] is empty and Scope
	// contains "openid". Required on that path; the empty value
	// yields server_error so a delegation-style grant that should
	// not advertise an end-user sub MUST omit "openid" from Scope.
	// Ignored when [IDToken] is non-empty (the embedder-signed
	// token already carries its own "sub").
	Subject Subject

	// AuthTime is the wall-clock time the subject most recently
	// authenticated. Threaded onto the id_token "auth_time" claim
	// when [IDToken] is empty; zero omits the claim. Ignored when
	// [IDToken] is non-empty.
	AuthTime time.Time

	// Scope is the issued scope set; the wire response folds it
	// into a space-separated string. The slice is intersected with
	// the client's allowed scopes by the OP; entries outside that
	// set yield invalid_scope.
	Scope []string

	// Audience is the issued audience set, written into the
	// access token's aud claim and the introspection projection.
	// Each entry MUST match a resource registered for the client.
	Audience []string

	// ExtraClaims are merged into the id_token the OP signs when
	// [IDToken] is empty. The names MUST NOT collide with the
	// standard JWT set the OP manages itself (iss / sub / aud /
	// iat / exp / auth_time / nonce / acr / amr / azp / at_hash /
	// c_hash / sid); a colliding name yields server_error so the
	// handler bug surfaces in the audit record rather than silently
	// shipping a malformed token.
	ExtraClaims map[string]any
}

// BoundAccessToken instructs the OP to mint a JWT-shape access token
// with cnf binding stamped automatically. The handler supplies extra
// claims; the OP fills iss / sub / aud / exp / iat / jti / scope and
// (when the request carried a verified DPoP proof or mTLS leaf cert)
// cnf.jkt / cnf.x5t#S256.
//
// Use this when:
//   - your handler needs no out-of-band signing key,
//   - the issued token is a JWT (not opaque), and
//   - you want the OP to enforce the FAPI 2.0 §3.1.4 binding contract
//     automatically.
//
// Use [CustomGrantResponse.AccessToken] when:
//   - the handler signs with an external key (KMS/HSM), OR
//   - the issued token is opaque and the handler operates its own
//     introspection backend.
//
// [CustomGrantResponse.AccessToken] and [CustomGrantResponse.BoundAccessToken]
// are mutually exclusive — setting both yields server_error.
//
// Stable since v0.9.1.
type BoundAccessToken struct {
	// Subject is the "sub" claim. When the zero value, the OP
	// defaults to the request's Subject; a request whose Subject is
	// also nil yields server_error so a delegation-style grant that
	// has no end-user MUST set [Subject] explicitly.
	Subject Subject

	// Audience is the "aud" claim. When empty, the OP defaults to a
	// single-element slice containing client.ID. Each entry is
	// intersected with the client's registered resources by the
	// dispatcher's existing [CustomGrantResponse.Audience] gate.
	Audience []string

	// TTL is the access-token lifetime. Zero falls back to the OP's
	// global access-token cap; values exceeding the cap are
	// truncated with an audit warning (same policy as the
	// [CustomGrantResponse.AccessTokenTTL] field).
	TTL time.Duration

	// ExtraClaims are merged onto the standard JWT set the OP writes
	// (iss / sub / aud / exp / iat / jti / scope / client_id / cnf).
	// Names that collide with the standard set yield server_error so
	// the handler bug surfaces in the audit record rather than
	// silently shipping a malformed token.
	ExtraClaims map[string]any
}

// DPoPProof is the public projection of an RFC 9449 §4.3 verified
// proof handed to a [CustomGrantHandler.Handle] invocation. The
// struct is small on purpose — the cryptographic verification, jti
// replay tracking, and nonce challenge bookkeeping all live inside
// the OP; handlers receive only the values they need to bind the
// issued access token themselves.
//
// Stable since v0.9.1.
type DPoPProof struct {
	// JKT is the RFC 7638 SHA-256 thumbprint of the proof's JWK,
	// base64url-no-pad. The handler MUST embed cnf.jkt = JKT in any
	// JWT access token it issues so subsequent uses of the credential
	// bind to the same key (RFC 9449 §6.1). For opaque access tokens
	// the handler is responsible for surfacing the binding through
	// its own introspection backend; the OP does not maintain a
	// shadow row for handler-supplied access tokens.
	JKT string

	// JTI is the proof's "jti" claim. The OP has already marked
	// the value consumed in the dpop replay store by the time the
	// handler observes it; the field is exposed for audit logging
	// only.
	JTI string
}

// customGrantAdapter wraps a public [CustomGrantHandler] so it
// satisfies the internal [customgrant.Handler] surface. The
// indirection exists because internal/* packages cannot import op
// (the dispatcher would otherwise reach across the boundary). The
// adapter copies request / response slices defensively so a handler
// cannot mutate dispatcher-owned values after the call returns.
type customGrantAdapter struct {
	upstream CustomGrantHandler
}

// Name implements [customgrant.Handler].
func (a customGrantAdapter) Name() string { return a.upstream.Name() }

// ParamPolicy implements [customgrant.Handler].
func (a customGrantAdapter) ParamPolicy() customgrant.ParamPolicy {
	policy := a.upstream.ParamPolicy()
	return customgrant.ParamPolicy{
		Allowed:      append([]string(nil), policy.Allowed...),
		DupesAllowed: append([]string(nil), policy.DupesAllowed...),
	}
}

// Handle implements [customgrant.Handler]. The adapter translates
// the dispatcher's [customgrant.Request] into the public
// [CustomGrantRequest] shape, invokes the upstream handler, and
// translates the response back. SubjectID is wrapped into a
// [Subject] pointer when non-empty so the handler observes the
// declared "nil for delegation" contract.
func (a customGrantAdapter) Handle(ctx context.Context, req customgrant.Request) (customgrant.Response, error) {
	publicReq := CustomGrantRequest{
		Client:   req.Client,
		AuthTime: req.AuthTime,
		Form:     req.Form,
		MTLSCert: req.MTLSCert,
	}
	if req.SubjectID != "" {
		sub := Subject(req.SubjectID)
		publicReq.Subject = &sub
	}
	if req.DPoPJKT != "" {
		publicReq.DPoP = &DPoPProof{JKT: req.DPoPJKT, JTI: req.DPoPJTI}
	}
	resp, err := a.upstream.Handle(ctx, publicReq)
	if err != nil {
		return customgrant.Response{}, err
	}
	out := customgrant.Response{
		AccessToken:    resp.AccessToken,
		AccessTokenTTL: resp.AccessTokenTTL,
		RefreshToken:   resp.RefreshToken,
		IDToken:        resp.IDToken,
		Subject:        string(resp.Subject),
		AuthTime:       resp.AuthTime,
		Scope:          append([]string(nil), resp.Scope...),
		Audience:       append([]string(nil), resp.Audience...),
		ExtraClaims:    cloneClaims(resp.ExtraClaims),
	}
	if resp.BoundAccessToken != nil {
		out.BoundAccessToken = &customgrant.BoundAccessToken{
			Subject:     string(resp.BoundAccessToken.Subject),
			Audience:    append([]string(nil), resp.BoundAccessToken.Audience...),
			TTL:         resp.BoundAccessToken.TTL,
			ExtraClaims: cloneClaims(resp.BoundAccessToken.ExtraClaims),
		}
	}
	return out, nil
}

// cloneClaims returns a defensive copy of m or nil when m is nil.
// The dispatcher persists the result; a shared map would let a
// handler observe (and confuse) the OP's own bookkeeping reads.
func cloneClaims(m map[string]any) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// customGrantNamesFor returns the registered handler names in
// registration order, plus the token-exchange URN when the embedder
// invoked [RegisterTokenExchange]. The discovery builder consults the
// result to extend grant_types_supported beyond the built-in catalogue.
// The helper lives next to the dispatcher constructor so a future
// change to the registration store updates both call sites at once.
func customGrantNamesFor(c *config) []string {
	handlers := c.customGrantHandlers()
	out := make([]string, 0, len(handlers)+1)
	for _, h := range handlers {
		out = append(out, h.Name())
	}
	if c.tokenExchangePolicy != nil {
		out = append(out, TokenExchangeGrantType)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildCustomGrantDispatcher constructs the [customgrant.Dispatcher]
// the token endpoint consults for grant_type values that match none
// of the built-in cases. The function returns nil when no handlers
// were registered so the caller can short-circuit the wiring instead
// of mounting an empty dispatcher.
//
// The token-exchange handler (when [RegisterTokenExchange] was
// invoked) rides on the same dispatcher: its [customgrant.Handler]
// surface is appended to the embedder-supplied registrations so a
// single grant_type lookup table answers every extension grant. The
// helper takes the additional dependencies it needs through the
// supplied callback so the call site in op/op_router.go can hand the
// same keyset / store handles already wired into the token endpoint.
func (c *config) buildCustomGrantDispatcher(extra ...customgrant.Handler) *customgrant.Dispatcher {
	handlers := c.customGrantHandlers()
	if len(handlers) == 0 && len(extra) == 0 {
		return nil
	}
	adapters := make([]customgrant.Handler, 0, len(handlers)+len(extra))
	for _, h := range handlers {
		adapters = append(adapters, customGrantAdapter{upstream: h})
	}
	adapters = append(adapters, extra...)
	opts := []customgrant.Option{
		customgrant.WithMaxAccessTTL(c.accessTokenTTL),
		customgrant.WithAudit(c.effectiveAuditEmitter()),
	}
	if c.clock != nil {
		opts = append(opts, customgrant.WithClock(c.clock.Now))
	}
	return customgrant.New(adapters, opts...)
}
