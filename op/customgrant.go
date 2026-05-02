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
	//   - req.DPoP / req.MTLSCert are populated when the client
	//     presented the corresponding credential and the OP's
	//     profile required it; nil otherwise.
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
	// the client presented one; nil otherwise. Handlers thread the
	// [DPoPProof.JKT] into the response so the OP stamps cnf.jkt
	// on the issued access token.
	DPoP *DPoPProof

	// MTLSCert is the client's leaf certificate when the request
	// was authenticated via [RFC 8705] mutual-TLS; nil otherwise.
	// The OP has already verified the chain and bound the client_id;
	// handlers thread the certificate into the response so the OP
	// stamps cnf.x5t#S256 on the issued access token.
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
//     A non-empty [IDToken] is treated as embedder-signed and copied
//     to the response verbatim.
//
// Stable since v0.9.1.
type CustomGrantResponse struct {
	// AccessToken is the opaque or JWT-shape access token. Non-empty.
	AccessToken string

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
	// [IDToken] is empty. The names are unrestricted; the OP
	// reserves the standard JWT set (iss / sub / aud / iat / exp /
	// auth_time / nonce / acr / amr / azp / at_hash / c_hash) and
	// silently drops attempts to override them.
	ExtraClaims map[string]any
}

// DPoPProof is the public projection of an RFC 9449 §4.3 verified
// proof handed to a [CustomGrantHandler.Handle] invocation. The
// struct is small on purpose — the cryptographic verification, jti
// replay tracking, and nonce challenge bookkeeping all live inside
// the OP; handlers receive only the values they need to thread the
// resulting binding into the issued access token.
//
// Stable since v0.9.1.
type DPoPProof struct {
	// JKT is the RFC 7638 SHA-256 thumbprint of the proof's JWK,
	// base64url-no-pad. Handlers thread the value into the
	// response so the OP stamps cnf.jkt on the issued access
	// token; subsequent uses of the credential then bind to the
	// same key.
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
	return customgrant.Response{
		AccessToken:    resp.AccessToken,
		AccessTokenTTL: resp.AccessTokenTTL,
		RefreshToken:   resp.RefreshToken,
		IDToken:        resp.IDToken,
		Scope:          append([]string(nil), resp.Scope...),
		Audience:       append([]string(nil), resp.Audience...),
		ExtraClaims:    cloneClaims(resp.ExtraClaims),
	}, nil
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
// registration order. The discovery builder consults the result to
// extend grant_types_supported beyond the built-in catalogue. The
// helper lives next to the dispatcher constructor so a future change
// to the registration store updates both call sites at once.
func customGrantNamesFor(c *config) []string {
	handlers := c.customGrantHandlers()
	if len(handlers) == 0 {
		return nil
	}
	out := make([]string, 0, len(handlers))
	for _, h := range handlers {
		out = append(out, h.Name())
	}
	return out
}

// buildCustomGrantDispatcher constructs the [customgrant.Dispatcher]
// the token endpoint consults for grant_type values that match none
// of the built-in cases. The function returns nil when no handlers
// were registered so the caller can short-circuit the wiring instead
// of mounting an empty dispatcher.
func (c *config) buildCustomGrantDispatcher() *customgrant.Dispatcher {
	handlers := c.customGrantHandlers()
	if len(handlers) == 0 {
		return nil
	}
	adapters := make([]customgrant.Handler, len(handlers))
	for i, h := range handlers {
		adapters[i] = customGrantAdapter{upstream: h}
	}
	opts := []customgrant.Option{
		customgrant.WithMaxAccessTTL(c.accessTokenTTL),
		customgrant.WithAudit(c.effectiveAuditEmitter()),
	}
	if c.clock != nil {
		opts = append(opts, customgrant.WithClock(c.clock.Now))
	}
	return customgrant.New(adapters, opts...)
}
