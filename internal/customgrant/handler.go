package customgrant

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Handler is the dispatch surface the op-supplied adapter satisfies.
// The shape mirrors op.CustomGrantHandler exactly; the indirection
// exists so internal/* code does not need to import the op package.
type Handler interface {
	// Name returns the grant_type URN the handler answers to. The
	// value is matched byte-for-byte against the request's
	// grant_type parameter; callers MUST guarantee uniqueness across
	// the registered handler set.
	Name() string

	// ParamPolicy returns the parameter-handling policy the
	// dispatcher enforces before [Handle] runs. The value is
	// consulted once per request; callers SHOULD return a stable
	// snapshot rather than recomputing on every invocation.
	ParamPolicy() ParamPolicy

	// Handle executes the grant. The dispatcher guarantees the
	// invariants documented on op.CustomGrantHandler before this
	// method runs: client authenticated, parameters parsed under
	// the policy, DPoP / mTLS verified.
	Handle(ctx context.Context, req Request) (Response, error)
}

// ParamPolicy mirrors op.ParamPolicy. See the public type for the
// authoritative documentation.
type ParamPolicy struct {
	// Allowed names the parameters [Handler.Handle] reads. Values
	// are matched case-sensitively; unknown parameters yield
	// invalid_request.
	Allowed []string

	// DupesAllowed is the subset of [Allowed] that admits repeated
	// values. The dispatcher rejects names that match the
	// security-sensitive parameter list at the option layer
	// (op.WithCustomGrant); the field exists here so dispatch-time
	// lookups stay self-contained.
	DupesAllowed []string
}

// Request is the input the dispatcher hands to a handler. The struct
// is read-only by contract; handlers MUST NOT mutate the embedded
// values.
type Request struct {
	// Client is the authenticated client record. Non-nil; the
	// dispatcher rejects unauthenticated requests before invoking
	// the handler.
	Client *store.Client

	// SubjectID is the resolved subject identifier when the request
	// targets an end-user, empty for delegation-style grants
	// (token-exchange impersonation, client_credentials-style flows
	// where the client owns the identity). The dispatcher does not
	// project this through a SubjectGenerator — the handler is
	// expected to resolve identity using whatever store hooks the
	// embedder configured.
	SubjectID string

	// AuthTime is the wall-clock time the subject most recently
	// authenticated. Zero when [SubjectID] is empty.
	AuthTime time.Time

	// Form contains the parsed token-endpoint parameters the
	// [ParamPolicy] admitted. Single-value parameters appear with
	// a one-element slice; [DupesAllowed] parameters may appear
	// with up to [DupCap] values.
	Form map[string][]string

	// DPoPJKT is the RFC 7638 thumbprint of a verified DPoP proof,
	// empty when the request did not present one. The dispatcher
	// has already invoked the verifier; handlers MUST NOT re-verify.
	DPoPJKT string

	// DPoPJTI is the proof's "jti" claim; empty when DPoPJKT is
	// empty. Useful for audit emission only — the replay store has
	// already marked the value consumed.
	DPoPJTI string

	// MTLSCert is the verified client leaf certificate when the
	// request authenticated via RFC 8705 mTLS, nil otherwise. The
	// dispatcher has already verified the chain and bound the
	// client_id; handlers thread the certificate into the response
	// so the dispatcher stamps cnf.x5t#S256 on the issued access
	// token.
	MTLSCert *x509.Certificate
}

// Response is the result a handler returns. The dispatcher validates
// and re-shapes the values before persisting and writing the wire
// response: TTL truncation, scope intersection, audience intersection,
// id_token signing from ExtraClaims when IDToken is empty.
type Response struct {
	// AccessToken is the opaque or JWT-shape access token.
	AccessToken string

	// AccessTokenTTL is the lifetime the dispatcher caps to the
	// global access-token TTL before issuance.
	AccessTokenTTL time.Duration

	// RefreshToken is the optional refresh credential. Empty omits
	// the field from the wire response.
	RefreshToken string

	// IDToken, when non-empty, is treated as embedder-signed and
	// returned verbatim. When empty and Scope contains "openid", the
	// wire layer signs a fresh id_token from ExtraClaims merged with
	// the standard claim set.
	IDToken string

	// Subject is the value the wire layer writes into the id_token
	// "sub" claim when [IDToken] is empty and Scope contains "openid".
	// Empty is permitted for delegation-style grants that do not
	// represent an end user (token-exchange impersonation,
	// client_credentials-style flows); the wire layer rejects an
	// openid-scoped response that returns an empty Subject because
	// id_token "sub" is REQUIRED per OIDC Core 1.0 §2.
	Subject string

	// AuthTime is the wall-clock time the subject most recently
	// authenticated; the wire layer threads it onto the issued
	// id_token's auth_time claim. Zero omits the claim.
	AuthTime time.Time

	// Scope is the issued scope set; intersected with
	// Client.Scopes by the dispatcher before issuance.
	Scope []string

	// Audience is the issued audience set; intersected with
	// Client.Resources by the dispatcher before issuance.
	Audience []string

	// ExtraClaims are merged into the id_token the wire layer signs
	// when IDToken is empty. Standard JWT claim names are reserved
	// and rejected by [tokens.SignIDToken].
	ExtraClaims map[string]any
}

// DupCap is the hard cap on the number of values the dispatcher
// accepts for any single duplicate-allowed parameter. Mirrors
// op.CustomGrantDupCap; defined here so internal callers do not
// import op.
const DupCap = 32
