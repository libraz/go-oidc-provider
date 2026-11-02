package assertiongrant

import (
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// ErrUnknownSubject is what an embedder's subject resolver returns for a
// verified assertion whose subject has no provisioned local account. The
// token endpoint answers it with access_denied rather than invalid_grant
// (draft-06 §4.4.3): the assertion is valid, re-obtaining it would not help.
var ErrUnknownSubject = errors.New("assertiongrant: assertion subject is not provisioned")

// ErrKeySourceUnavailable wraps a transient failure resolving an issuer's
// keys (fetch capacity pressure or a transient fetch error). It is a
// server-side fault, answered as retryable rather than as a bad assertion.
var ErrKeySourceUnavailable = errors.New("assertiongrant: issuer key source unavailable")

// Subject is the verified identity an assertion asserts, handed to the
// embedder's subject resolver.
type Subject struct {
	// Issuer is the assertion's iss, one of the configured issuers.
	Issuer string
	// Subject is the assertion's sub, verbatim.
	Subject string
	// ClientID is the authenticated client redeeming the assertion.
	ClientID string
	// Claims is the full verified claim set. Callers treat it as read-only.
	Claims map[string]any
}

// Profile selects the rule set an issuer's assertions are verified under.
type Profile int

const (
	// ProfileJWT is plain RFC 7523: typ absent or JWT, aud the OP issuer or
	// the token endpoint URL.
	ProfileJWT Profile = iota
	// ProfileIDJAG is the ID-JAG profile: typ oauth-id-jag+jwt, aud the OP
	// issuer only, and the client_id / scope / resource / cnf rules.
	ProfileIDJAG
)

// String returns the profile's audit-friendly name.
func (p Profile) String() string {
	switch p {
	case ProfileJWT:
		return "jwt"
	case ProfileIDJAG:
		return "id-jag"
	default:
		return "unknown"
	}
}

// Issuer is one trusted assertion issuer. Exactly one of JWKSURI and JWKS is
// set; the op layer validates the set before it reaches [New].
type Issuer struct {
	// Issuer is matched exactly against the assertion's iss.
	Issuer string
	// JWKSURI is the issuer's key document, resolved through the shared
	// relying-party fetcher with its cache and rotation refetch.
	JWKSURI string
	// JWKS is an inline key set, in the same representation as
	// store.Client.JWKs.
	JWKS []byte
	// Profile is the rule set this issuer's assertions are verified under.
	Profile Profile
}

// Binding is the proof of possession the redeeming request presented.
type Binding struct {
	// DPoPJKT is the RFC 7638 thumbprint of the request's DPoP key, or empty.
	DPoPJKT string
	// X5TS256 is the RFC 8705 certificate thumbprint of the request's mTLS
	// client certificate, or empty.
	X5TS256 string
}

// ClientContext is the authenticated client and request state the ID-JAG
// stage checks the assertion against.
type ClientContext struct {
	// ID is the authenticated client's client_id.
	ID string
	// Binding is the request's DPoP / mTLS binding.
	Binding Binding
	// RequestedScopes is the request's scope parameter, split on spaces.
	RequestedScopes []string
	// Resources is the client's registered resource set.
	Resources []string
}

// Result is a verified assertion.
type Result struct {
	// Subject is the verified identity, for the embedder's resolver.
	Subject Subject
	// Profile is the issuer's profile.
	Profile Profile
	// Scopes is the ID-JAG scope claim split on spaces; nil when absent or
	// under [ProfileJWT].
	Scopes []string
	// Resources is the ID-JAG resource claim in RFC 8707 canonical form;
	// nil when absent or under [ProfileJWT].
	Resources []string
	// ExpiresAt is the assertion's exp.
	ExpiresAt time.Time

	// jti is the identifier [Verifier.Consume] spends.
	jti string
}

// Reason names the verification stage that rejected an assertion. It is the
// reason the jwt_bearer.rejected audit event carries.
type Reason string

// The verification stages, in the order [Verifier.Verify] and
// [Verifier.Consume] run them.
const (
	ReasonParse     Reason = "parse"
	ReasonIssuer    Reason = "issuer"
	ReasonTyp       Reason = "typ"
	ReasonSignature Reason = "signature"
	ReasonClaims    Reason = "claims"
	ReasonIDJAG     Reason = "idjag"
	ReasonReplay    Reason = "replay"
)

// Error is a rejection of the assertion itself (invalid_grant).
type Error struct {
	// Reason is the stage that failed.
	Reason Reason
	// Err is the cause, safe to log but not to return to the client.
	Err error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return "assertiongrant: " + string(e.Reason)
	}
	return "assertiongrant: " + string(e.Reason) + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// Config configures [New].
type Config struct {
	// Issuers is the trusted issuer set. Required, non-empty, unique Issuer.
	Issuers []Issuer
	// KeySource resolves issuer keys. Required.
	KeySource *rpjwks.Fetcher
	// JTIs records consumed assertion identifiers. Required.
	JTIs store.ConsumedJTIStore
	// Clock drives every time comparison. Nil falls back to the system clock.
	Clock timex.Clock
	// OPIssuer is this OP's issuer, the aud both profiles accept. Required.
	OPIssuer string
	// TokenEndpointURL is the second aud [ProfileJWT] accepts. Empty disables it.
	TokenEndpointURL string
}
