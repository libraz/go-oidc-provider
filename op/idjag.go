package op

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// IDJAGIssuancePolicy admits each request to issue an Identity
// Assertion JWT Authorization Grant (ID-JAG) through RFC 8693 token
// exchange with requested_token_type
// urn:ietf:params:oauth:token-type:id-jag. Register it with
// [WithIDJAGIssuance].
//
// Before Allow runs the OP has authenticated the client (a "none"
// client is refused with invalid_client), verified that subject_token
// is an ID token this OP issued to that client, and required exactly
// one audience. Scope and resource name the audience authorization
// server's namespace, so the OP does not check them against the
// client's own registration; the policy is the only gate on them.
//
// Allow returns:
//
//   - a non-nil [IDJAGDecision] to issue;
//   - [ErrIDJAGUnknownAudience] when the audience is not an
//     authorization server the policy issues for (invalid_target);
//   - [ErrIDJAGDenied], or a nil decision with a nil error, to refuse
//     (access_denied);
//   - any other error to answer server_error.
//
// Implementations are called from the request goroutine; they MUST be
// safe for concurrent use.
//
// Experimental: tracks an IETF draft, so the surface MAY change in a
// minor release on a wire-incompatible draft bump.
type IDJAGIssuancePolicy interface {
	Allow(ctx context.Context, req IDJAGRequest) (*IDJAGDecision, error)
}

// IDJAGRequest is the verified token-exchange request handed to
// [IDJAGIssuancePolicy.Allow].
//
// Experimental: tracks an IETF draft, so the surface MAY change in a
// minor release on a wire-incompatible draft bump.
type IDJAGRequest struct {
	// Client is the authenticated requesting client.
	Client *store.Client

	// Subject is the sub of the presented ID token.
	Subject Subject

	// Audience is the issuer identifier of the authorization server the
	// ID-JAG is for.
	Audience string

	// Resource is the requested resource values, verbatim; empty when
	// the request named none.
	Resource []string

	// Scope is the requested scope values, in the audience's namespace.
	Scope []string
}

// IDJAGDecision is what an [IDJAGIssuancePolicy] issues.
//
// Experimental: tracks an IETF draft, so the surface MAY change in a
// minor release on a wire-incompatible draft bump.
type IDJAGDecision struct {
	// ClientID is the requesting client's identifier at the audience
	// authorization server, written to the client_id claim. Required;
	// an empty value answers server_error.
	ClientID string

	// Scope is the granted scope, in the audience's namespace.
	Scope []string

	// Resource is the granted resource values. Each MUST be one of
	// [IDJAGRequest.Resource], verbatim; anything else answers
	// server_error. Empty while the request named resources answers
	// invalid_target.
	Resource []string

	// Email is written to the email claim when non-empty. The OP holds
	// no verified email of its own, so the value is the embedder's.
	Email string

	// TTL is the ID-JAG lifetime. Zero, and anything above five
	// minutes, yields five minutes.
	TTL time.Duration
}

// ErrIDJAGUnknownAudience is the sentinel an [IDJAGIssuancePolicy]
// returns when the requested audience is not an authorization server it
// issues ID-JAGs for. The token endpoint maps it to invalid_target.
//
// Experimental: tracks an IETF draft, so the surface MAY change in a
// minor release on a wire-incompatible draft bump.
var ErrIDJAGUnknownAudience = errors.New("op: ID-JAG audience is not a known authorization server")

// ErrIDJAGDenied is the sentinel an [IDJAGIssuancePolicy] returns to
// refuse an ID-JAG. The token endpoint maps it to access_denied.
//
// Experimental: tracks an IETF draft, so the surface MAY change in a
// minor release on a wire-incompatible draft bump.
var ErrIDJAGDenied = errors.New("op: ID-JAG issuance denied")
