package interaction

import "context"

// Driver is the contract a caller implements to plug a UI into the
// [op.Provider]. Implementations own scope metadata, authenticator
// presentation, and prompt resolution; the library owns every
// protocol-visible decision the OP makes around them.
//
// Implementations MUST be safe for concurrent use; the library calls
// every method from request-scoped goroutines.
type Driver interface {
	// Offer is invoked when the OP determines that the request requires
	// user interaction. It returns the [Step] the SPA must render. The
	// Driver MAY use ctx to carry tracing or to honour cancellation; it
	// MUST NOT block beyond the request deadline.
	Offer(ctx context.Context, req Request) (Step, error)

	// Verify is invoked after the SPA POSTs an interaction result. It
	// returns the [Decision] that tells the OP whether to complete the
	// flow or to keep prompting.
	Verify(ctx context.Context, req Request, result Result) (Decision, error)

	// Cancel is invoked when the interaction is abandoned (timeout, user
	// abort, downstream error). Implementations SHOULD release any
	// SPA-side state associated with req.UID. Cancel MUST NOT return
	// an error for unknown UIDs; it is best-effort.
	Cancel(ctx context.Context, req Request) error
}

// Request is the call-side context handed to a [Driver] method. It bundles
// the interaction identifier with the authorization-request fragments the
// Driver may need for prompt selection.
//
// The struct is small on purpose: drivers that need richer context (full
// AuthorizationRequest, client metadata) read it via the [op.Provider]
// helpers using [Request.UID] as the key.
type Request struct {
	// UID is the opaque interaction identifier. It MUST be treated as a
	// secret; embedding it in URLs is fine because the library binds it
	// to a CSRF token, but Drivers MUST NOT log raw UIDs.
	UID string

	// ClientID is the OAuth client_id of the relying party that started
	// the authorization request. It is provided so Drivers can short-
	// circuit lookups for prompt routing.
	ClientID string

	// CurrentSubject is the canonical subject of the active session, or
	// empty when no user is logged in. Drivers use it to skip prompts
	// when the authenticated user already satisfies the request.
	CurrentSubject string
}

// NoopDriver is a [Driver] implementation that produces no UI and rejects
// every request with PromptLogin / "no_driver_configured". It is the
// default when the caller does not pass [op.WithInteraction]; the OP
// remains usable for non-interactive grants (client_credentials).
//
// Drivers that need a permissive default for tests should consult
// [op/testkit] instead; NoopDriver is deliberately strict so production
// misconfigurations fail closed.
type NoopDriver struct{}

// Offer implements [Driver]. It always returns a PromptLogin step with a
// "no_driver_configured" reason so an accidentally-deployed Provider
// surfaces the missing UI immediately rather than 500ing.
func (NoopDriver) Offer(_ context.Context, _ Request) (Step, error) {
	return Step{
		Hint: Hint{
			Prompt:  PromptLogin,
			Reasons: []string{"no_driver_configured"},
		},
	}, nil
}

// Verify implements [Driver]. It always returns Continue=false with an
// error string so the SPA cannot complete a flow against a Provider that
// has no configured Driver.
func (NoopDriver) Verify(_ context.Context, _ Request, _ Result) (Decision, error) {
	return Decision{Error: "no_driver_configured"}, nil
}

// Cancel implements [Driver] as a no-op.
func (NoopDriver) Cancel(_ context.Context, _ Request) error { return nil }

// Compile-time confirmation that NoopDriver satisfies Driver.
var _ Driver = NoopDriver{}
