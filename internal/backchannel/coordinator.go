package backchannel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// DefaultTokenTTL is the lifetime stamped onto a Logout Token's `exp`
// claim when the embedder does not override it. The OpenID Connect
// Back-Channel Logout 1.0 spec recommends a short window (a couple of
// minutes); two minutes is generous enough to survive RP processing
// latency without leaving long-lived signed material in flight.
const DefaultTokenTTL = 2 * time.Minute

// DefaultMaxConcurrentDeliveries bounds simultaneous outbound logout requests.
const DefaultMaxConcurrentDeliveries = 8

// DefaultMaxTargets bounds the post-deduplication audience set for one logout.
const DefaultMaxTargets = 256

// DefaultFanOutBudget bounds the wall-clock lifetime of one detached
// fan-out started by [Coordinator.NotifyDetached]. The per-RP timeout
// alone does not bound the whole event: with the shipped defaults a
// fully unresponsive audience would occupy
// DefaultMaxTargets / DefaultMaxConcurrentDeliveries waves of
// [DefaultTimeout] each. The budget caps the total instead, so a
// detached fan-out cannot outlive the process by more than this
// window. Targets abandoned when the budget elapses fail their
// delivery with the context error and are recorded as
// [eventFailed], so nothing disappears silently.
const DefaultFanOutBudget = 30 * time.Second

// DefaultMaxInflightFanOuts bounds how many detached fan-outs may run
// at once. Detaching removes the natural back-pressure the request
// path used to provide, so the coordinator applies its own: once the
// cap is reached a further fan-out is shed rather than queued, and the
// shed is recorded as [eventFailed] with a "fanout_capacity" stage.
// The cap exists so an adversary who registers black-holing
// backchannel_logout_uri values cannot convert a burst of logouts into
// an unbounded pile of long-lived outbound connections.
const DefaultMaxInflightFanOuts = 256

// auditEvent names lifted from op.AuditEvent. The internal package
// references them as raw strings so the import graph stays one-way
// (op depends on internal, not the reverse). The op package guards
// the values with a mirror test (op/audit_test.go).
const (
	eventDelivered         = string(auditevent.AuditLogoutBackChannelDelivered)
	eventFailed            = string(auditevent.AuditLogoutBackChannelFailed)
	eventResolveFailed     = string(auditevent.AuditLogoutBackChannelResolveFailed)
	eventOverflow          = string(auditevent.AuditLogoutBackChannelOverflow)
	eventNoSessionsForSubj = string(auditevent.AuditBCLNoSessionsForSubject)
)

// SessionDurabilityPosture is the embedder's declaration of how
// SessionStore writes flow through their persistence tier. The
// coordinator does not act on the value at runtime — it propagates
// the posture into the audit event extras so SOC tooling can
// distinguish "expected gap under volatile placement" from
// "unexpected gap under durable placement" without keying on the
// store-adapter type. The op package mirrors the type as
// [op.SessionDurabilityPosture] and threads the embedder's
// [op.WithSessionDurabilityPosture] choice through the wiring.
type SessionDurabilityPosture int

const (
	// PostureVolatile is the default. SessionStore writes are
	// best-effort; eviction / failover may remove rows the
	// back-channel coordinator would walk. OIDC Back-Channel Logout
	// 1.0 §2.7 explicitly classifies delivery as best-effort, so
	// the volatile floor is spec-conformant — but the audit signal
	// makes the gap observable when it fires.
	PostureVolatile SessionDurabilityPosture = iota

	// PostureDurable declares that SessionStore writes survive
	// process restarts and tier failover. Embedders flipping the
	// declaration MUST route SessionStore to a durable backend
	// (the SQL adapter, an embedder-supplied store with WAL
	// semantics, etc.). The coordinator does not enforce the
	// declaration; embedders who lie about durability will see
	// the audit event fire under conditions the dashboard's
	// "durable" filter does not expect.
	PostureDurable
)

// String returns the lower-case attribute value the audit event
// emits ("volatile" or "durable") so dashboards can filter by
// string equality without needing to import the constant.
func (p SessionDurabilityPosture) String() string {
	switch p {
	case PostureDurable:
		return "durable"
	default:
		return "volatile"
	}
}

// Coordinator orchestrates back-channel logout fan-out. The
// embedder constructs one at startup (the op package wires it into
// [internal/endsession.Deps]) and reuses it across logout events;
// the struct is safe for concurrent use.
//
// The coordinator pulls a bounded, distinct audience page from the
// [op/store.GrantClientLister] and looks each client up in the
// [op/store.ClientStore]. Clients without a
// registered backchannel_logout_uri are skipped silently — they have
// opted out by configuration, not by error. Deliveries run through a bounded
// worker pool.
//
// Two entry points share that machinery. [Coordinator.Notify] blocks
// until all admitted deliveries complete or the parent context
// expires; it is the seam tests and embedder-driven fan-outs use.
// [Coordinator.NotifyDetached] runs the same fan-out on a background
// goroutine under its own deadline and is what the /end_session
// handler calls, so a stalled RP never holds the end-user's logout
// response open.
type Coordinator struct {
	issuer           string
	signing          SigningKey
	clients          store.ClientStore
	grants           store.GrantClientLister
	subjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error)
	deliverer        Deliverer
	emitter          audit.Emitter
	clock            timex.Clock
	tokenTTL         time.Duration
	posture          SessionDurabilityPosture
	maxConcurrent    int
	maxTargets       int
	fanOutBudget     time.Duration

	// slots is the capacity semaphore for detached fan-outs: a buffered
	// channel whose capacity is the in-flight cap. A non-blocking send
	// admits a fan-out, the goroutine receives from it on exit.
	slots chan struct{}

	// running counts detached fan-outs that have been admitted and not
	// yet finished. [Coordinator.Drain] waits on it.
	running sync.WaitGroup
}

// Config carries the construction-time dependencies for [NewCoordinator].
// The struct is a plain bag; the constructor copies the values onto
// the receiver and returns an error on any missing required field.
type Config struct {
	// Issuer is the OP's canonical issuer URL. Stamped onto every
	// Logout Token's `iss` claim. Required.
	Issuer string

	// Signing carries the active OP signing key. Required.
	Signing SigningKey

	// Clients is the registry the coordinator consults for each
	// candidate audience. Required.
	Clients store.ClientStore

	// Grants is the store the coordinator queries to enumerate the
	// audience clients for a terminating subject. Required. The concrete
	// value must implement [store.GrantClientLister]; the OP guarantees
	// this by rejecting an interactive configuration whose GrantStore lacks
	// the extension at op.New.
	Grants store.GrantClientLister

	// SubjectProjector converts the OP-internal subject into the
	// per-client subject value used in the Logout Token's sub claim.
	// Nil preserves the raw subject. Pairwise deployments wire the same
	// projector used by ID token / userinfo / introspection issuance.
	SubjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error)

	// Deliverer ships the signed token to one RP. A nil value
	// substitutes [NewHTTPDeliverer] with [DefaultTimeout]; tests
	// inject [DelivererFunc] to capture deliveries.
	Deliverer Deliverer

	// Emitter receives the per-delivery audit record. A nil value
	// substitutes [audit.Discard()] so the coordinator is safe to
	// construct without a wired audit logger.
	Emitter audit.Emitter

	// Clock supplies the iat / exp wall-clock readings. A nil value
	// substitutes [timex.SystemClock]; tests inject a fixed clock so
	// the token timestamps are deterministic.
	Clock timex.Clock

	// TokenTTL overrides the lifetime stamped onto exp. A zero value
	// substitutes [DefaultTokenTTL].
	TokenTTL time.Duration

	// SessionDurabilityPosture carries the embedder's declaration of
	// how SessionStore writes flow through their persistence tier.
	// The coordinator stamps the value into the
	// [eventNoSessionsForSubj] audit event's extras so dashboards can
	// distinguish expected gaps under volatile placement from
	// unexpected gaps under durable placement. Default
	// [PostureVolatile].
	SessionDurabilityPosture SessionDurabilityPosture

	// MaxConcurrentDeliveries limits active outbound requests. Zero selects
	// [DefaultMaxConcurrentDeliveries]; negative values are invalid.
	MaxConcurrentDeliveries int

	// MaxTargets limits the deduplicated audience set. Zero selects
	// [DefaultMaxTargets]; negative values are invalid.
	MaxTargets int

	// FanOutBudget caps the total wall-clock time one detached fan-out
	// may occupy, per [Coordinator.NotifyDetached]. Zero selects
	// [DefaultFanOutBudget]; negative values are invalid.
	FanOutBudget time.Duration

	// MaxInflightFanOuts limits concurrently running detached fan-outs.
	// Zero selects [DefaultMaxInflightFanOuts]; negative values are
	// invalid.
	MaxInflightFanOuts int
}

// validate reports the first missing required dependency or
// out-of-range bound in cfg. Splitting it out of [NewCoordinator]
// keeps the constructor's remaining body about defaulting, so the two
// concerns stay separately readable as bounds are added.
func (c Config) validate() error {
	switch {
	case c.Issuer == "":
		return errors.New("backchannel: Config.Issuer is empty")
	case c.Signing.Signer == nil:
		return errors.New("backchannel: Config.Signing has nil Signer")
	case c.Clients == nil:
		return errors.New("backchannel: Config.Clients is nil")
	case c.Grants == nil:
		return errors.New("backchannel: Config.Grants is nil")
	case c.MaxConcurrentDeliveries < 0:
		return errors.New("backchannel: Config.MaxConcurrentDeliveries is negative")
	case c.MaxTargets < 0:
		return errors.New("backchannel: Config.MaxTargets is negative")
	case c.FanOutBudget < 0:
		return errors.New("backchannel: Config.FanOutBudget is negative")
	case c.MaxInflightFanOuts < 0:
		return errors.New("backchannel: Config.MaxInflightFanOuts is negative")
	default:
		return nil
	}
}

// NewCoordinator validates cfg and returns a ready-to-use
// [Coordinator]. The function fails fast on missing required
// dependencies; optional fields fall back to their package defaults.
func NewCoordinator(cfg Config) (*Coordinator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	deliverer := cfg.Deliverer
	if deliverer == nil {
		deliverer = NewHTTPDeliverer(DefaultTimeout)
	}
	emitter := cfg.Emitter
	if emitter == nil {
		emitter = audit.Discard()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = timex.SystemClock
	}
	ttl := cfg.TokenTTL
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	maxConcurrent := cfg.MaxConcurrentDeliveries
	if maxConcurrent == 0 {
		maxConcurrent = DefaultMaxConcurrentDeliveries
	}
	maxTargets := cfg.MaxTargets
	if maxTargets == 0 {
		maxTargets = DefaultMaxTargets
	}
	budget := cfg.FanOutBudget
	if budget == 0 {
		budget = DefaultFanOutBudget
	}
	maxInflight := cfg.MaxInflightFanOuts
	if maxInflight == 0 {
		maxInflight = DefaultMaxInflightFanOuts
	}
	return &Coordinator{
		issuer:           cfg.Issuer,
		signing:          cfg.Signing,
		clients:          cfg.Clients,
		grants:           cfg.Grants,
		subjectProjector: cfg.SubjectProjector,
		deliverer:        deliverer,
		emitter:          emitter,
		clock:            clock,
		tokenTTL:         ttl,
		posture:          cfg.SessionDurabilityPosture,
		maxConcurrent:    maxConcurrent,
		maxTargets:       maxTargets,
		fanOutBudget:     budget,
		slots:            make(chan struct{}, maxInflight),
	}, nil
}

// Notice carries the per-event input the [Coordinator] needs to
// dispatch a fan-out. The fields are the data the caller already has
// at logout time (subject + optional sid + correlation ids); the
// coordinator translates the notice into a list of [Target]s by
// querying the configured stores.
type Notice struct {
	// Subject is the OP-internal subject identifier of the
	// terminating session. Required: the coordinator uses it as the
	// query key against [op/store.GrantStore.ListClientIDsBySubject].
	Subject string

	// SessionID is the OP browser-session identifier used only for
	// audit correlation. It is never copied into a Logout Token:
	// the current grant model cannot prove that an OP-side SID belongs
	// to a particular RP.
	SessionID string

	// RequestID is the per-request correlation identifier propagated
	// to the audit record so operators can join the back-channel
	// outcome to the originating /end_session call.
	RequestID string
}

// Notify resolves the audience client list for the supplied notice
// and dispatches a Logout Token to each one. The function blocks
// until every delivery has completed (or the parent context has
// expired). It returns the number of deliveries attempted; transient
// per-RP failures are surfaced through audit events rather than the
// return error so a single broken RP does not defeat the entire
// fan-out.
//
// The function returns an error when a precondition fails, the grant audience
// page cannot be read, or one or more ClientStore lookups fail. Lookup faults
// are aggregated after all resolvable targets have been delivered; missing
// clients are stale grants and are skipped. Each backend fault also emits a
// retryable [eventFailed] evidence record.
func (c *Coordinator) Notify(ctx context.Context, notice Notice) (int, error) {
	if notice.Subject == "" {
		return 0, errors.New("backchannel: Notice.Subject is empty")
	}
	page, err := c.grants.ListClientIDsBySubject(ctx, notice.Subject, "", c.maxTargets)
	if err != nil {
		return 0, err
	}
	if page.NextCursor != "" {
		c.emitOverflow(ctx, notice, page.NextCursor)
	}
	targets, resolutionErr := c.resolveTargets(ctx, page.ClientIDs, notice)
	if len(targets) == 0 {
		if resolutionErr == nil {
			c.emitNoSessionsForSubject(ctx, notice)
		}
		return 0, resolutionErr
	}
	now := c.clock.Now().UTC()
	iat := now.Unix()
	exp := now.Add(c.tokenTTL).Unix()

	jobs := make(chan Target)
	workers := min(c.maxConcurrent, len(targets))
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				c.dispatchOne(ctx, target, notice, iat, exp)
			}
		}()
	}
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	wg.Wait()
	return len(targets), resolutionErr
}

// NotifyDetached runs the [Coordinator.Notify] fan-out on a background
// goroutine and returns immediately. It is the entry point the
// /end_session handler uses so the end-user's logout response is
// written as soon as the OP-side session is durably gone, instead of
// waiting on the slowest relying party.
//
// Detaching is sound because OpenID Connect Back-Channel Logout 1.0
// defines delivery as a back-channel exchange independent of the
// end-user's user agent, and explicitly allows an RP to miss a Logout
// Token (for instance while temporarily unreachable). Nothing in
// RP-Initiated Logout 1.0 conditions the logout response — the static
// page or the post_logout_redirect_uri redirect — on delivery having
// happened. What the OP still owes the user is that its own session is
// terminated first; that step stays on the request path.
//
// The background work is bounded three ways:
//
//   - a per-fan-out deadline (Config.FanOutBudget) so the goroutine
//     cannot outlive the request indefinitely. The context is derived
//     with [context.WithoutCancel] so request-scoped values (request
//     id, trace context) still reach the audit records, while the
//     browser disconnecting no longer aborts delivery;
//   - the existing per-RP timeout, target cap, and worker-pool width;
//   - a cap on concurrently running fan-outs
//     (Config.MaxInflightFanOuts). Over the cap the fan-out is shed
//     and audited rather than queued.
//
// Nothing is returned: the caller has already answered the browser, so
// every outcome — per-RP delivery result, target-resolution fault,
// capacity shed — is reported through the audit emitter instead.
func (c *Coordinator) NotifyDetached(ctx context.Context, notice Notice) {
	select {
	case c.slots <- struct{}{}:
	default:
		c.emitFanOutShed(ctx, notice)
		return
	}
	base := context.WithoutCancel(ctx)
	detached, cancel := context.WithTimeout(base, c.fanOutBudget)
	c.running.Add(1)
	go func() {
		defer c.running.Done()
		defer cancel()
		defer func() { <-c.slots }()
		if _, err := c.Notify(detached, notice); err != nil {
			c.emitFanOutFailure(base, notice, err)
		}
	}()
}

// Drain blocks until every detached fan-out admitted before the call
// has finished, or until ctx expires, in which case it returns ctx's
// error. It backs the OP's public graceful-shutdown seam and is also
// how tests observe a detached fan-out deterministically.
//
// Draining is not what bounds the background work — each fan-out is
// self-limiting through Config.FanOutBudget, so a process that never
// drains still converges. What Drain adds is the ability to wait for
// that convergence instead of racing process exit and losing the
// Logout Tokens still in flight.
//
// The method holds no closed state: it does not stop further fan-outs
// from being admitted, so a caller that wants a quiescent coordinator
// must first stop the traffic that starts them.
func (c *Coordinator) Drain(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		c.running.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// emitFanOutShed records a fan-out that was refused because the
// in-flight cap was already saturated. The event is deliberately the
// same one a per-RP failure raises: from an operator's point of view a
// shed fan-out is a set of RPs that were not notified, which is what
// the back-channel failure signal already means. The "failure_stage"
// extra distinguishes it for anyone who needs the detail.
func (c *Coordinator) emitFanOutShed(ctx context.Context, notice Notice) {
	c.emitEvent(ctx, audit.Event{
		Name:      eventFailed,
		Level:     audit.LevelError,
		Message:   "back-channel logout fan-out shed: in-flight limit reached",
		ActorID:   notice.Subject,
		SessionID: notice.SessionID,
		RequestID: notice.RequestID,
		Extras: map[string]any{
			"failure_stage":         "fanout_capacity",
			"max_inflight_fan_outs": cap(c.slots),
			"retryable":             true,
		},
	})
}

// emitFanOutFailure records the aggregate error [Coordinator.Notify]
// would otherwise have returned to the caller. Detaching removed that
// return path, so the audit record is what replaces it; the per-target
// evidence records ([eventFailed] from resolveTargets / dispatchOne)
// continue to fire alongside it.
func (c *Coordinator) emitFanOutFailure(ctx context.Context, notice Notice, cause error) {
	c.emitEvent(ctx, audit.Event{
		Name:      eventResolveFailed,
		Level:     audit.LevelError,
		Message:   "back-channel logout target resolution failed",
		ActorID:   notice.Subject,
		SessionID: notice.SessionID,
		RequestID: notice.RequestID,
		Extras: map[string]any{
			"error": cause.Error(),
		},
	})
}

func (c *Coordinator) emitOverflow(ctx context.Context, notice Notice, nextCursor string) {
	c.emitEvent(ctx, audit.Event{
		Name:      eventOverflow,
		Level:     audit.LevelWarn,
		Message:   "back-channel logout target limit exceeded",
		ActorID:   notice.Subject,
		SessionID: notice.SessionID,
		RequestID: notice.RequestID,
		Extras: map[string]any{
			"max_targets":  c.maxTargets,
			"more_targets": true,
			"next_cursor":  nextCursor,
		},
	})
}

// resolveTargets walks a bounded page of distinct client IDs, looks each
// candidate up in the registry, and projects the eligible
// ones into [Target] values. A client is eligible when:
//
//   - the registry returns the record without error. A missing client is
//     skipped silently because the grant likely outlived the registration;
//     backend faults are audited, aggregated, and returned after the other
//     candidates have been resolved;
//   - BackchannelLogoutURI is non-empty;
//   - BackchannelLogoutSessionRequired is false. New registrations with
//     true are rejected; skipping legacy rows avoids issuing a sub-only
//     token to a client that explicitly requires sid.
//
//nolint:gocognit // Target resolution is intentionally linear to keep skip reasons local.
func (c *Coordinator) resolveTargets(
	ctx context.Context,
	clientIDs []string,
	notice Notice,
) ([]Target, error) {
	out := make([]Target, 0, len(clientIDs))
	var faults []error
	for _, clientID := range clientIDs {
		client, err := c.clients.GetClient(ctx, clientID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			fault := fmt.Errorf("resolve client %q: %w", clientID, err)
			faults = append(faults, fault)
			c.emitResolutionFailure(ctx, notice, clientID, "client_lookup", fault)
			continue
		}
		if client == nil {
			fault := fmt.Errorf("resolve client %q: ClientStore returned nil client without error", clientID)
			faults = append(faults, fault)
			c.emitResolutionFailure(ctx, notice, clientID, "client_lookup", fault)
			continue
		}
		if client.BackchannelLogoutURI == "" {
			continue
		}
		if client.BackchannelLogoutSessionRequired {
			continue
		}
		subject := notice.Subject
		if c.subjectProjector != nil {
			projected, err := c.subjectProjector(ctx, notice.Subject, client)
			if err != nil {
				fault := fmt.Errorf("project subject for client %q: %w", clientID, err)
				faults = append(faults, fault)
				c.emitResolutionFailure(ctx, notice, clientID, "subject_projection", fault)
				continue
			}
			if projected == "" {
				fault := fmt.Errorf("project subject for client %q: empty subject", clientID)
				faults = append(faults, fault)
				c.emitResolutionFailure(ctx, notice, clientID, "subject_projection", fault)
				continue
			}
			subject = projected
		}
		out = append(out, Target{
			ClientID: clientID,
			Subject:  subject,
			URL:      client.BackchannelLogoutURI,
		})
	}
	return out, errors.Join(faults...)
}

func (c *Coordinator) emitResolutionFailure(
	ctx context.Context,
	notice Notice,
	clientID, stage string,
	cause error,
) {
	c.emitEvent(ctx, audit.Event{
		Name:      eventFailed,
		Level:     audit.LevelError,
		Message:   "back-channel logout target resolution failed",
		ActorID:   notice.Subject,
		ClientID:  clientID,
		SessionID: notice.SessionID,
		RequestID: notice.RequestID,
		Extras: map[string]any{
			"error":         cause.Error(),
			"failure_stage": stage,
			"retryable":     true,
		},
	})
}

// dispatchOne mints, signs, and ships a Logout Token for one
// audience. Delivery outcome is recorded as an audit event; the
// function never propagates the per-RP error to the caller because
// fan-out is best-effort by design.
func (c *Coordinator) dispatchOne(
	ctx context.Context,
	target Target,
	notice Notice,
	iat, exp int64,
) {
	claims := LogoutClaims{
		Issuer:    c.issuer,
		Audience:  target.ClientID,
		IssuedAt:  iat,
		ExpiresAt: exp,
		Subject:   target.Subject,
	}
	token, err := SignLogoutToken(c.signing, claims)
	if err != nil {
		c.emit(ctx, eventFailed, notice, target, audit.LevelError,
			"sign logout token failed", err)
		return
	}
	if err := c.deliverer.Deliver(ctx, target, token); err != nil {
		c.emit(ctx, eventFailed, notice, target, audit.LevelWarn,
			"deliver logout token failed", err)
		return
	}
	c.emit(ctx, eventDelivered, notice, target, audit.LevelInfo,
		"logout token delivered", nil)
}

// emitNoSessionsForSubject fires the
// [eventNoSessionsForSubj] audit signal when the coordinator's
// session walk returned zero RPs to notify. The event is gated on
// notice.SessionID being non-empty: a logout call that does not
// name a session has no expectation of a fan-out, and emitting
// then would generate noise on every Provider.Logout call against
// a stale subject. INFO-level because under volatile session
// placement the gap is the spec-conformant best-effort floor;
// dashboards alert on elevated rates rather than on individual
// occurrences.
func (c *Coordinator) emitNoSessionsForSubject(ctx context.Context, notice Notice) {
	if notice.SessionID == "" {
		return
	}
	c.emitEvent(ctx, audit.Event{
		Name:      eventNoSessionsForSubj,
		Level:     audit.LevelInfo,
		Message:   "back-channel logout: no RPs to notify for subject",
		ActorID:   notice.Subject,
		SessionID: notice.SessionID,
		RequestID: notice.RequestID,
		Extras: map[string]any{
			"session_durability_posture": c.posture.String(),
		},
	})
}

// emitEvent is the single funnel every audit record in this package
// passes through. It strips cancellation from ctx before handing the
// event to the emitter: the fan-out runs under a deadline, and an
// emitter that writes to a context-aware sink would otherwise drop
// exactly the records describing the deliveries that deadline
// abandoned. Request-scoped values (request id, trace context) survive
// the strip, so correlation is unaffected.
func (c *Coordinator) emitEvent(ctx context.Context, ev audit.Event) {
	c.emitter.Emit(context.WithoutCancel(ctx), ev)
}

// emit assembles the audit record. The helper centralises the field
// projection so the success and failure paths cannot drift; the
// canonical fields (event, client_id, session_id, request_id) live
// at the top level and the per-event detail (target URL, error)
// rides under "extras" where the redactor can mask anything
// sensitive that ends up there.
func (c *Coordinator) emit(
	ctx context.Context,
	name string,
	notice Notice,
	target Target,
	level audit.Level,
	message string,
	cause error,
) {
	extras := map[string]any{
		"backchannel_logout_uri": target.URL,
	}
	if cause != nil {
		extras["error"] = cause.Error()
	}
	c.emitEvent(ctx, audit.Event{
		Name:      name,
		Level:     level,
		Message:   message,
		ActorID:   notice.Subject,
		ClientID:  target.ClientID,
		SessionID: notice.SessionID,
		RequestID: notice.RequestID,
		Extras:    extras,
	})
}
