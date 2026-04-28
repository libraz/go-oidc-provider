package backchannel

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// DefaultTokenTTL is the lifetime stamped onto a Logout Token's `exp`
// claim when the embedder does not override it. The OpenID Connect
// Back-Channel Logout 1.0 spec recommends a short window (a couple of
// minutes); two minutes is generous enough to survive RP processing
// latency without leaving long-lived signed material in flight.
const DefaultTokenTTL = 2 * time.Minute

// auditEvent names lifted from op.AuditEvent. The internal package
// references them as raw strings so the import graph stays one-way
// (op depends on internal, not the reverse). The op package guards
// the values with a mirror test (op/audit_test.go).
const (
	eventDelivered = "logout.back_channel.delivered"
	eventFailed    = "logout.back_channel.failed"
)

// Coordinator orchestrates back-channel logout fan-out. The
// embedder constructs one at startup (the op package wires it into
// [internal/endsession.Deps]) and reuses it across logout events;
// the struct is safe for concurrent use.
//
// The coordinator pulls audience clients from the [op/store.GrantStore]
// (every active grant for the terminating subject becomes a candidate)
// and looks each up in the [op/store.ClientStore]. Clients without a
// registered backchannel_logout_uri are skipped silently — they have
// opted out by configuration, not by error. Each delivery runs in its
// own goroutine; the coordinator blocks until all deliveries complete
// or the parent context expires.
type Coordinator struct {
	issuer    string
	signing   SigningKey
	clients   store.ClientStore
	grants    store.GrantStore
	deliverer Deliverer
	emitter   audit.Emitter
	clock     timex.Clock
	tokenTTL  time.Duration
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
	// audience clients for a terminating subject. Required.
	Grants store.GrantStore

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
}

// NewCoordinator validates cfg and returns a ready-to-use
// [Coordinator]. The function fails fast on missing required
// dependencies; optional fields fall back to their package defaults.
func NewCoordinator(cfg Config) (*Coordinator, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("backchannel: Config.Issuer is empty")
	}
	if cfg.Signing.Signer == nil {
		return nil, errors.New("backchannel: Config.Signing has nil Signer")
	}
	if cfg.Clients == nil {
		return nil, errors.New("backchannel: Config.Clients is nil")
	}
	if cfg.Grants == nil {
		return nil, errors.New("backchannel: Config.Grants is nil")
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
	return &Coordinator{
		issuer:    cfg.Issuer,
		signing:   cfg.Signing,
		clients:   cfg.Clients,
		grants:    cfg.Grants,
		deliverer: deliverer,
		emitter:   emitter,
		clock:     clock,
		tokenTTL:  ttl,
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
	// query key against [op/store.GrantStore.ListBySubject].
	Subject string

	// SessionID is the OP session identifier. Optional but strongly
	// recommended: every client that registered
	// backchannel_logout_session_required is skipped when this field
	// is empty.
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
// The function returns an error only when the precondition fails:
// empty Subject, or a store fault on the initial ListBySubject. A
// per-RP delivery failure is logged via [audit.Event] of name
// [eventFailed]; a successful delivery emits [eventDelivered].
func (c *Coordinator) Notify(ctx context.Context, notice Notice) (int, error) {
	if notice.Subject == "" {
		return 0, errors.New("backchannel: Notice.Subject is empty")
	}
	grants, err := c.grants.ListBySubject(ctx, notice.Subject)
	if err != nil {
		return 0, err
	}
	targets := c.resolveTargets(ctx, grants, notice.SessionID)
	if len(targets) == 0 {
		return 0, nil
	}
	now := c.clock.Now().UTC()
	iat := now.Unix()
	exp := now.Add(c.tokenTTL).Unix()

	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(target Target) {
			defer wg.Done()
			c.dispatchOne(ctx, target, notice, iat, exp)
		}(t)
	}
	wg.Wait()
	return len(targets), nil
}

// resolveTargets walks the grants returned by the store, looks each
// candidate client up in the registry, and projects the eligible
// ones into [Target] values. A client is eligible when:
//
//   - the registry returns the record without error (a missing client
//     is skipped silently — the grant likely outlived the
//     registration);
//   - BackchannelLogoutURI is non-empty;
//   - if BackchannelLogoutSessionRequired is true the notice carries
//     a SessionID — otherwise the spec contract cannot be honoured.
func (c *Coordinator) resolveTargets(ctx context.Context, grants []*store.Grant, sid string) []Target {
	out := make([]Target, 0, len(grants))
	seen := make(map[string]struct{}, len(grants))
	for _, g := range grants {
		if g == nil {
			continue
		}
		if _, dup := seen[g.ClientID]; dup {
			continue
		}
		client, err := c.clients.GetClient(ctx, g.ClientID)
		if err != nil || client == nil {
			continue
		}
		if client.BackchannelLogoutURI == "" {
			continue
		}
		if client.BackchannelLogoutSessionRequired && sid == "" {
			continue
		}
		seen[g.ClientID] = struct{}{}
		out = append(out, Target{
			ClientID: client.ID,
			URL:      client.BackchannelLogoutURI,
		})
	}
	return out
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
		Subject:   notice.Subject,
		SessionID: notice.SessionID,
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
	c.emitter.Emit(ctx, audit.Event{
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
