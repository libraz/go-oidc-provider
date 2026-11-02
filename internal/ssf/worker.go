package ssf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/keys"
	internallog "github.com/libraz/go-oidc-provider/internal/log"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Push delivery shape. A claim takes at most workerStreamShare SETs of one
// stream, pushed one after another, and streams share workerConcurrency
// goroutines, so a round lasts at most (ceil(workerBatchSize/
// workerConcurrency) + workerStreamShare) × workerPushTimeout. That must
// stay under workerLease or another replica re-claims a SET mid-push.
const (
	workerBatchSize      = 32
	workerStreamShare    = 4
	workerConcurrency    = 8
	workerPushTimeout    = 5 * time.Second
	workerLease          = 60 * time.Second
	workerInterval       = 5 * time.Second
	workerExpiryInterval = time.Hour
)

// workerMaxErrCodeLen bounds the RFC 8935 err code copied into audit.
const workerMaxErrCodeLen = 64

// workerBackoff is the delay before retry n+1 after n failed pushes; one
// entry per retry. Each delay is jittered by ±workerJitterPct%.
//
//nolint:gochecknoglobals // immutable retry schedule.
var workerBackoff = [workerMaxRetries]time.Duration{time.Minute, 5 * time.Minute, 25 * time.Minute, 2 * time.Hour}

// workerMaxRetries is the retry budget after the first push.
const workerMaxRetries = 4

const workerJitterPct = 10

const (
	workerEventDelivered = string(auditevent.AuditSSFPushDelivered)
	workerEventRejected  = string(auditevent.AuditSSFPushRejected)
	workerEventRetried   = string(auditevent.AuditSSFPushRetried)
	workerEventAbandoned = string(auditevent.AuditSSFPushAbandoned)
)

// push_abandoned reasons.
const (
	workerReasonAttempts = "attempts"
	workerReasonSeal     = "seal"
	workerReasonClaims   = "claims"
)

// WorkerDeps are the construction-time dependencies of a [Worker].
type WorkerDeps struct {
	// Events and Streams are the SSF substores. Required.
	Events  store.SSFEventStore
	Streams store.SSFStreamStore

	// Sealer opens each stream's sealed authorization_header. Required.
	Sealer *Sealer

	// SigningKey returns the key active at dispatch time. Required.
	SigningKey func() (SigningKey, error)

	// AllowPrivateNetwork admits RFC 1918 / ULA / loopback push
	// endpoints. Cloud metadata addresses stay refused.
	AllowPrivateNetwork bool

	// AllowInsecureForDev admits http:// and loopback push endpoints.
	AllowInsecureForDev bool

	// Audit receives the ssf.push_* events. Nil discards.
	Audit audit.Emitter

	// Clock drives the loop's RunOnce instant and the expiry sweep. Nil
	// is the system clock.
	Clock timex.Clock

	// Logger records faults that leave a SET for its lease to expire.
	// Nil discards.
	Logger *slog.Logger
}

// Worker pushes queued SETs to receivers (RFC 8935). Each SET is signed
// with the key active when it is sent; a failed push is retried on the
// [workerBackoff] schedule and abandoned once the budget is spent. Safe
// for concurrent use; several replicas may run one each, since ClaimDue
// leases every SET to a single claimer.
type Worker struct {
	events     store.SSFEventStore
	streams    store.SSFStreamStore
	sealer     *Sealer
	signingKey func() (SigningKey, error)
	fetch      *securefetch.Client
	audit      audit.Emitter
	clock      timex.Clock
	logger     *slog.Logger
	interval   time.Duration

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewWorker builds a Worker. It does not start the loop; see [Worker.Start].
func NewWorker(d WorkerDeps) (*Worker, error) {
	switch {
	case d.Events == nil, d.Streams == nil:
		return nil, errors.New("ssf: WorkerDeps.Events and WorkerDeps.Streams are required")
	case d.Sealer == nil:
		return nil, errors.New("ssf: WorkerDeps.Sealer is required")
	case d.SigningKey == nil:
		return nil, errors.New("ssf: WorkerDeps.SigningKey is required")
	}
	emitter := audit.OrDiscard(d.Audit)
	logger := d.Logger
	if logger == nil {
		logger = slog.New(internallog.DiscardHandler{})
	}
	return &Worker{
		events:     d.Events,
		streams:    d.Streams,
		sealer:     d.Sealer,
		signingKey: d.SigningKey,
		fetch:      workerFetchClient(d.AllowPrivateNetwork, d.AllowInsecureForDev, workerPushTimeout),
		audit:      emitter,
		clock:      timex.OrSystem(d.Clock),
		logger:     logger,
		interval:   workerInterval,
	}, nil
}

// workerFetchClient builds the SSRF-hardened push client: https only and
// no loopback unless the dev flag is set, no redirects, a bounded body.
func workerFetchClient(allowPrivate, insecureDev bool, timeout time.Duration) *securefetch.Client {
	return securefetch.NewClient(securefetch.Policy{
		AllowPrivateNetwork:  allowPrivate,
		AllowLoopbackNetwork: insecureDev,
		AllowedSchemes:       securefetch.Schemes(insecureDev),
		MaxBodyBytes:         backchannel.MaxResponseBytes,
		Timeout:              timeout,
	})
}

// Start runs the delivery loop on a background goroutine: every interval
// it claims rounds of due SETs until the backlog is drained, and it runs
// DeleteExpired once an hour. Calls after the first are
// no-ops. ctx bounds the loop as [Worker.Stop] does.
func (w *Worker) Start(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return
	}
	w.started = true
	loopCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.done = make(chan struct{})
	go w.loop(loopCtx, w.done)
}

// Stop cancels the loop and any push in flight. A SET whose push was
// cut short keeps its lease and is claimed again once the lease ends.
// It does not wait; see [Worker.Drain].
func (w *Worker) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		w.cancel()
	}
}

// Drain blocks until the loop has exited or ctx expires, in which case
// it returns ctx's error. It returns at once when the loop never started.
func (w *Worker) Drain(ctx context.Context) error {
	w.mu.Lock()
	done := w.done
	w.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *Worker) loop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	var lastSweep time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := w.clock.Now()
		if lastSweep.IsZero() || now.Sub(lastSweep) >= workerExpiryInterval {
			lastSweep = now
			if _, err := w.events.DeleteExpired(ctx, now); err != nil && ctx.Err() == nil {
				w.logger.ErrorContext(ctx, "ssf: delete expired SETs", "error", err)
			}
		}
		w.runRounds(ctx)
	}
}

// runRounds runs claim rounds back to back while each one reports that
// more SETs may be due. Every claimed SET leaves the due set, by its lease
// or by settling, so the rounds end once the backlog is drained.
func (w *Worker) runRounds(ctx context.Context) {
	for ctx.Err() == nil {
		_, more, err := w.RunOnce(ctx, w.clock.Now())
		if err != nil {
			if ctx.Err() == nil {
				w.logger.ErrorContext(ctx, "ssf: claim due SETs", "error", err)
			}
			return
		}
		if !more {
			return
		}
	}
}

// RunOnce claims the SETs due at now, at most [workerStreamShare] per
// stream, and pushes each stream's share in order on one of
// [workerConcurrency] goroutines, so a stream has one push in flight and
// a stalled receiver holds a single slot. It returns once every stream's
// share is done and reports how many SETs it claimed, and whether more
// may be due: the claim was full, or a stream took its whole share
// without a failure.
func (w *Worker) RunOnce(ctx context.Context, now time.Time) (int, bool, error) {
	due, err := w.events.ClaimDue(ctx, now, workerBatchSize, workerStreamShare, workerLease)
	if err != nil {
		return 0, false, fmt.Errorf("ssf: claim due SETs: %w", err)
	}
	var drained atomic.Bool
	backchannel.EachBounded(workerConcurrency, perStreamShares(due), func(share []*store.SSFEvent) {
		if w.deliverShare(ctx, share, now) && len(share) == workerStreamShare {
			drained.Store(true)
		}
	})
	return len(due), len(due) == workerBatchSize || drained.Load(), nil
}

// perStreamShares splits a claimed batch into each stream's SETs, keeping
// the claim order within a stream.
func perStreamShares(due []*store.SSFEvent) [][]*store.SSFEvent {
	index := make(map[string]int)
	var out [][]*store.SSFEvent
	for _, ev := range due {
		i, ok := index[ev.StreamID]
		if !ok {
			i = len(out)
			index[ev.StreamID] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], ev)
	}
	return out
}

// deliverShare pushes one stream's SETs one at a time and stops at the
// first the receiver did not take: the rest keep their lease and come back
// once it ends, without spending the receiver's retry budget. It reports
// whether every SET was settled.
func (w *Worker) deliverShare(ctx context.Context, share []*store.SSFEvent, now time.Time) bool {
	// Settling must survive Stop: a receiver that already accepted the
	// SET must not get it again.
	settle := context.WithoutCancel(ctx)
	streamID := share[0].StreamID
	stream, err := w.streams.Get(ctx, streamID)
	if errors.Is(err, store.ErrNotFound) {
		for _, ev := range share {
			w.ack(settle, ev)
		}
		return true
	}
	if err != nil {
		w.logger.ErrorContext(ctx, "ssf: load stream for push", "stream_id", streamID, "error", err)
		return false
	}
	if stream.Delivery.Method != store.SSFDeliveryPush {
		// Switched to poll after the claim; the stream Update already
		// moved the rows to the poll queue.
		return false
	}
	for _, ev := range share {
		if !w.deliver(ctx, settle, stream, ev, now) {
			return false
		}
	}
	return true
}

// workerOutcome is one push's result.
type workerOutcome struct {
	status  int    // HTTP status; 0 for a transport failure
	errCode string // RFC 8935 err of a 400 response
	cause   error
}

// deliver pushes one claimed SET and settles it in the queue, reporting
// whether it was settled: delivered, rejected or abandoned. A fault on the
// OP side (signing key) leaves the SET leased, so it is retried after the
// lease without spending the receiver's budget.
func (w *Worker) deliver(ctx, settle context.Context, stream *store.SSFStream, ev *store.SSFEvent, now time.Time) bool {
	var authz string
	if len(stream.Delivery.SealedAuthorizationHeader) > 0 {
		var err error
		authz, err = w.sealer.Unseal(stream.ID, stream.Delivery.SealedAuthorizationHeader)
		if err != nil {
			w.abandon(settle, stream, ev, workerReasonSeal, workerOutcome{cause: err})
			return true
		}
	}
	key, err := w.signingKey()
	if err != nil {
		w.logger.ErrorContext(ctx, "ssf: signing key for push", "stream_id", stream.ID, "jti", ev.JTI, "error", err)
		return false
	}
	set, err := Sign(ev.Claims, key)
	if errors.Is(err, ErrInvalidClaims) {
		w.abandon(settle, stream, ev, workerReasonClaims, workerOutcome{cause: err})
		return true
	}
	if err != nil {
		w.logger.ErrorContext(ctx, "ssf: sign SET for push", "stream_id", stream.ID, "jti", ev.JTI, "error", err)
		return false
	}
	out := w.post(ctx, stream.Delivery.EndpointURL, authz, set)
	if out.status == 0 && ctx.Err() != nil {
		// Cut short by Stop; the lease brings it back.
		return false
	}
	switch out.status {
	case http.StatusAccepted:
		w.ack(settle, ev)
		w.emit(settle, workerEventDelivered, audit.LevelInfo, "security event token delivered", stream, ev, out, "", nil)
	case http.StatusBadRequest:
		w.ack(settle, ev)
		w.emit(settle, workerEventRejected, audit.LevelWarn, "security event token rejected by receiver", stream, ev, out, "", nil)
	default:
		w.retry(settle, stream, ev, now, out)
		return false
	}
	return true
}

// post sends set to endpoint and classifies the response.
func (w *Worker) post(ctx context.Context, endpoint, authz, set string) workerOutcome {
	req, err := w.fetch.NewRequest(ctx, http.MethodPost, endpoint, strings.NewReader(set))
	if err != nil {
		return workerOutcome{cause: err}
	}
	req.Header.Set("Content-Type", "application/"+TokenType)
	req.Header.Set("Accept", "application/json")
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := w.fetch.DoRaw(req)
	if err != nil {
		return workerOutcome{cause: err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, backchannel.MaxResponseBytes))
	out := workerOutcome{status: resp.StatusCode}
	if resp.StatusCode == http.StatusBadRequest {
		out.errCode = workerErrCode(body)
	}
	if resp.StatusCode != http.StatusAccepted {
		out.cause = fmt.Errorf("%w: %d", securefetch.ErrUnexpectedStatus, resp.StatusCode)
	}
	return out
}

// workerErrCode extracts the err member of an RFC 8935 §2.3 error body.
func workerErrCode(body []byte) string {
	var parsed struct {
		Err string `json:"err"`
	}
	if json.Unmarshal(body, &parsed) != nil || len(parsed.Err) > workerMaxErrCodeLen {
		return ""
	}
	return parsed.Err
}

// retry reschedules ev on the backoff schedule, or abandons it once the
// retry budget is spent.
func (w *Worker) retry(ctx context.Context, stream *store.SSFStream, ev *store.SSFEvent, now time.Time, out workerOutcome) {
	if ev.Attempts >= workerMaxRetries {
		w.abandon(ctx, stream, ev, workerReasonAttempts, out)
		return
	}
	next := now.Add(workerJitter(workerBackoff[ev.Attempts]))
	err := w.events.Reschedule(ctx, ev.JTI, next, ev.Attempts+1)
	if errors.Is(err, store.ErrNotFound) {
		// Acked or purged meanwhile; nothing left to retry.
		return
	}
	if err != nil {
		w.logger.ErrorContext(ctx, "ssf: reschedule SET", "stream_id", stream.ID, "jti", ev.JTI, "error", err)
		return
	}
	w.emit(ctx, workerEventRetried, audit.LevelWarn, "security event token push failed; retry scheduled", stream, ev, out, "",
		map[string]any{"attempts": ev.Attempts + 1, "next_attempt_at": next.UTC().Format(time.RFC3339)})
}

func (w *Worker) abandon(ctx context.Context, stream *store.SSFStream, ev *store.SSFEvent, reason string, out workerOutcome) {
	w.ack(ctx, ev)
	w.emit(ctx, workerEventAbandoned, audit.LevelError, "security event token abandoned", stream, ev, out, reason, nil)
}

func (w *Worker) ack(ctx context.Context, ev *store.SSFEvent) {
	if err := w.events.Ack(ctx, ev.StreamID, []string{ev.JTI}); err != nil {
		w.logger.ErrorContext(ctx, "ssf: ack SET", "stream_id", ev.StreamID, "jti", ev.JTI, "error", err)
	}
}

// emit records one ssf.push_* event; more adds extras.
func (w *Worker) emit(
	ctx context.Context,
	name string,
	level audit.Level,
	msg string,
	stream *store.SSFStream,
	ev *store.SSFEvent,
	out workerOutcome,
	reason string,
	more map[string]any,
) {
	extras := map[string]any{
		"stream_id":  stream.ID,
		"jti":        ev.JTI,
		"kind":       string(ev.Kind),
		"event_type": workerEventType(ev.Claims),
	}
	if out.status != 0 {
		extras["status"] = out.status
	}
	if out.errCode != "" {
		extras["err"] = out.errCode
	}
	if out.cause != nil {
		extras["error"] = out.cause.Error()
	}
	if reason != "" {
		extras["reason"] = reason
	}
	maps.Copy(extras, more)
	w.audit.Emit(ctx, audit.Event{
		Name:     name,
		Level:    level,
		Message:  msg,
		ClientID: stream.ClientID,
		Extras:   extras,
	})
}

// workerEventType returns the single events member key of stored claims,
// or "" when the claims do not parse.
func workerEventType(claims []byte) string {
	var parsed struct {
		Events map[string]json.RawMessage `json:"events"`
	}
	if json.Unmarshal(claims, &parsed) != nil {
		return ""
	}
	for k := range parsed.Events {
		return k
	}
	return ""
}

// workerJitter spreads d uniformly over [d-10%, d+10%] with crypto/rand,
// so receivers recovering together are not hit in lockstep. A failed read
// returns d unjittered: the retry still happens.
func workerJitter(d time.Duration) time.Duration {
	spread := int64(d) * workerJitterPct / 100
	r, err := keys.RandomInt63Except(0)
	if err != nil {
		return d
	}
	return d - time.Duration(spread) + time.Duration(r%(2*spread+1))
}
