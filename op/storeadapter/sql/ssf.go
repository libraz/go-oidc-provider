package oidcsql

import (
	"cmp"
	"context"
	databasesql "database/sql"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// ssfAckBatch caps the JTIs bound into one Ack DELETE, well under every
// supported driver's bind-parameter limit.
const ssfAckBatch = 500

// SSFStreams returns the [store.SSFStreamStore] backed by the ssf_streams
// table. Deleting a stream also deletes its rows in ssf_events.
func (s *Store) SSFStreams() store.SSFStreamStore { return s.ssfStreamsImpl }

// SSFEvents returns the [store.SSFEventStore] backed by the ssf_events
// table.
func (s *Store) SSFEvents() store.SSFEventStore { return s.ssfEventsImpl }

var _ store.SharedSignalsStore = (*Store)(nil)

// ssfStreamStore is the SQL-backed [store.SSFStreamStore]. The unique
// client_id index is what makes Create's one-stream-per-receiver check
// and the insert a single atomic step.
type ssfStreamStore struct {
	parent *Store
}

func (s *ssfStreamStore) Create(ctx context.Context, st *store.SSFStream) error {
	if st == nil {
		return errors.New("oidcsql: nil SSF stream")
	}
	_, err := s.parent.db.ExecContext(ctx, s.parent.queries.ssfStreamInsert, ssfStreamArgs(st)...)
	if isDuplicate(err) {
		return store.ErrConflict
	}
	return wrapErr("ssf_streams.Create", err)
}

func (s *ssfStreamStore) Get(ctx context.Context, id string) (*store.SSFStream, error) {
	return scanSSFStream(s.parent.db.QueryRowContext(ctx, s.parent.queries.ssfStreamGet, id))
}

func (s *ssfStreamStore) GetByClient(ctx context.Context, clientID string) (*store.SSFStream, error) {
	return scanSSFStream(s.parent.db.QueryRowContext(ctx, s.parent.queries.ssfStreamGetByClient, clientID))
}

func (s *ssfStreamStore) ListActive(ctx context.Context) ([]*store.SSFStream, error) {
	rows, err := s.parent.db.QueryContext(ctx, s.parent.queries.ssfStreamListActive,
		string(store.SSFStreamEnabled), string(store.SSFStreamPaused))
	if err != nil {
		return nil, wrapErr("ssf_streams.ListActive", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*store.SSFStream, 0)
	for rows.Next() {
		st, err := scanSSFStream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("ssf_streams.ListActive.Rows", err)
	}
	return out, nil
}

// Update rewrites the stream row first, so its row lock orders the queue
// rewrite after every Enqueue that read the earlier state and before every
// Enqueue that reads the new one.
func (s *ssfStreamStore) Update(ctx context.Context, st *store.SSFStream, notice *store.SSFEvent) error {
	if st == nil {
		return errors.New("oidcsql: nil SSF stream")
	}
	q := s.parent.queries
	tx, err := s.parent.beginInternalTx(ctx, "ssf_streams.Update.BeginTx")
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// The SET list skips id and client_id, so the WHERE id is the only
	// key bound after the assigned values.
	args := ssfStreamArgs(st)
	args = append(args[2:], st.ID)
	res, err := tx.ExecContext(ctx, q.ssfStreamUpdate, args...)
	if err != nil {
		return wrapErr("ssf_streams.Update", err)
	}
	if err := requireRow(ctx, tx, res, "ssf_streams.Update", q.ssfStreamExists, st.ID); err != nil {
		return err
	}
	ordinary := string(store.SSFEventKindEvent)
	if st.Status == store.SSFStreamDisabled {
		if _, err := tx.ExecContext(ctx, q.ssfEventPurgeKind, st.ID, ordinary); err != nil {
			return wrapErr("ssf_streams.Update.drop", err)
		}
	}
	if _, err := tx.ExecContext(ctx, q.ssfEventRetag,
		string(st.Delivery.Method), ordinary, boolToInt64(st.Status == store.SSFStreamPaused), st.ID); err != nil {
		return wrapErr("ssf_streams.Update.retag", err)
	}
	if notice != nil {
		if err := s.parent.ssfEventsImpl.insertReplacing(ctx, tx, notice); err != nil {
			return err
		}
	}
	return wrapErr("ssf_streams.Update.Commit", tx.Commit())
}

func (s *ssfStreamStore) Delete(ctx context.Context, id string) error {
	tx, err := s.parent.beginInternalTx(ctx, "ssf_streams.Delete.BeginTx")
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := execDeleteOne(ctx, tx, "ssf_streams.Delete", s.parent.queries.ssfStreamDelete, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.parent.queries.ssfEventPurgeStream, id); err != nil {
		return wrapErr("ssf_streams.Delete.events", err)
	}
	return wrapErr("ssf_streams.Delete.Commit", tx.Commit())
}

// ssfEventStore is the SQL-backed [store.SSFEventStore].
//
// ClaimDue takes no row lock on any engine: it reads due candidates, then
// leases each with an UPDATE conditioned on the next_attempt_at it read.
// A claimer whose UPDATE matches no row lost that event to another, so
// each event goes to exactly one of several replicas.
type ssfEventStore struct {
	parent *Store
}

// Enqueue locks the stream row before checking its state, which
// serialises it against Update and against other enqueues for the stream,
// so two verifications cannot both miss each other's row.
func (s *ssfEventStore) Enqueue(ctx context.Context, ev *store.SSFEvent) error {
	if ev == nil {
		return errors.New("oidcsql: nil SSF event")
	}
	tx, err := s.parent.beginInternalTx(ctx, "ssf_events.Enqueue.BeginTx")
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var status, method string
	err = tx.QueryRowContext(ctx, s.parent.queries.ssfStreamLockState, ev.StreamID).Scan(&status, &method)
	switch {
	case errors.Is(err, databasesql.ErrNoRows):
	case err != nil:
		return wrapErr("ssf_events.Enqueue.stream", err)
	case !ssfEventMatchesStream(ev, store.SSFStreamStatus(status), store.SSFDeliveryMethod(method)):
		return store.ErrConflict
	}
	if err := s.insertReplacing(ctx, tx, ev); err != nil {
		return err
	}
	return wrapErr("ssf_events.Enqueue.Commit", tx.Commit())
}

// insertReplacing inserts ev and, for a control event, deletes the
// stream's other queued event of the same Kind.
func (s *ssfEventStore) insertReplacing(ctx context.Context, e execer, ev *store.SSFEvent) error {
	if err := s.insert(ctx, e, ev); err != nil {
		return err
	}
	if ev.Kind == store.SSFEventKindEvent {
		return nil
	}
	_, err := e.ExecContext(ctx, s.parent.queries.ssfEventDropOtherOfKind, ev.StreamID, string(ev.Kind), ev.JTI)
	return wrapErr("ssf_events.Enqueue.replace", err)
}

// ssfEventMatchesStream reports whether ev carries the tags a stream in
// status and method gives a newly queued event.
func ssfEventMatchesStream(ev *store.SSFEvent, status store.SSFStreamStatus, method store.SSFDeliveryMethod) bool {
	if ev.Delivery != method {
		return false
	}
	if ev.Kind != store.SSFEventKindEvent {
		return true
	}
	return status != store.SSFStreamDisabled && ev.Held == (status == store.SSFStreamPaused)
}

func (s *ssfEventStore) insert(ctx context.Context, e execer, ev *store.SSFEvent) error {
	_, err := e.ExecContext(ctx, s.parent.queries.ssfEventInsert,
		ev.JTI,
		ev.StreamID,
		string(ev.Kind),
		string(ev.Delivery),
		boolToInt64(ev.Held),
		nonNilBytes(ev.Claims),
		int64(ev.Attempts),
		timeToInt64(ev.NextAttemptAt),
		timeToInt64(ev.ExpiresAt),
	)
	if isDuplicate(err) {
		return store.ErrAlreadyExists
	}
	return wrapErr("ssf_events.Enqueue", err)
}

// ClaimDue first reads the due head of every stream holding a push,
// unheld event, then each of the n earliest-headed streams' first
// min(perStream, n) due events, and leases the earliest n of those. Only
// those streams can contribute to the claim, so the result is the one a
// walk of every due event would give, at the cost of an index probe per
// stream and a bounded read per contributing stream rather than of the
// streams' backlogs.
func (s *ssfEventStore) ClaimDue(ctx context.Context, now time.Time, n, perStream int, lease time.Duration) ([]*store.SSFEvent, error) {
	if n <= 0 || perStream <= 0 {
		return nil, errors.New("oidcsql: ssf_events.ClaimDue: n and perStream must be positive")
	}
	db := dbRunner{db: s.parent.db}
	push := string(store.SSFDeliveryPush)
	streams, err := s.dueStreams(ctx, db, timeToInt64(now), n)
	if err != nil {
		return nil, err
	}
	if len(streams) == 0 {
		return make([]*store.SSFEvent, 0), nil
	}
	candidates, err := s.dueCandidates(ctx, db, streams, timeToInt64(now), min(perStream, n))
	if err != nil {
		return nil, err
	}
	slices.SortFunc(candidates, func(a, b *store.SSFEvent) int {
		return cmp.Or(a.NextAttemptAt.Compare(b.NextAttemptAt), strings.Compare(a.JTI, b.JTI))
	})
	until := int64ToTime(timeToInt64(now.Add(lease)))
	claimed := make([]*store.SSFEvent, 0, n)
	for _, ev := range candidates[:min(n, len(candidates))] {
		res, err := db.ExecContext(ctx, s.parent.queries.ssfEventLease,
			timeToInt64(until), ev.JTI, timeToInt64(ev.NextAttemptAt), push)
		if err != nil {
			return nil, wrapErr("ssf_events.ClaimDue.lease", err)
		}
		won, err := res.RowsAffected()
		if err != nil {
			return nil, wrapErr("ssf_events.ClaimDue.RowsAffected", err)
		}
		// Zero rows: another claimer leased it first, or it was acked,
		// retagged or held since the scan.
		if won == 1 {
			ev.NextAttemptAt = until
			claimed = append(claimed, ev)
		}
	}
	return claimed, nil
}

// ssfDueWalkDepth is the number of streams one page of the heads walk
// visits, bounding the recursion depth of a single query.
const ssfDueWalkDepth = 500

// streamHead is one stream's earliest push, unheld next_attempt_at.
type streamHead struct {
	id   string
	head int64
}

// dueStreams returns the streams whose earliest push, unheld event is due
// at now, earliest head first: the first n of them and every stream tied
// with the n-th, so the JTI tiebreak is left to the caller.
func (s *ssfEventStore) dueStreams(ctx context.Context, r runner, now int64, n int) ([]string, error) {
	all, err := s.allHeads(ctx, r)
	if err != nil {
		return nil, err
	}
	due := slices.DeleteFunc(all, func(h streamHead) bool { return h.head > now })
	slices.SortStableFunc(due, func(a, b streamHead) int { return cmp.Compare(a.head, b.head) })
	out := make([]string, 0, min(n, len(due)))
	for i, h := range due {
		if i >= n && h.head != due[n-1].head {
			break
		}
		out = append(out, h.id)
	}
	return out, nil
}

// allHeads reads the head of every stream holding a push, unheld event:
// in one query where the engine skips between groups, else page by page.
func (s *ssfEventStore) allHeads(ctx context.Context, r runner) ([]streamHead, error) {
	push := string(store.SSFDeliveryPush)
	if s.parent.dialect.groupMinScan {
		return s.heads(ctx, r, []any{push})
	}
	var all []streamHead
	for after := ""; ; {
		page, err := s.heads(ctx, r, []any{push, after, push, ssfDueWalkDepth, push})
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < ssfDueWalkDepth {
			return all, nil
		}
		after = page[len(page)-1].id
	}
}

// heads runs the due-heads query: every stream's head where the engine
// skips between groups, else one page of the walk in stream ID order.
func (s *ssfEventStore) heads(ctx context.Context, r runner, args []any) ([]streamHead, error) {
	rows, err := r.QueryContext(ctx, s.parent.queries.ssfEventDueHeads, args...)
	if err != nil {
		return nil, wrapErr("ssf_events.ClaimDue.heads", err)
	}
	defer func() { _ = rows.Close() }()
	var page []streamHead
	for rows.Next() {
		var h streamHead
		if err := rows.Scan(&h.id, &h.head); err != nil {
			return nil, wrapErr("ssf_events.ClaimDue.heads.Scan", err)
		}
		page = append(page, h)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr("ssf_events.ClaimDue.heads.Rows", err)
	}
	return page, nil
}

// dueCandidates reads each listed stream's first limit due events, one
// bounded index range per stream, in a single statement.
func (s *ssfEventStore) dueCandidates(ctx context.Context, r runner, streams []string, now int64, limit int) ([]*store.SSFEvent, error) {
	push := string(store.SSFDeliveryPush)
	parts := make([]string, 0, len(streams))
	args := make([]any, 0, 4*len(streams))
	for i, id := range streams {
		parts = append(parts, s.parent.queries.ssfEventDueStreamPart+strconv.Itoa(i))
		args = append(args, push, id, now, limit)
	}
	query := s.parent.dialect.rebind(strings.Join(parts, " UNION ALL "))
	return queryEvents(ctx, r, "ssf_events.ClaimDue", query, args...)
}

func (s *ssfEventStore) Reschedule(ctx context.Context, jti string, next time.Time, attempts int) error {
	res, err := s.parent.db.ExecContext(ctx, s.parent.queries.ssfEventReschedule,
		timeToInt64(next), int64(attempts), jti)
	if err != nil {
		return wrapErr("ssf_events.Reschedule", err)
	}
	return requireRow(ctx, dbRunner{db: s.parent.db}, res, "ssf_events.Reschedule", s.parent.queries.ssfEventExists, jti)
}

func (s *ssfEventStore) Ack(ctx context.Context, streamID string, jtis []string) error {
	for chunk := range slices.Chunk(jtis, ssfAckBatch) {
		args := make([]any, 0, len(chunk)+1)
		args = append(args, streamID)
		for _, jti := range chunk {
			args = append(args, jti)
		}
		query := s.parent.dialect.rebind(s.parent.queries.ssfEventAckPrefix + placeholders(len(chunk)) + ")")
		if _, err := s.parent.db.ExecContext(ctx, query, args...); err != nil {
			return wrapErr("ssf_events.Ack", err)
		}
	}
	return nil
}

func (s *ssfEventStore) Pending(ctx context.Context, streamID string, n int) ([]*store.SSFEvent, bool, error) {
	if n <= 0 {
		return nil, false, errors.New("oidcsql: ssf_events.Pending: n must be positive")
	}
	// One row past n answers whether more remain.
	got, err := queryEvents(ctx, dbRunner{db: s.parent.db}, "ssf_events.Pending", s.parent.queries.ssfEventPending,
		streamID, string(store.SSFDeliveryPoll), n+1)
	if err != nil {
		return nil, false, err
	}
	if len(got) > n {
		return got[:n], true, nil
	}
	return got, false, nil
}

func (s *ssfEventStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := s.parent.db.ExecContext(ctx, s.parent.queries.ssfEventDeleteExpired, timeToInt64(now))
	if err != nil {
		return 0, wrapErr("ssf_events.DeleteExpired", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, wrapErr("ssf_events.DeleteExpired.RowsAffected", err)
	}
	return int(n), nil
}

// requireRow reports [store.ErrNotFound] for an UPDATE that affected no
// row and whose key does not exist. The existence probe is needed because
// MySQL counts changed rather than matched rows, so rewriting a row with
// its own values also reports zero.
func requireRow(ctx context.Context, r runner, res databasesql.Result, op, existsQuery, key string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr(op+".RowsAffected", err)
	}
	if n > 0 {
		return nil
	}
	var one int
	err = r.QueryRowContext(ctx, existsQuery, key).Scan(&one)
	if errors.Is(err, databasesql.ErrNoRows) {
		return store.ErrNotFound
	}
	return wrapErr(op+".exists", err)
}

// ssfStreamArgs binds st in ssfStreamColumns order.
func ssfStreamArgs(st *store.SSFStream) []any {
	var sealed any
	if st.Delivery.SealedAuthorizationHeader != nil {
		sealed = st.Delivery.SealedAuthorizationHeader
	}
	return []any{
		st.ID,
		st.ClientID,
		string(st.Delivery.Method),
		st.Delivery.EndpointURL,
		sealed,
		encodeStrings(st.EventsRequested),
		encodeStrings(st.EventsDelivered),
		st.Description,
		string(st.Status),
		st.StatusReason,
		timeToInt64(st.UpdatedAt),
		timeToInt64(st.CreatedAt),
	}
}

func scanSSFStream(sc scanner) (*store.SSFStream, error) {
	var (
		st                   store.SSFStream
		method, status       string
		sealed               []byte
		requested, delivered []byte
		updated, created     int64
	)
	err := sc.Scan(
		&st.ID,
		&st.ClientID,
		&method,
		&st.Delivery.EndpointURL,
		&sealed,
		&requested,
		&delivered,
		&st.Description,
		&status,
		&st.StatusReason,
		&updated,
		&created,
	)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("ssf_streams.Scan", err)
	}
	if st.EventsRequested, err = decodeStrings(requested); err != nil {
		return nil, err
	}
	if st.EventsDelivered, err = decodeStrings(delivered); err != nil {
		return nil, err
	}
	st.Delivery.SealedAuthorizationHeader = sealed
	st.Delivery.Method = store.SSFDeliveryMethod(method)
	st.Status = store.SSFStreamStatus(status)
	st.UpdatedAt = int64ToTime(updated)
	st.CreatedAt = int64ToTime(created)
	return &st, nil
}

// queryEvents runs a multi-row event SELECT and closes the result set
// before returning.
func queryEvents(ctx context.Context, r runner, op, query string, args ...any) ([]*store.SSFEvent, error) {
	rows, err := r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*store.SSFEvent, 0)
	for rows.Next() {
		var (
			ev                     store.SSFEvent
			kind, delivery         string
			held, attempts         int64
			claims                 []byte
			nextAttempt, expiresAt int64
		)
		if err := rows.Scan(&ev.JTI, &ev.StreamID, &kind, &delivery, &held, &claims,
			&attempts, &nextAttempt, &expiresAt); err != nil {
			return nil, wrapErr(op+".Scan", err)
		}
		ev.Kind = store.SSFEventKind(kind)
		ev.Delivery = store.SSFDeliveryMethod(delivery)
		ev.Held = int64ToBool(held)
		ev.Claims = claims
		ev.Attempts = int(attempts)
		ev.NextAttemptAt = int64ToTime(nextAttempt)
		ev.ExpiresAt = int64ToTime(expiresAt)
		out = append(out, &ev)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapErr(op+".Rows", err)
	}
	return out, nil
}

var (
	_ store.SSFStreamStore = (*ssfStreamStore)(nil)
	_ store.SSFEventStore  = (*ssfEventStore)(nil)
)
