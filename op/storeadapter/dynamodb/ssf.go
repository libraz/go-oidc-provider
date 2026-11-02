package oidcdynamo

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Key prefixes and sort values of the two SSF tables. The prefixes keep a
// caller-chosen identifier of one item shape from ever addressing an item
// of another.
const (
	ssfStreamPrefix = "stream#"
	ssfClientPrefix = "client#"
	// ssfQueuePrefix is the partition of one stream's queue.
	ssfQueuePrefix = "queue#"
	// ssfEventPrefix is an event's sort key in its stream's queue and the
	// partition of the item reserving its JTI.
	ssfEventPrefix = "set#"
	// ssfJTISort is the sort value of a JTI reservation.
	ssfJTISort = "jti"
)

// ssfDueValue is the single value of [attrDueQueue]. Every push, unheld
// event shares one ssf_due partition, ordered by [ssfDueKey].
const ssfDueValue = "push"

// ssfDueKey is an event's [attrDueKey]: its stream's [ssfDueStream]
// prefix, then next_attempt_at, then its JTI.
func ssfDueKey(streamID string, next time.Time, jti string) string {
	return ssfDueStream(streamID) + ssfDueInstant(next) + jti
}

// ssfDueStream is the prefix every due key of streamID starts with. A '!'
// in the ID is escaped to `!"` and the prefix ends in "!!", so no
// stream's prefix starts another's and each stream's keys are contiguous.
func ssfDueStream(streamID string) string {
	return strings.ReplaceAll(streamID, "!", `!"`) + "!!"
}

// ssfDueAfter is the least key above every due key of streamID.
func ssfDueAfter(streamID string) string {
	return strings.ReplaceAll(streamID, "!", `!"`) + `!"`
}

// ssfDueInstant renders t, as [avTime] stores it, in fixed-width digits
// whose string order is its numeric order, negative instants included.
func ssfDueInstant(t time.Time) string {
	var n int64
	if !t.IsZero() {
		n = t.UnixNano()
	}
	return fmt.Sprintf("%020d", uint64(n)^(1<<63))
}

// ssfEnqueueAttempts bounds the retries of a control-event write that
// lost the race for its stream's pointer of that kind to another one.
const ssfEnqueueAttempts = 8

// ssfUpdateAttempts bounds the retries of a stream Update whose write, or
// one of its queue moves, lost to a concurrent write of the same item.
const ssfUpdateAttempts = 16

// transactionConflict is the cancellation code of a transaction action
// that collided with another transaction on the same item.
const transactionConflict = "TransactionConflict"

// errSSFStreamMoved reports a stream write whose observed version another
// Update replaced first.
var errSSFStreamMoved = errors.New("oidcdynamo: ssf stream changed concurrently")

func ssfStreamKey(id string) string       { return ssfStreamPrefix + id }
func ssfClientKey(clientID string) string { return ssfClientPrefix + clientID }
func ssfQueueKey(streamID string) string  { return ssfQueuePrefix + streamID }

// ssfKey addresses one item of the SSF queue table.
func ssfKey(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: avS(pk), attrSSFSort: avS(sk)}
}

// ssfEventKey addresses an event in its stream's queue.
func ssfEventKey(streamID, jti string) map[string]types.AttributeValue {
	return ssfKey(ssfQueueKey(streamID), ssfEventPrefix+jti)
}

// ssfJTIKey addresses the item reserving jti, which names its stream.
func ssfJTIKey(jti string) map[string]types.AttributeValue {
	return ssfKey(ssfEventPrefix+jti, ssfJTISort)
}

// ssfControlKey is the pointer item naming the stream's queued event of a
// control kind, or nil for an ordinary event, which has none.
func ssfControlKey(kind store.SSFEventKind, streamID string) map[string]types.AttributeValue {
	switch kind {
	case store.SSFEventKindVerification, store.SSFEventKindStreamUpdated:
		return ssfKey(ssfQueueKey(streamID), string(kind))
	case store.SSFEventKindEvent:
	}
	return nil
}

// ssfStreamStore persists streams. A stream item carries the JSON
// document and, projected for the Enqueue state check, its status and
// delivery method; a client item, written in the same transaction,
// reserves the receiver's one stream. Its record version, bumped by each
// Update, orders the queue moves of concurrent Updates.
type ssfStreamStore struct {
	parent *Store
}

// ssfEventStore is the SET queue.
//
// The document holds the event as enqueued and is never rewritten; the
// fields that change afterwards (delivery, held, attempts,
// next_attempt_at and the due key derived from it) are projected
// attributes updated in place and are authoritative over the document's
// copy. ClaimDue reads the sparse ssf_due index one stream at a time and
// leases each candidate with an update conditioned on the
// next_attempt_at it observed, so of several claimers only the first
// write lands. Every read that must see each committed event of a stream
// is a strongly consistent Query of its queue partition or of ssf_ready.
type ssfEventStore struct {
	parent *Store
}

func ssfStreamItem(s *store.SSFStream, version int64) (item, error) {
	return newItem(ssfStreamKey(s.ID)).
		set(attrClientID, s.ClientID).
		set(attrStatus, string(s.Status)).
		set(attrDelivery, string(s.Delivery.Method)).
		setN(attrRecordVersion, version).
		doc(s)
}

func decodeSSFStream(found item) (*store.SSFStream, error) {
	var rec store.SSFStream
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// Create writes the stream and its client claim as one transaction, so a
// receiver's second stream and a reused stream ID are both refused by a
// condition rather than by a lookup a concurrent Create could slip past.
func (s *ssfStreamStore) Create(ctx context.Context, in *store.SSFStream) error {
	if in == nil {
		return errors.New("oidcdynamo: nil ssf stream")
	}
	entry, err := ssfStreamItem(in, 0)
	if err != nil {
		return err
	}
	table := s.parent.names.ssfStreams
	claim := newItem(ssfClientKey(in.ClientID)).set(attrStreamID, in.ID)
	absent := aws.String(absentKeyCondition)
	_, err = s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{TableName: aws.String(table), Item: entry, ConditionExpression: absent}},
			{Put: &types.Put{TableName: aws.String(table), Item: claim, ConditionExpression: absent}},
		},
	})
	if err != nil {
		if isTransactionCanceledByCondition(err) {
			return store.ErrConflict
		}
		return wrapErr("ssfStreams.Create", err)
	}
	return nil
}

func (s *ssfStreamStore) Get(ctx context.Context, id string) (*store.SSFStream, error) {
	found, err := s.parent.get(ctx, s.parent.names.ssfStreams, ssfStreamKey(id))
	if err != nil {
		return nil, wrapErr("ssfStreams.Get", err)
	}
	return decodeSSFStream(found)
}

// GetByClient resolves the client claim to its stream. A claim whose
// stream is gone reports [store.ErrNotFound]: Delete removes both in one
// transaction, so that state is only visible to a reader racing it.
func (s *ssfStreamStore) GetByClient(ctx context.Context, clientID string) (*store.SSFStream, error) {
	found, err := s.parent.get(ctx, s.parent.names.ssfStreams, ssfClientKey(clientID))
	if err != nil {
		return nil, wrapErr("ssfStreams.GetByClient", err)
	}
	id := readS(found, attrStreamID)
	if id == "" {
		return nil, store.ErrNotFound
	}
	return s.Get(ctx, id)
}

// ListActive is one consistent Scan filtered on the projected status.
// Client claims carry no status, so the filter drops them too.
func (s *ssfStreamStore) ListActive(ctx context.Context) ([]*store.SSFStream, error) {
	found, err := s.parent.scanPages(ctx, 0, dynamodb.ScanInput{
		TableName:                aws.String(s.parent.names.ssfStreams),
		FilterExpression:         aws.String("#status IN (:enabled, :paused)"),
		ExpressionAttributeNames: map[string]string{"#status": attrStatus},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":enabled": avS(string(store.SSFStreamEnabled)),
			":paused":  avS(string(store.SSFStreamPaused)),
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, wrapErr("ssfStreams.ListActive", err)
	}
	out := make([]*store.SSFStream, 0, len(found))
	for _, raw := range found {
		rec, err := decodeSSFStream(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// Update replaces the stream but keeps the client it was created for:
// the client claim item is never rewritten, so the binding cannot move.
// Each Update first completes the queue move of the state it read, then
// writes the stream, with the notice in the same transaction, as a
// compare-and-swap on the record version read, then moves the queue to
// its own state. Every move is conditioned on the stream still holding
// the version it moves to, so a version's move is finished, by its own
// Update or by the next, before a later one can be stored, and no event
// keeps a superseded state's tags. Every Enqueue committed before the
// stream write is in the move's strongly consistent read, and every
// later one is refused by Enqueue's state check.
func (s *ssfStreamStore) Update(ctx context.Context, in *store.SSFStream, notice *store.SSFEvent) error {
	if in == nil {
		return errors.New("oidcdynamo: nil ssf stream")
	}
	for range ssfUpdateAttempts {
		keep, version, err := s.write(ctx, in, notice)
		switch {
		case errors.Is(err, errSSFStreamMoved):
			continue
		case err != nil:
			return err
		}
		return s.parent.ssfEventsImpl.reconcile(ctx, keep, version)
	}
	return wrapErr("ssfStreams.Update", errSSFStreamMoved)
}

// write stores in, with notice when one is given, over the stream item
// read, and returns what it stored with the version it stored it at.
func (s *ssfStreamStore) write(ctx context.Context, in *store.SSFStream, notice *store.SSFEvent) (*store.SSFStream, int64, error) {
	table := s.parent.names.ssfStreams
	found, err := s.parent.get(ctx, table, ssfStreamKey(in.ID))
	if err != nil {
		return nil, 0, wrapErr("ssfStreams.Update", err)
	}
	cur, err := decodeSSFStream(found)
	if err != nil {
		return nil, 0, err
	}
	prior := readN(found, attrRecordVersion)
	// Finish the queue move of the state read before replacing it, so a
	// superseded Update's unfinished move, a drop above all, still lands.
	if err := s.parent.ssfEventsImpl.reconcile(ctx, cur, prior); err != nil {
		return nil, 0, err
	}
	keep := *in
	keep.ClientID = readS(found, attrClientID)
	entry, err := ssfStreamItem(&keep, prior+1)
	if err != nil {
		return nil, 0, err
	}
	put := &types.Put{
		TableName:                aws.String(table),
		Item:                     entry,
		ConditionExpression:      aws.String("#version = :version AND #client = :client"),
		ExpressionAttributeNames: map[string]string{"#version": attrRecordVersion, "#client": attrClientID},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":version": avN(prior),
			":client":  avS(keep.ClientID),
		},
	}
	if notice != nil {
		err = s.parent.ssfEventsImpl.put(ctx, notice, types.TransactWriteItem{Put: put}, errSSFStreamMoved)
	} else {
		_, err = s.parent.api.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: put.TableName, Item: put.Item, ConditionExpression: put.ConditionExpression,
			ExpressionAttributeNames: put.ExpressionAttributeNames, ExpressionAttributeValues: put.ExpressionAttributeValues,
		})
		if isConditionalCheckFailed(err) || isTransactionConflict(err) {
			err = errSSFStreamMoved
		}
	}
	switch {
	case err == nil:
		return &keep, prior + 1, nil
	case errors.Is(err, errSSFStreamMoved), errors.Is(err, store.ErrAlreadyExists):
		return nil, 0, err
	}
	return nil, 0, wrapErr("ssfStreams.Update", err)
}

// Delete removes the stream and its client claim in one transaction,
// then every item of its queue partition and each event's JTI
// reservation.
func (s *ssfStreamStore) Delete(ctx context.Context, id string) error {
	table := s.parent.names.ssfStreams
	found, err := s.parent.get(ctx, table, ssfStreamKey(id))
	if err != nil {
		return wrapErr("ssfStreams.Delete", err)
	}
	clientID := readS(found, attrClientID)
	_, err = s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Delete: &types.Delete{
				TableName:                 aws.String(table),
				Key:                       key(ssfStreamKey(id)),
				ConditionExpression:       aws.String("#client = :client"),
				ExpressionAttributeNames:  map[string]string{"#client": attrClientID},
				ExpressionAttributeValues: map[string]types.AttributeValue{":client": avS(clientID)},
			}},
			{Delete: &types.Delete{
				TableName:                 aws.String(table),
				Key:                       key(ssfClientKey(clientID)),
				ConditionExpression:       aws.String("#stream = :stream"),
				ExpressionAttributeNames:  map[string]string{"#stream": attrStreamID},
				ExpressionAttributeValues: map[string]types.AttributeValue{":stream": avS(id)},
			}},
		},
	})
	if err != nil {
		if isTransactionCanceledByCondition(err) {
			// A concurrent Delete removed it first.
			return store.ErrNotFound
		}
		return wrapErr("ssfStreams.Delete", err)
	}
	return s.parent.ssfEventsImpl.purge(ctx, id)
}

// ssfDue reports whether an event belongs in the ssf_due index.
func ssfDue(delivery store.SSFDeliveryMethod, held bool) bool {
	return delivery == store.SSFDeliveryPush && !held
}

// ssfReady reports whether an event belongs in the ssf_ready index.
func ssfReady(delivery store.SSFDeliveryMethod, held bool) bool {
	return delivery == store.SSFDeliveryPoll && !held
}

func ssfEventItem(ev *store.SSFEvent) (item, error) {
	entry := item(ssfEventKey(ev.StreamID, ev.JTI)).
		set(attrStreamID, ev.StreamID).
		set(attrKind, string(ev.Kind)).
		set(attrDelivery, string(ev.Delivery)).
		setBool(attrHeld, ev.Held).
		setN(attrAttempts, int64(ev.Attempts)).
		setTime(attrNextAttemptAt, ev.NextAttemptAt).
		set(attrDueKey, ssfDueKey(ev.StreamID, ev.NextAttemptAt, ev.JTI)).
		expires(ev.ExpiresAt)
	if ssfDue(ev.Delivery, ev.Held) {
		entry.set(attrDueQueue, ssfDueValue)
	}
	if ssfReady(ev.Delivery, ev.Held) {
		entry.set(attrReady, ev.JTI)
	}
	return entry.doc(ev)
}

// decodeSSFEvent reads the document and overlays the projected mutable
// fields, which are what the event currently reports.
func decodeSSFEvent(found item) (*store.SSFEvent, error) {
	var ev store.SSFEvent
	if err := unmarshalDoc(found, &ev); err != nil {
		return nil, err
	}
	ev.Delivery = store.SSFDeliveryMethod(readS(found, attrDelivery))
	ev.Held = readBool(found, attrHeld)
	ev.Attempts = int(readN(found, attrAttempts))
	ev.NextAttemptAt = readTime(found, attrNextAttemptAt)
	return &ev, nil
}

func (s *ssfEventStore) table() string { return s.parent.names.ssfEvents }

// getItem reads one queue-table item with a strongly consistent read.
func (s *ssfEventStore) getItem(ctx context.Context, k map[string]types.AttributeValue) (item, error) {
	out, err := s.parent.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.table()),
		Key:            k,
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, store.ErrNotFound
	}
	return out.Item, nil
}

// Enqueue writes the event together with a condition on its stream item,
// so the state check and the insert are one transaction.
func (s *ssfEventStore) Enqueue(ctx context.Context, in *store.SSFEvent) error {
	if in == nil {
		return errors.New("oidcdynamo: nil ssf event")
	}
	return s.put(ctx, in, s.streamStateCheck(in), store.ErrConflict)
}

// streamStateCheck holds when ev's stream is absent or its state gives a
// newly queued event ev's tags. A stream item written before the delivery
// method was projected passes the method check until its next Update.
func (s *ssfEventStore) streamStateCheck(ev *store.SSFEvent) types.TransactWriteItem {
	cond := "attribute_not_exists(#pk) OR attribute_not_exists(#delivery) OR #delivery = :delivery"
	values := map[string]types.AttributeValue{":delivery": avS(string(ev.Delivery))}
	names := map[string]string{"#pk": attrPK, "#delivery": attrDelivery}
	if ev.Kind == store.SSFEventKindEvent {
		status := store.SSFStreamEnabled
		if ev.Held {
			status = store.SSFStreamPaused
		}
		cond = "attribute_not_exists(#pk) OR ((attribute_not_exists(#delivery) OR #delivery = :delivery) AND #status = :status)"
		names["#status"] = attrStatus
		values[":status"] = avS(string(status))
	}
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:                 aws.String(s.parent.names.ssfStreams),
		Key:                       key(ssfStreamKey(ev.StreamID)),
		ConditionExpression:       aws.String(cond),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	}}
}

// put writes ev and its JTI reservation in one transaction with lead,
// reporting leadErr when lead's condition fails. A control event also
// swaps its stream's pointer of that kind to it, deleting the event the
// pointer held before. The pointer is conditioned on the value read, so
// two control events of one kind written at once cannot both keep their
// event: the loser re-reads the pointer and replaces the winner.
func (s *ssfEventStore) put(ctx context.Context, ev *store.SSFEvent, lead types.TransactWriteItem, leadErr error) error {
	entry, err := ssfEventItem(ev)
	if err != nil {
		return err
	}
	table := aws.String(s.table())
	reservation := item(ssfJTIKey(ev.JTI)).set(attrStreamID, ev.StreamID).expires(ev.ExpiresAt)
	pointerKey := ssfControlKey(ev.Kind, ev.StreamID)
	for range ssfEnqueueAttempts {
		actions := []types.TransactWriteItem{
			lead,
			{Put: &types.Put{TableName: table, Item: entry, ConditionExpression: aws.String(absentKeyCondition)}},
			{Put: &types.Put{TableName: table, Item: reservation, ConditionExpression: aws.String(absentKeyCondition)}},
		}
		if pointerKey != nil {
			swap, err := s.pointerSwap(ctx, pointerKey, ev.StreamID, ev.JTI)
			if err != nil {
				return wrapErr("ssfEvents.Enqueue", err)
			}
			actions = append(actions, swap...)
		}
		_, err = s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: actions})
		if err == nil {
			return nil
		}
		codes := transactionCancellationCodes(err)
		switch {
		case len(codes) < 3:
			return wrapErr("ssfEvents.Enqueue", err)
		case codes[0] == conditionalCheckFailed, codes[0] == transactionConflict && errors.Is(leadErr, errSSFStreamMoved):
			return leadErr
		case codes[1] == conditionalCheckFailed, codes[2] == conditionalCheckFailed:
			return store.ErrAlreadyExists
		case pointerKey == nil:
			return wrapErr("ssfEvents.Enqueue", err)
		}
	}
	return wrapErr("ssfEvents.Enqueue", errors.New("control event pointer kept changing"))
}

// pointerSwap reads the pointer at pointerKey and returns the writes that
// move it to jti, conditioned on the value read, and delete its old event
// with that event's JTI reservation.
func (s *ssfEventStore) pointerSwap(
	ctx context.Context, pointerKey map[string]types.AttributeValue, streamID, jti string,
) ([]types.TransactWriteItem, error) {
	table := aws.String(s.table())
	prior := ""
	found, err := s.getItem(ctx, pointerKey)
	switch {
	case err == nil:
		prior = readS(found, attrValue)
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	pointer := &types.Put{
		TableName:                table,
		Item:                     item(maps.Clone(pointerKey)).set(attrValue, jti),
		ConditionExpression:      aws.String("attribute_not_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{"#pk": attrPK},
	}
	if prior != "" {
		pointer.ConditionExpression = aws.String("#v = :prior")
		pointer.ExpressionAttributeNames = map[string]string{"#v": attrValue}
		pointer.ExpressionAttributeValues = map[string]types.AttributeValue{":prior": avS(prior)}
	}
	out := []types.TransactWriteItem{{Put: pointer}}
	if prior != "" && prior != jti {
		out = append(out,
			types.TransactWriteItem{Delete: &types.Delete{TableName: table, Key: ssfEventKey(streamID, prior)}},
			types.TransactWriteItem{Delete: &types.Delete{TableName: table, Key: ssfJTIKey(prior)}},
		)
	}
	return out, nil
}

// ClaimDue reads ssf_due one stream at a time: each Query starts past the
// previous stream's keys and returns the next stream's earliest push
// events, of which the due ones, at most min(perStream, n), are that
// stream's candidates. Only the n streams with the earliest due head can
// contribute to the claim, so their candidates are merged earliest first
// and the first n leased, each with an update conditioned on the
// next_attempt_at the index reported and on the event still being due.
// The work is one Query per stream holding a push event and n leases,
// whatever the streams' backlogs. The index is eventually consistent, so
// a candidate it reports stale fails that condition and is skipped; a
// concurrent claimer that leased it first fails it the same way.
func (s *ssfEventStore) ClaimDue(ctx context.Context, now time.Time, n, perStream int, lease time.Duration) ([]*store.SSFEvent, error) {
	if n <= 0 || perStream <= 0 {
		return nil, errors.New("oidcdynamo: ssf claim sizes must be positive")
	}
	share := min(perStream, n)
	var streams [][]item
	after := ""
	for {
		head, err := s.streamHead(ctx, after, share)
		if err != nil {
			return nil, wrapErr("ssfEvents.ClaimDue", err)
		}
		if len(head) == 0 {
			break
		}
		streamID := readS(head[0], attrStreamID)
		if due := ssfDueOf(head, streamID, now); len(due) > 0 {
			streams = append(streams, due)
		}
		after = ssfDueAfter(streamID)
	}
	slices.SortFunc(streams, func(a, b []item) int { return ssfDueOrder(a[0], b[0]) })
	var candidates []item
	for _, due := range streams[:min(n, len(streams))] {
		candidates = append(candidates, due...)
	}
	slices.SortFunc(candidates, ssfDueOrder)
	leased := now.Add(lease)
	out := make([]*store.SSFEvent, 0, n)
	for _, candidate := range candidates[:min(n, len(candidates))] {
		ev, won, err := s.claim(ctx, candidate, leased)
		if err != nil {
			return nil, err
		}
		if won {
			out = append(out, ev)
		}
	}
	return out, nil
}

// streamHead reads the first limit ssf_due entries at or past after,
// which start with the earliest push events of the next stream.
func (s *ssfEventStore) streamHead(ctx context.Context, after string, limit int) ([]item, error) {
	cond := "#q = :q"
	names := map[string]string{"#q": attrDueQueue}
	values := map[string]types.AttributeValue{":q": avS(ssfDueValue)}
	if after != "" {
		cond += " AND #k >= :after"
		names["#k"] = attrDueKey
		values[":after"] = avS(after)
	}
	page, err := s.parent.api.Query(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(s.table()),
		IndexName:                 aws.String(indexSSFDue),
		KeyConditionExpression:    aws.String(cond),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
		ScanIndexForward:          aws.Bool(true),
		Limit:                     aws.Int32(int32(limit)), //nolint:gosec // limit is at most the caller's batch size, far below int32.
	})
	if err != nil {
		return nil, err
	}
	out := make([]item, len(page.Items))
	for i, raw := range page.Items {
		out[i] = raw
	}
	return out, nil
}

// ssfDueOf returns the leading entries of head that belong to streamID
// and are due at now; head is in due-key order, so they are a prefix.
func ssfDueOf(head []item, streamID string, now time.Time) []item {
	due := now.UnixNano()
	for i, entry := range head {
		if readS(entry, attrStreamID) != streamID || readN(entry, attrNextAttemptAt) > due {
			return head[:i]
		}
	}
	return head
}

// ssfDueOrder orders ssf_due entries by next_attempt_at, then JTI.
func ssfDueOrder(a, b item) int {
	return cmp.Or(
		cmp.Compare(readN(a, attrNextAttemptAt), readN(b, attrNextAttemptAt)),
		strings.Compare(readS(a, attrSSFSort), readS(b, attrSSFSort)),
	)
}

// claim leases one candidate, reporting false when another claimer, a
// stream Update, or a Reschedule changed it after the index read.
func (s *ssfEventStore) claim(ctx context.Context, candidate item, leased time.Time) (*store.SSFEvent, bool, error) {
	out, err := s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.table()),
		Key:                 ssfKey(readS(candidate, attrPK), readS(candidate, attrSSFSort)),
		UpdateExpression:    aws.String("SET #next = :leased, #k = :key"),
		ConditionExpression: aws.String("#next = :observed AND #q = :q"),
		ExpressionAttributeNames: map[string]string{
			"#next": attrNextAttemptAt,
			"#q":    attrDueQueue,
			"#k":    attrDueKey,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":leased":   avTime(leased),
			":key":      avS(ssfDueKey(readS(candidate, attrStreamID), leased, strings.TrimPrefix(readS(candidate, attrSSFSort), ssfEventPrefix))),
			":observed": avN(readN(candidate, attrNextAttemptAt)),
			":q":        avS(ssfDueValue),
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return nil, false, nil
		}
		return nil, false, wrapErr("ssfEvents.ClaimDue", err)
	}
	ev, err := decodeSSFEvent(out.Attributes)
	if err != nil {
		return nil, false, err
	}
	return ev, true, nil
}

// Reschedule resolves the event's stream through its JTI reservation,
// then updates the event in that stream's queue.
func (s *ssfEventStore) Reschedule(ctx context.Context, jti string, next time.Time, attempts int) error {
	reservation, err := s.getItem(ctx, ssfJTIKey(jti))
	if err != nil {
		return wrapErr("ssfEvents.Reschedule", err)
	}
	streamID := readS(reservation, attrStreamID)
	_, err = s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.table()),
		Key:                 ssfEventKey(streamID, jti),
		UpdateExpression:    aws.String("SET #next = :next, #k = :key, #attempts = :attempts"),
		ConditionExpression: aws.String("attribute_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{
			"#pk": attrPK, "#next": attrNextAttemptAt, "#k": attrDueKey, "#attempts": attrAttempts,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":next":     avTime(next),
			":key":      avS(ssfDueKey(streamID, next, jti)),
			":attempts": avN(int64(attempts)),
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return store.ErrNotFound
		}
		return wrapErr("ssfEvents.Reschedule", err)
	}
	return nil
}

// Ack removes each listed event from the stream's own queue partition, so
// a receiver cannot remove another stream's events.
func (s *ssfEventStore) Ack(ctx context.Context, streamID string, jtis []string) error {
	if err := s.removeMany(ctx, streamID, jtis); err != nil {
		return wrapErr("ssfEvents.Ack", err)
	}
	return nil
}

// ssfRemoveBatch is the most events one transaction removes: each takes
// two actions, and a guarded transaction keeps one more for its guard.
const ssfRemoveBatch = (maxTransactionItems - 1) / 2

// removeMany deletes events of streamID and their JTI reservations,
// ssfRemoveBatch events to a transaction. An event no longer in the
// queue is not an error: a batch that one such event cancels is redone
// event by event so the rest still go.
func (s *ssfEventStore) removeMany(ctx context.Context, streamID string, jtis []string) error {
	jtis = slices.Compact(slices.Sorted(slices.Values(jtis)))
	for chunk := range slices.Chunk(jtis, ssfRemoveBatch) {
		actions := make([]types.TransactWriteItem, 0, 2*len(chunk))
		for _, jti := range chunk {
			actions = append(actions, s.removeActions(streamID, jti)...)
		}
		_, err := s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: actions})
		if err == nil || (len(chunk) == 1 && isTransactionCanceledByCondition(err)) {
			continue
		}
		if !isTransactionCanceledByCondition(err) {
			return err
		}
		for _, jti := range chunk {
			if err := s.remove(ctx, streamID, jti); err != nil {
				return err
			}
		}
	}
	return nil
}

// remove deletes an event of streamID and its JTI reservation in one
// transaction. An event no longer in the stream's queue is not an error.
func (s *ssfEventStore) remove(ctx context.Context, streamID, jti string) error {
	_, err := s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: s.removeActions(streamID, jti),
	})
	if err != nil && !isTransactionCanceledByCondition(err) {
		return err
	}
	return nil
}

// removeActions deletes an event of streamID, if it is still queued, and
// its JTI reservation.
func (s *ssfEventStore) removeActions(streamID, jti string) []types.TransactWriteItem {
	table := aws.String(s.table())
	return []types.TransactWriteItem{
		{Delete: &types.Delete{
			TableName:           table,
			Key:                 ssfEventKey(streamID, jti),
			ConditionExpression: aws.String(presentKeyCondition),
		}},
		{Delete: &types.Delete{TableName: table, Key: ssfJTIKey(jti)}},
	}
}

// Pending reads ssf_ready, which holds only the stream's poll-ready
// events, with a strongly consistent Query that stops one event past n.
func (s *ssfEventStore) Pending(ctx context.Context, streamID string, n int) ([]*store.SSFEvent, bool, error) {
	if n <= 0 {
		return nil, false, errors.New("oidcdynamo: ssf pending size must be positive")
	}
	limit := int32(n + 1) //nolint:gosec // n is the poll request's maxEvents, far below int32.
	found, err := s.parent.queryPages(ctx, limit, dynamodb.QueryInput{
		TableName:                 aws.String(s.table()),
		IndexName:                 aws.String(indexSSFReady),
		KeyConditionExpression:    aws.String("#pk = :pk"),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK},
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(ssfQueueKey(streamID))},
		ConsistentRead:            aws.Bool(true),
		Limit:                     aws.Int32(limit),
	})
	if err != nil {
		return nil, false, wrapErr("ssfEvents.Pending", err)
	}
	more := len(found) > n
	if more {
		found = found[:n]
	}
	out := make([]*store.SSFEvent, 0, len(found))
	for _, raw := range found {
		ev, err := decodeSSFEvent(raw)
		if err != nil {
			return nil, false, err
		}
		out = append(out, ev)
	}
	return out, more, nil
}

// queryQueue reads the items of a stream's queue partition whose sort key
// starts with prefix, every item for an empty prefix, with a strongly
// consistent Query, so an item committed before the call is never missed.
func (s *ssfEventStore) queryQueue(ctx context.Context, streamID, prefix string) ([]item, error) {
	cond := "#pk = :pk"
	names := map[string]string{"#pk": attrPK}
	values := map[string]types.AttributeValue{":pk": avS(ssfQueueKey(streamID))}
	if prefix != "" {
		cond += " AND begins_with(#sk, :prefix)"
		names["#sk"] = attrSSFSort
		values[":prefix"] = avS(prefix)
	}
	return s.parent.queryPages(ctx, 0, dynamodb.QueryInput{
		TableName:                 aws.String(s.table()),
		KeyConditionExpression:    aws.String(cond),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
		ConsistentRead:            aws.Bool(true),
	})
}

// reconcile moves every event queued for st to st's state: ordinary
// events of a disabled stream are deleted, every other event takes the
// stream's delivery method, and ordinary events take its hold. Each move
// holds only while the stream item is still at version; once a later
// Update has replaced it, that Update has already finished this move.
func (s *ssfEventStore) reconcile(ctx context.Context, st *store.SSFStream, version int64) error {
	found, err := s.queryQueue(ctx, st.ID, ssfEventPrefix)
	if err != nil {
		return wrapErr("ssfStreams.Update", err)
	}
	guard := s.streamVersionCheck(st.ID, version)
	var gone []string
	for _, raw := range found {
		jti := strings.TrimPrefix(readS(raw, attrSSFSort), ssfEventPrefix)
		move, held := reconcileMove(raw, st)
		switch move {
		case reconcileDelete:
			gone = append(gone, jti)
			continue
		case reconcileKeep:
			continue
		case reconcileRetag:
		}
		current, err := s.guardedRemove(ctx, guard, st.ID, gone)
		gone = nil
		if err != nil {
			return wrapErr("ssfStreams.Update", err)
		}
		if !current {
			return nil
		}
		current, err = s.guarded(ctx, guard, []types.TransactWriteItem{s.retagAction(st.ID, jti, st.Delivery.Method, held)})
		if err != nil {
			return wrapErr("ssfStreams.Update", err)
		}
		if !current {
			return nil
		}
	}
	if _, err := s.guardedRemove(ctx, guard, st.ID, gone); err != nil {
		return wrapErr("ssfStreams.Update", err)
	}
	return nil
}

// reconcileAction is what [ssfEventStore.reconcile] does with one queued event.
type reconcileAction int

const (
	reconcileKeep reconcileAction = iota
	reconcileDelete
	reconcileRetag
)

// reconcileMove classifies a queued event against st and returns the hold
// a retag must apply: ordinary events of a disabled stream go, events
// already at st's delivery method and hold stay, the rest are retagged.
func reconcileMove(raw map[string]types.AttributeValue, st *store.SSFStream) (reconcileAction, bool) {
	ordinary := store.SSFEventKind(readS(raw, attrKind)) == store.SSFEventKindEvent
	held := ordinary && st.Status == store.SSFStreamPaused
	switch {
	case ordinary && st.Status == store.SSFStreamDisabled:
		return reconcileDelete, held
	case store.SSFDeliveryMethod(readS(raw, attrDelivery)) == st.Delivery.Method && readBool(raw, attrHeld) == held:
		return reconcileKeep, held
	default:
		return reconcileRetag, held
	}
}

// streamVersionCheck holds while the stream item is at version.
func (s *ssfEventStore) streamVersionCheck(streamID string, version int64) types.TransactWriteItem {
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:                 aws.String(s.parent.names.ssfStreams),
		Key:                       key(ssfStreamKey(streamID)),
		ConditionExpression:       aws.String("#version = :version"),
		ExpressionAttributeNames:  map[string]string{"#version": attrRecordVersion},
		ExpressionAttributeValues: map[string]types.AttributeValue{":version": avN(version)},
	}}
}

// guardedOutcome is how a transaction led by a stream-version guard ended.
type guardedOutcome int

const (
	// guardedMoved: every action landed.
	guardedMoved guardedOutcome = iota
	// guardedStale: the guard no longer holds.
	guardedStale
	// guardedSkipped: an action's own condition failed, which for an
	// event means it was acknowledged since it was read.
	guardedSkipped
)

// guarded writes move in one transaction with guard and reports false
// when guard no longer holds. A move whose event was acknowledged since
// it was read is done; one that collided with another transaction is
// retried.
func (s *ssfEventStore) guarded(ctx context.Context, guard types.TransactWriteItem, move []types.TransactWriteItem) (bool, error) {
	outcome, err := s.guardedWrite(ctx, append([]types.TransactWriteItem{guard}, move...))
	if err != nil {
		return false, err
	}
	return outcome != guardedStale, nil
}

// guardedRemove removes events of streamID under guard, ssfRemoveBatch
// to a transaction, and reports false when guard no longer holds. A
// batch cancelled by an acknowledged event is redone event by event.
func (s *ssfEventStore) guardedRemove(ctx context.Context, guard types.TransactWriteItem, streamID string, jtis []string) (bool, error) {
	for chunk := range slices.Chunk(jtis, ssfRemoveBatch) {
		actions := []types.TransactWriteItem{guard}
		for _, jti := range chunk {
			actions = append(actions, s.removeActions(streamID, jti)...)
		}
		outcome, err := s.guardedWrite(ctx, actions)
		if err != nil {
			return false, err
		}
		switch {
		case outcome == guardedStale:
			return false, nil
		case outcome == guardedSkipped && len(chunk) > 1:
			if current, err := s.guardedRemoveEach(ctx, guard, streamID, chunk); err != nil || !current {
				return false, err
			}
		}
	}
	return true, nil
}

// guardedRemoveEach removes each event in its own guarded transaction, so
// one acknowledged event does not hold back the rest.
func (s *ssfEventStore) guardedRemoveEach(ctx context.Context, guard types.TransactWriteItem, streamID string, jtis []string) (bool, error) {
	for _, jti := range jtis {
		current, err := s.guarded(ctx, guard, s.removeActions(streamID, jti))
		if err != nil || !current {
			return false, err
		}
	}
	return true, nil
}

// guardedWrite runs actions, whose first is the guard, retrying a
// collision with another transaction.
func (s *ssfEventStore) guardedWrite(ctx context.Context, actions []types.TransactWriteItem) (guardedOutcome, error) {
	for range ssfUpdateAttempts {
		_, err := s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: actions})
		codes := transactionCancellationCodes(err)
		switch {
		case err == nil:
			return guardedMoved, nil
		case len(codes) == 0:
			return guardedStale, err
		case codes[0] == conditionalCheckFailed:
			return guardedStale, nil
		case slices.Contains(codes, conditionalCheckFailed):
			return guardedSkipped, nil
		case !slices.Contains(codes, transactionConflict):
			return guardedStale, err
		}
	}
	return guardedStale, errSSFStreamMoved
}

// retagAction sets an event's delivery and hold and the sparse index keys
// that follow from them, if the event is still queued.
func (s *ssfEventStore) retagAction(streamID, jti string, delivery store.SSFDeliveryMethod, held bool) types.TransactWriteItem {
	sets := []string{"#delivery = :delivery", "#held = :held"}
	var removes []string
	names := map[string]string{"#pk": attrPK, "#delivery": attrDelivery, "#held": attrHeld}
	values := map[string]types.AttributeValue{":delivery": avS(string(delivery)), ":held": avBool(held)}
	if ssfDue(delivery, held) {
		sets = append(sets, "#q = :q")
		values[":q"] = avS(ssfDueValue)
	} else {
		removes = append(removes, "#q")
	}
	names["#q"] = attrDueQueue
	if ssfReady(delivery, held) {
		sets = append(sets, "#ready = :ready")
		values[":ready"] = avS(jti)
	} else {
		removes = append(removes, "#ready")
	}
	names["#ready"] = attrReady
	update := "SET " + strings.Join(sets, ", ")
	if len(removes) > 0 {
		update += " REMOVE " + strings.Join(removes, ", ")
	}
	return types.TransactWriteItem{Update: &types.Update{
		TableName:                 aws.String(s.table()),
		Key:                       ssfEventKey(streamID, jti),
		UpdateExpression:          aws.String(update),
		ConditionExpression:       aws.String("attribute_exists(#pk)"),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	}}
}

// isTransactionConflict reports whether a single-item write collided with
// a transaction in progress on the same item.
func isTransactionConflict(err error) bool {
	var conflict *types.TransactionConflictException
	return errors.As(err, &conflict)
}

// purge deletes every item of the stream's queue partition: each event
// with its JTI reservation, and the control pointers.
func (s *ssfEventStore) purge(ctx context.Context, streamID string) error {
	found, err := s.queryQueue(ctx, streamID, "")
	if err != nil {
		return wrapErr("ssfStreams.Delete", err)
	}
	var jtis []string
	for _, raw := range found {
		sk := readS(raw, attrSSFSort)
		if jti, ok := strings.CutPrefix(sk, ssfEventPrefix); ok {
			jtis = append(jtis, jti)
			continue
		}
		if err := s.removeMany(ctx, streamID, jtis); err != nil {
			return wrapErr("ssfStreams.Delete", err)
		}
		jtis = nil
		_, err = s.parent.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: aws.String(s.table()),
			Key:       ssfKey(ssfQueueKey(streamID), sk),
		})
		if err != nil {
			return wrapErr("ssfStreams.Delete", err)
		}
	}
	if err := s.removeMany(ctx, streamID, jtis); err != nil {
		return wrapErr("ssfStreams.Delete", err)
	}
	return nil
}

// DeleteExpired scans for expired items with a consistent read and
// deletes each under the same expiry condition, counting only the events
// whose delete landed. A JTI reservation expires with its event; the
// control pointers carry no expiry and never match.
func (s *ssfEventStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	values := map[string]types.AttributeValue{":cutoff": avTime(now)}
	deleted := 0
	var start map[string]types.AttributeValue
	for {
		page, err := s.parent.api.Scan(ctx, &dynamodb.ScanInput{
			TableName:                 aws.String(s.table()),
			FilterExpression:          aws.String(expiredAtOrBeforeCondition),
			ProjectionExpression:      aws.String("#pk, #sk"),
			ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#sk": attrSSFSort, "#expires": attrExpiresAt},
			ExpressionAttributeValues: values,
			ExclusiveStartKey:         start,
			ConsistentRead:            aws.Bool(true),
		})
		if err != nil {
			return deleted, wrapErr("ssfEvents.DeleteExpired", err)
		}
		for _, entry := range page.Items {
			counted, err := s.deleteExpiredItem(ctx, entry, values)
			if err != nil {
				return deleted, wrapErr("ssfEvents.DeleteExpired", err)
			}
			if counted {
				deleted++
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			return deleted, nil
		}
		start = page.LastEvaluatedKey
	}
}

// deleteExpiredItem deletes entry under the expiry condition and reports
// whether it was an event whose delete landed.
func (s *ssfEventStore) deleteExpiredItem(ctx context.Context, entry item, values map[string]types.AttributeValue) (bool, error) {
	sk := readS(entry, attrSSFSort)
	_, err := s.parent.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(s.table()),
		Key:                       ssfKey(readS(entry, attrPK), sk),
		ConditionExpression:       aws.String("attribute_exists(#pk) AND " + expiredAtOrBeforeCondition),
		ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#expires": attrExpiresAt},
		ExpressionAttributeValues: values,
	})
	if isConditionalCheckFailed(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(sk, ssfEventPrefix), nil
}

// expiredAtOrBeforeCondition holds for an item whose expiry is set and at
// or before :cutoff; an item with no expiry attribute never matches.
const expiredAtOrBeforeCondition = "#expires <= :cutoff"
