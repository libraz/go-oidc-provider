package oidcdynamo

import (
	"context"
	"errors"
	"maps"
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

// ssfDueValue is the single value of [attrDueQueue]. Every due event
// shares one ssf_due partition so a Query reads them in global
// next_attempt_at order.
const ssfDueValue = "push"

// ssfEnqueueAttempts bounds the retries of a control-event write that
// lost the race for its stream's pointer of that kind to another one.
const ssfEnqueueAttempts = 8

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
	}
	return nil
}

// ssfStreamStore persists streams. A stream item carries the JSON
// document and, projected for the Enqueue state check, its status and
// delivery method; a client item, written in the same transaction,
// reserves the receiver's one stream.
type ssfStreamStore struct {
	parent *Store
}

// ssfEventStore is the SET queue.
//
// The document holds the event as enqueued and is never rewritten; the
// fields that change afterwards (delivery, held, attempts,
// next_attempt_at) are projected attributes updated in place and are
// authoritative over the document's copy. ClaimDue reads the sparse
// ssf_due index and leases each candidate with an update conditioned on
// the next_attempt_at it observed, so of several claimers only the first
// write lands. Every read that must see each committed event of a stream
// is a strongly consistent Query of its queue partition or of ssf_ready.
type ssfEventStore struct {
	parent *Store
}

func ssfStreamItem(s *store.SSFStream) (item, error) {
	return newItem(ssfStreamKey(s.ID)).
		set(attrClientID, s.ClientID).
		set(attrStatus, string(s.Status)).
		set(attrDelivery, string(s.Delivery.Method)).
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
	entry, err := ssfStreamItem(in)
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
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
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
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
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
	found, err := collectPages(0, func(start map[string]types.AttributeValue) ([]map[string]types.AttributeValue, map[string]types.AttributeValue, error) {
		page, err := s.parent.api.Scan(ctx, &dynamodb.ScanInput{
			TableName:                aws.String(s.parent.names.ssfStreams),
			FilterExpression:         aws.String("#status IN (:enabled, :paused)"),
			ExpressionAttributeNames: map[string]string{"#status": attrStatus},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":enabled": avS(string(store.SSFStreamEnabled)),
				":paused":  avS(string(store.SSFStreamPaused)),
			},
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
		})
		if err != nil {
			return nil, nil, err
		}
		return page.Items, page.LastEvaluatedKey, nil
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
// The stream and the notice are written in one transaction; the queued
// events are then moved by a strongly consistent read of the stream's
// queue. Every Enqueue committed before the stream write is in that read,
// and every later one is refused by Enqueue's state check, so no event
// keeps the earlier state's tags.
func (s *ssfStreamStore) Update(ctx context.Context, in *store.SSFStream, notice *store.SSFEvent) error {
	if in == nil {
		return errors.New("oidcdynamo: nil ssf stream")
	}
	cur, err := s.Get(ctx, in.ID)
	if err != nil {
		return err
	}
	keep := *in
	keep.ClientID = cur.ClientID
	entry, err := ssfStreamItem(&keep)
	if err != nil {
		return err
	}
	put := &types.Put{
		TableName:           aws.String(s.parent.names.ssfStreams),
		Item:                entry,
		ConditionExpression: aws.String(presentKeyCondition),
	}
	if notice != nil {
		err = s.parent.ssfEventsImpl.put(ctx, notice, types.TransactWriteItem{Put: put}, store.ErrNotFound)
	} else if _, err = s.parent.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: put.TableName, Item: put.Item, ConditionExpression: put.ConditionExpression,
	}); isConditionalCheckFailed(err) {
		err = store.ErrNotFound
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrAlreadyExists) {
			return err
		}
		return wrapErr("ssfStreams.Update", err)
	}
	return s.parent.ssfEventsImpl.reconcile(ctx, &keep)
}

// Delete removes the stream and its client claim in one transaction,
// then every item of its queue partition and each event's JTI
// reservation.
func (s *ssfStreamStore) Delete(ctx context.Context, id string) error {
	table := s.parent.names.ssfStreams
	found, err := s.parent.get(ctx, table, ssfStreamKey(id))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.ErrNotFound
		}
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
		case codes[0] == conditionalCheckFailed:
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

// ClaimDue walks ssf_due earliest first, passing over the events of a
// stream that already has perStream in the claim, and leases each
// candidate with an update conditioned on the next_attempt_at the index
// reported and on the event still being due. The index is eventually
// consistent, so a candidate it reports stale fails that condition and is
// skipped; a concurrent claimer that leased it first fails it the same
// way. The walk covers only due push events, never poll or held ones.
func (s *ssfEventStore) ClaimDue(ctx context.Context, now time.Time, n, perStream int, lease time.Duration) ([]*store.SSFEvent, error) {
	if n <= 0 || perStream <= 0 {
		return nil, errors.New("oidcdynamo: ssf claim sizes must be positive")
	}
	leased := now.Add(lease)
	out := make([]*store.SSFEvent, 0, n)
	taken := make(map[string]int)
	var start map[string]types.AttributeValue
	for {
		page, err := s.dueCandidates(ctx, now, n, start)
		if err != nil {
			return nil, wrapErr("ssfEvents.ClaimDue", err)
		}
		for _, candidate := range page.Items {
			streamID := readS(candidate, attrStreamID)
			if len(out) == n || taken[streamID] == perStream {
				continue
			}
			ev, won, err := s.claim(ctx, candidate, leased)
			if err != nil {
				return nil, err
			}
			if won {
				taken[streamID]++
				out = append(out, ev)
			}
		}
		if len(out) == n || len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		start = page.LastEvaluatedKey
	}
}

// dueCandidates reads one page of ssf_due: events due at now, earliest
// first.
func (s *ssfEventStore) dueCandidates(
	ctx context.Context, now time.Time, n int, start map[string]types.AttributeValue,
) (*dynamodb.QueryOutput, error) {
	return s.parent.api.Query(ctx, &dynamodb.QueryInput{
		TableName:                aws.String(s.table()),
		IndexName:                aws.String(indexSSFDue),
		KeyConditionExpression:   aws.String("#q = :q AND #next <= :now"),
		ExpressionAttributeNames: map[string]string{"#q": attrDueQueue, "#next": attrNextAttemptAt},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":q":   avS(ssfDueValue),
			":now": avTime(now),
		},
		ScanIndexForward:  aws.Bool(true),
		Limit:             aws.Int32(int32(n)), //nolint:gosec // n is the caller's batch size, far below int32.
		ExclusiveStartKey: start,
	})
}

// claim leases one candidate, reporting false when another claimer, a
// stream Update, or a Reschedule changed it after the index read.
func (s *ssfEventStore) claim(ctx context.Context, candidate item, leased time.Time) (*store.SSFEvent, bool, error) {
	out, err := s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.table()),
		Key:                 ssfKey(readS(candidate, attrPK), readS(candidate, attrSSFSort)),
		UpdateExpression:    aws.String("SET #next = :leased"),
		ConditionExpression: aws.String("#next = :observed AND #q = :q"),
		ExpressionAttributeNames: map[string]string{
			"#next": attrNextAttemptAt,
			"#q":    attrDueQueue,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":leased":   avTime(leased),
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
	if errors.Is(err, store.ErrNotFound) {
		return store.ErrNotFound
	}
	if err != nil {
		return wrapErr("ssfEvents.Reschedule", err)
	}
	_, err = s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(s.table()),
		Key:                      ssfEventKey(readS(reservation, attrStreamID), jti),
		UpdateExpression:         aws.String("SET #next = :next, #attempts = :attempts"),
		ConditionExpression:      aws.String("attribute_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{"#pk": attrPK, "#next": attrNextAttemptAt, "#attempts": attrAttempts},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":next":     avTime(next),
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
	for _, jti := range jtis {
		if err := s.remove(ctx, streamID, jti); err != nil {
			return wrapErr("ssfEvents.Ack", err)
		}
	}
	return nil
}

// remove deletes an event of streamID and its JTI reservation in one
// transaction. An event no longer in the stream's queue is not an error.
func (s *ssfEventStore) remove(ctx context.Context, streamID, jti string) error {
	table := aws.String(s.table())
	_, err := s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Delete: &types.Delete{
				TableName:           table,
				Key:                 ssfEventKey(streamID, jti),
				ConditionExpression: aws.String(presentKeyCondition),
			}},
			{Delete: &types.Delete{TableName: table, Key: ssfJTIKey(jti)}},
		},
	})
	if err != nil && !isTransactionCanceledByCondition(err) {
		return err
	}
	return nil
}

// Pending reads ssf_ready, which holds only the stream's poll-ready
// events, with a strongly consistent Query that stops one event past n.
func (s *ssfEventStore) Pending(ctx context.Context, streamID string, n int) ([]*store.SSFEvent, bool, error) {
	if n <= 0 {
		return nil, false, errors.New("oidcdynamo: ssf pending size must be positive")
	}
	limit := int32(n + 1) //nolint:gosec // n is the poll request's maxEvents, far below int32.
	found, err := collectPages(limit, func(start map[string]types.AttributeValue) ([]map[string]types.AttributeValue, map[string]types.AttributeValue, error) {
		page, err := s.parent.api.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(s.table()),
			IndexName:                 aws.String(indexSSFReady),
			KeyConditionExpression:    aws.String("#pk = :pk"),
			ExpressionAttributeNames:  map[string]string{"#pk": attrPK},
			ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(ssfQueueKey(streamID))},
			ConsistentRead:            aws.Bool(true),
			Limit:                     aws.Int32(limit),
			ExclusiveStartKey:         start,
		})
		if err != nil {
			return nil, nil, err
		}
		return page.Items, page.LastEvaluatedKey, nil
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
	return collectPages(0, func(start map[string]types.AttributeValue) ([]map[string]types.AttributeValue, map[string]types.AttributeValue, error) {
		page, err := s.parent.api.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(s.table()),
			KeyConditionExpression:    aws.String(cond),
			ExpressionAttributeNames:  names,
			ExpressionAttributeValues: values,
			ConsistentRead:            aws.Bool(true),
			ExclusiveStartKey:         start,
		})
		if err != nil {
			return nil, nil, err
		}
		return page.Items, page.LastEvaluatedKey, nil
	})
}

// reconcile moves every event queued for st to st's state: ordinary
// events of a disabled stream are deleted, every other event takes the
// stream's delivery method, and ordinary events take its hold.
func (s *ssfEventStore) reconcile(ctx context.Context, st *store.SSFStream) error {
	found, err := s.queryQueue(ctx, st.ID, ssfEventPrefix)
	if err != nil {
		return wrapErr("ssfStreams.Update", err)
	}
	for _, raw := range found {
		jti := strings.TrimPrefix(readS(raw, attrSSFSort), ssfEventPrefix)
		ordinary := store.SSFEventKind(readS(raw, attrKind)) == store.SSFEventKindEvent
		if ordinary && st.Status == store.SSFStreamDisabled {
			if err := s.remove(ctx, st.ID, jti); err != nil {
				return wrapErr("ssfStreams.Update", err)
			}
			continue
		}
		held := ordinary && st.Status == store.SSFStreamPaused
		if store.SSFDeliveryMethod(readS(raw, attrDelivery)) == st.Delivery.Method && readBool(raw, attrHeld) == held {
			continue
		}
		if err := s.retagOne(ctx, st.ID, jti, st.Delivery.Method, held); err != nil {
			return wrapErr("ssfStreams.Update", err)
		}
	}
	return nil
}

// retagOne sets an event's delivery and hold and the sparse index keys
// that follow from them.
func (s *ssfEventStore) retagOne(ctx context.Context, streamID, jti string, delivery store.SSFDeliveryMethod, held bool) error {
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
	_, err := s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table()),
		Key:                       ssfEventKey(streamID, jti),
		UpdateExpression:          aws.String(update),
		ConditionExpression:       aws.String("attribute_exists(#pk)"),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	})
	if err != nil && !isConditionalCheckFailed(err) {
		// A condition failure is an event acknowledged since the read.
		return err
	}
	return nil
}

// purge deletes every item of the stream's queue partition: each event
// with its JTI reservation, and the control pointers.
func (s *ssfEventStore) purge(ctx context.Context, streamID string) error {
	found, err := s.queryQueue(ctx, streamID, "")
	if err != nil {
		return wrapErr("ssfStreams.Delete", err)
	}
	for _, raw := range found {
		sk := readS(raw, attrSSFSort)
		if jti, ok := strings.CutPrefix(sk, ssfEventPrefix); ok {
			err = s.remove(ctx, streamID, jti)
		} else {
			_, err = s.parent.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
				TableName: aws.String(s.table()),
				Key:       ssfKey(ssfQueueKey(streamID), sk),
			})
		}
		if err != nil {
			return wrapErr("ssfStreams.Delete", err)
		}
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
			sk := readS(entry, attrSSFSort)
			_, err := s.parent.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
				TableName:                 aws.String(s.table()),
				Key:                       ssfKey(readS(entry, attrPK), sk),
				ConditionExpression:       aws.String("attribute_exists(#pk) AND " + expiredAtOrBeforeCondition),
				ExpressionAttributeNames:  map[string]string{"#pk": attrPK, "#expires": attrExpiresAt},
				ExpressionAttributeValues: values,
			})
			if isConditionalCheckFailed(err) {
				continue
			}
			if err != nil {
				return deleted, wrapErr("ssfEvents.DeleteExpired", err)
			}
			if strings.HasPrefix(sk, ssfEventPrefix) {
				deleted++
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			return deleted, nil
		}
		start = page.LastEvaluatedKey
	}
}

// expiredAtOrBeforeCondition holds for an item whose expiry is set and at
// or before :cutoff; an item with no expiry attribute never matches.
const expiredAtOrBeforeCondition = "#expires <= :cutoff"
