package oidcdynamo

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Key prefixes inside the two SSF tables. Each table holds two item
// shapes, and the prefixes keep a caller-chosen identifier of one shape
// from ever addressing an item of the other.
const (
	ssfStreamPrefix       = "stream#"
	ssfClientPrefix       = "client#"
	ssfEventPrefix        = "set#"
	ssfVerificationPrefix = "verification#"
)

// ssfDueValue is the single value of [attrDueQueue]. Every due event
// shares one ssf_due partition so a Query reads them in global
// next_attempt_at order.
const ssfDueValue = "push"

// ssfEnqueueAttempts bounds the retries of a verification enqueue that
// lost the race for its stream's verification pointer to another one.
const ssfEnqueueAttempts = 8

func ssfStreamKey(id string) string             { return ssfStreamPrefix + id }
func ssfClientKey(clientID string) string       { return ssfClientPrefix + clientID }
func ssfEventKey(jti string) string             { return ssfEventPrefix + jti }
func ssfVerificationKey(streamID string) string { return ssfVerificationPrefix + streamID }

// ssfStreamStore persists streams. A stream item carries the JSON
// document and its status; a client item, written in the same
// transaction, reserves the receiver's one stream.
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
// write lands.
type ssfEventStore struct {
	parent *Store
}

func ssfStreamItem(s *store.SSFStream) (item, error) {
	return newItem(ssfStreamKey(s.ID)).
		set(attrClientID, s.ClientID).
		set(attrStatus, string(s.Status)).
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
func (s *ssfStreamStore) Update(ctx context.Context, in *store.SSFStream) error {
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
	_, err = s.parent.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.parent.names.ssfStreams),
		Item:                entry,
		ConditionExpression: aws.String(presentKeyCondition),
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return store.ErrNotFound
		}
		return wrapErr("ssfStreams.Update", err)
	}
	return nil
}

// Delete removes the stream and its client claim in one transaction,
// then every event queued for it and its verification pointer.
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
	events := s.parent.ssfEventsImpl
	if err := events.Purge(ctx, id, true); err != nil {
		return err
	}
	if _, err := s.parent.deleteKey(ctx, s.parent.names.ssfEvents, ssfVerificationKey(id)); err != nil {
		return wrapErr("ssfStreams.Delete", err)
	}
	return nil
}

// ssfDue reports whether an event belongs in the ssf_due index.
func ssfDue(delivery store.SSFDeliveryMethod, held bool) bool {
	return delivery == store.SSFDeliveryPush && !held
}

func ssfEventItem(ev *store.SSFEvent) (item, error) {
	entry := newItem(ssfEventKey(ev.JTI)).
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

func (s *ssfEventStore) Enqueue(ctx context.Context, in *store.SSFEvent) error {
	if in == nil {
		return errors.New("oidcdynamo: nil ssf event")
	}
	entry, err := ssfEventItem(in)
	if err != nil {
		return err
	}
	if in.Kind == store.SSFEventKindVerification {
		return s.enqueueVerification(ctx, in, entry)
	}
	placed, err := s.parent.putIfAbsent(ctx, s.table(), entry)
	if err != nil {
		return wrapErr("ssfEvents.Enqueue", err)
	}
	if !placed {
		return store.ErrAlreadyExists
	}
	return nil
}

// enqueueVerification writes a verification and swaps the stream's
// verification pointer to it in one transaction, deleting the event the
// pointer held before. The pointer is conditioned on the value read, so
// two verifications enqueued at once cannot both keep their event: the
// loser re-reads the pointer and replaces the winner.
func (s *ssfEventStore) enqueueVerification(ctx context.Context, in *store.SSFEvent, entry item) error {
	table := s.table()
	pointerKey := ssfVerificationKey(in.StreamID)
	for range ssfEnqueueAttempts {
		prior := ""
		found, err := s.parent.get(ctx, table, pointerKey)
		switch {
		case err == nil:
			prior = readS(found, attrValue)
		case !errors.Is(err, store.ErrNotFound):
			return wrapErr("ssfEvents.Enqueue", err)
		}
		pointer := &types.Put{
			TableName:                aws.String(table),
			Item:                     newItem(pointerKey).set(attrValue, in.JTI),
			ConditionExpression:      aws.String("attribute_not_exists(#pk)"),
			ExpressionAttributeNames: map[string]string{"#pk": attrPK},
		}
		if prior != "" {
			pointer.ConditionExpression = aws.String("#v = :prior")
			pointer.ExpressionAttributeNames = map[string]string{"#v": attrValue}
			pointer.ExpressionAttributeValues = map[string]types.AttributeValue{":prior": avS(prior)}
		}
		actions := []types.TransactWriteItem{
			{Put: &types.Put{
				TableName:           aws.String(table),
				Item:                entry,
				ConditionExpression: aws.String(absentKeyCondition),
			}},
			{Put: pointer},
		}
		if prior != "" && prior != in.JTI {
			actions = append(actions, types.TransactWriteItem{Delete: &types.Delete{
				TableName: aws.String(table),
				Key:       key(ssfEventKey(prior)),
			}})
		}
		_, err = s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: actions})
		if err == nil {
			return nil
		}
		codes := transactionCancellationCodes(err)
		if len(codes) == 0 {
			return wrapErr("ssfEvents.Enqueue", err)
		}
		if codes[0] == conditionalCheckFailed {
			return store.ErrAlreadyExists
		}
	}
	return wrapErr("ssfEvents.Enqueue", errors.New("verification pointer kept changing"))
}

// ClaimDue walks ssf_due earliest first and leases each candidate with an
// update conditioned on the next_attempt_at the index reported and on
// the event still being due. The index is eventually consistent, so a
// candidate it reports stale fails that condition and is skipped; a
// concurrent claimer that leased it first fails it the same way.
func (s *ssfEventStore) ClaimDue(ctx context.Context, now time.Time, n int, lease time.Duration) ([]*store.SSFEvent, error) {
	if n <= 0 {
		return nil, errors.New("oidcdynamo: ssf claim size must be positive")
	}
	leased := now.Add(lease)
	out := make([]*store.SSFEvent, 0, n)
	var start map[string]types.AttributeValue
	for {
		page, err := s.dueCandidates(ctx, now, n, start)
		if err != nil {
			return nil, wrapErr("ssfEvents.ClaimDue", err)
		}
		out, err = s.claimPage(ctx, page.Items, leased, out, n)
		if err != nil {
			return nil, err
		}
		if len(out) == n || len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		start = page.LastEvaluatedKey
	}
}

// claimPage leases candidates in order until out holds n events.
func (s *ssfEventStore) claimPage(
	ctx context.Context, candidates []map[string]types.AttributeValue, leased time.Time, out []*store.SSFEvent, n int,
) ([]*store.SSFEvent, error) {
	for _, candidate := range candidates {
		if len(out) == n {
			break
		}
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
// Retag, or a Reschedule changed it after the index read.
func (s *ssfEventStore) claim(ctx context.Context, candidate item, leased time.Time) (*store.SSFEvent, bool, error) {
	out, err := s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.table()),
		Key:                 key(readS(candidate, attrPK)),
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

func (s *ssfEventStore) Reschedule(ctx context.Context, jti string, next time.Time, attempts int) error {
	_, err := s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(s.table()),
		Key:                      key(ssfEventKey(jti)),
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

// Ack deletes each listed event under a condition on its stream, so a
// receiver cannot remove another stream's events.
func (s *ssfEventStore) Ack(ctx context.Context, streamID string, jtis []string) error {
	for _, jti := range jtis {
		if err := s.deleteOfStream(ctx, ssfEventKey(jti), streamID); err != nil {
			return wrapErr("ssfEvents.Ack", err)
		}
	}
	return nil
}

// deleteOfStream deletes an event when it belongs to streamID. An event
// that is gone or belongs elsewhere is not an error.
func (s *ssfEventStore) deleteOfStream(ctx context.Context, pk, streamID string) error {
	_, err := s.parent.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(s.table()),
		Key:                       key(pk),
		ConditionExpression:       aws.String("#stream = :stream"),
		ExpressionAttributeNames:  map[string]string{"#stream": attrStreamID},
		ExpressionAttributeValues: map[string]types.AttributeValue{":stream": avS(streamID)},
	})
	if err != nil && !isConditionalCheckFailed(err) {
		return err
	}
	return nil
}

func (s *ssfEventStore) Pending(ctx context.Context, streamID string, n int) ([]*store.SSFEvent, bool, error) {
	if n <= 0 {
		return nil, false, errors.New("oidcdynamo: ssf pending size must be positive")
	}
	found, err := s.parent.queryIndex(ctx, s.table(), indexByStream, attrStreamID, streamID)
	if err != nil {
		return nil, false, wrapErr("ssfEvents.Pending", err)
	}
	out := make([]*store.SSFEvent, 0, min(n, len(found)))
	for _, raw := range found {
		if store.SSFDeliveryMethod(readS(raw, attrDelivery)) != store.SSFDeliveryPoll || readBool(raw, attrHeld) {
			continue
		}
		if len(out) == n {
			return out, true, nil
		}
		ev, err := decodeSSFEvent(raw)
		if err != nil {
			return nil, false, err
		}
		out = append(out, ev)
	}
	return out, false, nil
}

// Retag rewrites the projected delivery and held attributes of every
// event of the stream, and adds or removes the ssf_due key to match.
func (s *ssfEventStore) Retag(ctx context.Context, streamID string, delivery store.SSFDeliveryMethod, held bool) error {
	found, err := s.parent.queryIndex(ctx, s.table(), indexByStream, attrStreamID, streamID)
	if err != nil {
		return wrapErr("ssfEvents.Retag", err)
	}
	for _, raw := range found {
		evHeld := held && store.SSFEventKind(readS(raw, attrKind)) == store.SSFEventKindEvent
		if err := s.retagOne(ctx, readS(raw, attrPK), streamID, delivery, evHeld); err != nil {
			return wrapErr("ssfEvents.Retag", err)
		}
	}
	return nil
}

func (s *ssfEventStore) retagOne(ctx context.Context, pk, streamID string, delivery store.SSFDeliveryMethod, held bool) error {
	update := "SET #delivery = :delivery, #held = :held REMOVE #q"
	values := map[string]types.AttributeValue{
		":delivery": avS(string(delivery)),
		":held":     avBool(held),
		":stream":   avS(streamID),
	}
	if ssfDue(delivery, held) {
		update = "SET #delivery = :delivery, #held = :held, #q = :q"
		values[":q"] = avS(ssfDueValue)
	}
	_, err := s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.table()),
		Key:                 key(pk),
		UpdateExpression:    aws.String(update),
		ConditionExpression: aws.String("#stream = :stream"),
		ExpressionAttributeNames: map[string]string{
			"#delivery": attrDelivery,
			"#held":     attrHeld,
			"#q":        attrDueQueue,
			"#stream":   attrStreamID,
		},
		ExpressionAttributeValues: values,
	})
	if err != nil && !isConditionalCheckFailed(err) {
		// A condition failure is an event acknowledged since the read.
		return err
	}
	return nil
}

func (s *ssfEventStore) Purge(ctx context.Context, streamID string, includeControl bool) error {
	found, err := s.parent.queryIndex(ctx, s.table(), indexByStream, attrStreamID, streamID)
	if err != nil {
		return wrapErr("ssfEvents.Purge", err)
	}
	for _, raw := range found {
		if !includeControl && store.SSFEventKind(readS(raw, attrKind)) != store.SSFEventKindEvent {
			continue
		}
		if err := s.deleteOfStream(ctx, readS(raw, attrPK), streamID); err != nil {
			return wrapErr("ssfEvents.Purge", err)
		}
	}
	return nil
}

// DeleteExpired scans for expired events and deletes each under the same
// expiry condition, counting only the deletes that landed. Verification
// pointers carry no expiry and never match.
func (s *ssfEventStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	values := map[string]types.AttributeValue{":cutoff": avTime(now)}
	return s.parent.gcWhere(ctx, s.table(), "ssfEvents.DeleteExpired", expiredAtOrBeforeCondition, values, true)
}

// expiredAtOrBeforeCondition holds for an item whose expiry is set and at
// or before :cutoff; an item with no expiry attribute never matches.
const expiredAtOrBeforeCondition = "#expires <= :cutoff"
