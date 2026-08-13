package oidcdynamo

import (
	"context"
	"errors"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// item accumulates the attributes of a single DynamoDB item. The
// builder exists so every substore writes its projected attributes and
// its document through one shape, which keeps the item layout uniform
// across 22 tables.
type item map[string]types.AttributeValue

// newItem starts an item keyed by pk.
func newItem(pk string) item {
	return item{attrPK: avS(pk)}
}

// newCompositeItem starts an item keyed by (pk, sort).
func newCompositeItem(pk, sortAttr string, sortValue types.AttributeValue) item {
	return item{attrPK: avS(pk), sortAttr: sortValue}
}

// set projects an attribute. An empty string value is skipped: DynamoDB
// rejects an empty string as an index key, and an absent attribute is
// how "no value" is represented throughout the adapter.
func (i item) set(name, value string) item {
	if value != "" {
		i[name] = avS(value)
	}
	return i
}

func (i item) setN(name string, value int64) item {
	i[name] = avN(value)
	return i
}

func (i item) setBool(name string, value bool) item {
	i[name] = avBool(value)
	return i
}

func (i item) setTime(name string, value time.Time) item {
	i[name] = avTime(value)
	return i
}

// expires projects the record's expiry twice: once at nanosecond
// precision for the adapter's own comparisons, once as the unix-seconds
// TTL attribute DynamoDB reclaims storage from.
func (i item) expires(at time.Time) item {
	i[attrExpiresAt] = avTime(at)
	if ttl, ok := avTTL(at); ok {
		i[attrTTL] = ttl
	}
	return i
}

// doc attaches the JSON-encoded record.
func (i item) doc(v any) (item, error) {
	encoded, err := marshalDoc(v)
	if err != nil {
		return nil, err
	}
	i[attrDoc] = encoded
	return i, nil
}

func key(pk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{attrPK: avS(pk)}
}

// get reads one item by primary key. The read is strongly consistent:
// every caller is making a security decision on the result, and an
// eventually consistent read can return an authorization code that was
// already redeemed.
func (s *Store) get(ctx context.Context, table, pk string) (item, error) {
	out, err := s.api.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(table),
		Key:            key(pk),
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

// getLive reads one item and reports [store.ErrNotFound] when its
// expiry has passed. DynamoDB's TTL deletion is asynchronous and
// documented as taking up to 48 hours, so expiry has to be enforced
// here rather than trusted to the table's TTL configuration.
func (s *Store) getLive(ctx context.Context, table, pk string) (item, error) {
	found, err := s.get(ctx, table, pk)
	if err != nil {
		return nil, err
	}
	if s.expired(found) {
		return nil, store.ErrNotFound
	}
	return found, nil
}

func (s *Store) expired(found item) bool {
	expiresAt := readTime(found, attrExpiresAt)
	return !expiresAt.IsZero() && expiresAt.Before(s.now())
}

// overwrite replaces whatever the key holds. It is the adapter's only
// write that asserts nothing, so it is confined to records whose holder
// is not itself a decision: a metadata value, a directory entry, a
// session its own owner rewrites.
//
// A write that decides who holds a key — a replay marker, an identifier
// claim, a state transition — states that decision as a condition
// instead. Reading a record, judging it, and overwriting it lets two
// callers reach the same judgement and both succeed, which is exactly
// the outcome a single-use guarantee exists to prevent.
func (s *Store) overwrite(ctx context.Context, table string, i item) error {
	_, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(table),
		Item:      i,
	})
	return err
}

// A record whose expiry has passed no longer identifies anything
// redeemable, and DynamoDB reclaims it asynchronously — documented as
// taking up to 48 hours — so a fresh record has to be able to take its
// key rather than wait for the row to disappear. The free-key guard
// states that as one condition: nothing is stored under the key, or what
// is stored has already expired. A record with no expiry at all holds
// its key indefinitely.
const freeKeyCondition = "attribute_not_exists(#pk) OR (#expires <> :never AND #expires < :now)"

// freeKeyAtExpiryCondition is [freeKeyCondition] under the inclusive
// expiry bound [store.ConsumedJTIStore] pins for replay markers: a
// record is free from its own expiry instant onwards rather than after
// it. The two bounds differ only at that instant, and a substore whose
// reads report a marker as expired there has to let a write take the
// key there too — otherwise a caller is told the jti is free and is
// still refused as a replay.
const freeKeyAtExpiryCondition = "attribute_not_exists(#pk) OR (#expires <> :never AND #expires <= :now)"

func freeKeyNames() map[string]string {
	return map[string]string{"#pk": attrPK, "#expires": attrExpiresAt}
}

func (s *Store) freeKeyValues() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{":never": avN(0), ":now": avTime(s.now())}
}

// putIfKeyFree writes an item onto a key nothing live holds, reporting
// whether the write landed. See [freeKeyCondition].
func (s *Store) putIfKeyFree(ctx context.Context, table string, i item) (bool, error) {
	return s.putUnderFreeKey(ctx, table, i, freeKeyCondition)
}

// putIfKeyFreeAtExpiry is [Store.putIfKeyFree] under the inclusive
// expiry bound. See [freeKeyAtExpiryCondition].
func (s *Store) putIfKeyFreeAtExpiry(ctx context.Context, table string, i item) (bool, error) {
	return s.putUnderFreeKey(ctx, table, i, freeKeyAtExpiryCondition)
}

// putUnderFreeKey is the single write behind the free-key guards:
// taking a key from a record that no longer holds it is one conditional
// write, so the judgement and the write cannot be separated by a
// competing caller.
func (s *Store) putUnderFreeKey(ctx context.Context, table string, i item, condition string) (bool, error) {
	_, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                 aws.String(table),
		Item:                      i,
		ConditionExpression:       aws.String(condition),
		ExpressionAttributeNames:  freeKeyNames(),
		ExpressionAttributeValues: s.freeKeyValues(),
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// putIfAbsent writes an item only when its primary key is unused,
// reporting whether the write landed.
func (s *Store) putIfAbsent(ctx context.Context, table string, i item) (bool, error) {
	_, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(table),
		Item:                i,
		ConditionExpression: aws.String("attribute_not_exists(" + attrPK + ")"),
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// updateFromItem renders entry as an UpdateItem that SETs every
// attribute it carries except the primary key and the ones named in
// preserve. The caller attaches the condition its read justified to the
// returned input.
//
// It exists for records that hold an atomically incremented counter
// beside their document: a PutItem replaces the whole item and would
// drop every increment that landed since the record was read. An
// attribute absent from entry is left as it is stored rather than
// removed, which holds because a record's projected attribute set is
// fixed by its writer and no transition clears one.
func updateFromItem(table string, entry item, preserve ...string) *dynamodb.UpdateItemInput {
	attrs := slices.Sorted(maps.Keys(entry))
	names := make(map[string]string, len(attrs))
	values := make(map[string]types.AttributeValue, len(attrs))
	clauses := make([]string, 0, len(attrs))
	for i, attr := range attrs {
		if attr == attrPK || slices.Contains(preserve, attr) {
			continue
		}
		alias, placeholder := "#u"+formatInt(int64(i)), ":u"+formatInt(int64(i))
		names[alias] = attr
		values[placeholder] = entry[attr]
		clauses = append(clauses, alias+" = "+placeholder)
	}
	return &dynamodb.UpdateItemInput{
		TableName:                 aws.String(table),
		Key:                       key(readS(entry, attrPK)),
		UpdateExpression:          aws.String("SET " + strings.Join(clauses, ", ")),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	}
}

// putBumpingVersion writes every attribute entry carries and advances
// the record's version in the same call, creating the item when its key
// is unused.
//
// The version is what a transaction's read-amend-write conditions on
// (see [txBuffer.putVersioned]). Letting the service do the increment is
// what keeps this path free of a read-modify-write of its own: a version
// read beforehand and written back could hand a stale value to a
// transaction that is about to commit against it.
func (s *Store) putBumpingVersion(ctx context.Context, table string, entry item, attr string) error {
	in := updateFromItem(table, entry, attr)
	in.UpdateExpression = aws.String(*in.UpdateExpression + " ADD #version :one")
	in.ExpressionAttributeNames["#version"] = attr
	in.ExpressionAttributeValues[":one"] = avN(1)
	_, err := s.api.UpdateItem(ctx, in)
	return err
}

// maxCounter8 is the ceiling of the saturating counters the store
// interfaces expose as uint8 (user-code strikes, poll violations). The
// SQL adapter's update carries the same guard, so a counter that has
// run away reports the ceiling on every backend instead of wrapping.
const maxCounter8 = math.MaxUint8

// counter8 reads a saturating counter projected beside a record's
// document. The projected attribute is authoritative: the counter is
// incremented in place, so the copy inside the document may lag it.
func counter8(from item, attr string) uint8 {
	switch n := readN(from, attr); {
	case n <= 0:
		return 0
	case n >= maxCounter8:
		return maxCounter8
	default:
		// The cases above bound n to (0, maxCounter8).
		return uint8(n)
	}
}

// incrementCounter bumps a saturating counter projected beside a
// record's document and returns the new value.
//
// The increment is one conditional update rather than a
// read-modify-write. These counters exist to detect parallel guessing,
// and N concurrent increments that each read the same value before
// writing it back would be recorded as one — the lockout they arm would
// then never trigger against the very access pattern it defends.
//
// The guard also enforces liveness, so a missing or expired record
// reports [store.ErrNotFound]. A counter already at [maxCounter8] stays
// there and reports the ceiling rather than an error.
func (s *Store) incrementCounter(ctx context.Context, op, table, pk, attr string) (uint8, error) {
	out, err := s.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(table),
		Key:              key(pk),
		UpdateExpression: aws.String("ADD #counter :one"),
		ConditionExpression: aws.String(
			"attribute_exists(#pk) AND (#expires = :never OR #expires >= :now) " +
				"AND (attribute_not_exists(#counter) OR #counter < :max)",
		),
		ExpressionAttributeNames: map[string]string{
			"#pk":      attrPK,
			"#expires": attrExpiresAt,
			"#counter": attr,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one":   avN(1),
			":never": avN(0),
			":now":   avTime(s.now()),
			":max":   avN(maxCounter8),
		},
		ReturnValues: types.ReturnValueUpdatedNew,
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return s.rejectedCounter(ctx, op, table, pk, attr)
		}
		return 0, wrapErr(op, err)
	}
	return counter8(out.Attributes, attr), nil
}

// rejectedCounter resolves an increment the guard turned away. Two
// situations reach it and only one is an error: a record that is gone
// or expired reports [store.ErrNotFound], while a counter already at
// the ceiling reports the ceiling.
func (s *Store) rejectedCounter(ctx context.Context, op, table, pk, attr string) (uint8, error) {
	found, err := s.getLive(ctx, table, pk)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return 0, store.ErrNotFound
		}
		return 0, wrapErr(op, err)
	}
	return counter8(found, attr), nil
}

// deleteKey removes one item and reports whether it existed. ALL_OLD
// return values are what make the distinction possible; DeleteItem is
// otherwise idempotent and silent.
func (s *Store) deleteKey(ctx context.Context, table, pk string) (bool, error) {
	out, err := s.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:    aws.String(table),
		Key:          key(pk),
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return false, err
	}
	return out.Attributes != nil, nil
}

// deleteLiveKey removes one item and reports whether what it removed
// was live. DynamoDB reclaims a TTL-expired item asynchronously —
// documented as taking up to 48 hours — so "the item was there" and
// "the item was redeemable" are different answers, and a substore whose
// Delete owes the caller [store.ErrNotFound] for an expired record
// needs the second one. ALL_OLD gives it in the same round trip the
// delete already costs; the item is reclaimed either way.
func (s *Store) deleteLiveKey(ctx context.Context, table, pk string) (bool, error) {
	out, err := s.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:    aws.String(table),
		Key:          key(pk),
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return false, err
	}
	if out.Attributes == nil {
		return false, nil
	}
	return !s.expired(out.Attributes), nil
}

// queryIndex enumerates every item whose indexed attribute equals
// value. Index reads cannot be strongly consistent, so callers that act
// on an individual result re-read it by primary key first.
func (s *Store) queryIndex(ctx context.Context, table, index, attr, value string) ([]item, error) {
	var (
		out   []item
		start map[string]types.AttributeValue
	)
	for {
		page, err := s.api.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(table),
			IndexName:                 aws.String(index),
			KeyConditionExpression:    aws.String("#a = :v"),
			ExpressionAttributeNames:  map[string]string{"#a": attr},
			ExpressionAttributeValues: map[string]types.AttributeValue{":v": avS(value)},
			ExclusiveStartKey:         start,
		})
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Items {
			out = append(out, raw)
		}
		if len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		start = page.LastEvaluatedKey
	}
}

// queryPartition enumerates every item sharing a partition key, in sort
// order. It backs the composite-key tables (recovery-code slots).
func (s *Store) queryPartition(ctx context.Context, table, pk string) ([]item, error) {
	var (
		out   []item
		start map[string]types.AttributeValue
	)
	for {
		page, err := s.api.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(table),
			KeyConditionExpression:    aws.String("#k = :v"),
			ExpressionAttributeNames:  map[string]string{"#k": attrPK},
			ExpressionAttributeValues: map[string]types.AttributeValue{":v": avS(pk)},
			ExclusiveStartKey:         start,
			ConsistentRead:            aws.Bool(true),
		})
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Items {
			out = append(out, raw)
		}
		if len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		start = page.LastEvaluatedKey
	}
}

// scanAll walks an entire table. It is used only where the store
// contract asks a question that has no key — HasAny and the static
// client reconciliation — and never on a request path.
func (s *Store) scanAll(ctx context.Context, table string, limit int32) ([]item, error) {
	var (
		out   []item
		start map[string]types.AttributeValue
	)
	for {
		in := &dynamodb.ScanInput{
			TableName:         aws.String(table),
			ExclusiveStartKey: start,
		}
		if limit > 0 {
			in.Limit = aws.Int32(limit)
		}
		page, err := s.api.Scan(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Items {
			out = append(out, raw)
		}
		if limit > 0 && len(out) >= int(limit) {
			return out[:limit], nil
		}
		if len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		start = page.LastEvaluatedKey
	}
}
