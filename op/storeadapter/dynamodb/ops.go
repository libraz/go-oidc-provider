package oidcdynamo

import (
	"context"
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

func (s *Store) put(ctx context.Context, table string, i item) error {
	_, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(table),
		Item:      i,
	})
	return err
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
