package oidcdynamo

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// DynamoDB has no interactive transaction. TransactWriteItems is a
// single all-or-nothing call carrying up to 100 actions, and it cannot
// read. [store.Tx], by contrast, is a handle whose substores are
// mutated over time and whose effects become visible on Commit.
//
// The bridge is a write buffer. Substore handles obtained from a Tx
// record their intended writes here instead of calling the service;
// Commit translates the buffer into one TransactWriteItems. Reads
// through the Tx consult the buffer before the table, which reproduces
// the read-your-writes behaviour a relational transaction provides.
//
// What this does not reproduce is isolation against concurrent writers
// between BeginTx and Commit: DynamoDB has no row lock to hold across
// calls. Each buffered action instead carries the condition its read
// justified, so a concurrent modification makes the commit fail rather
// than silently overwrite.

type txOpKind int

const (
	txPut txOpKind = iota
	txPutIfAbsent
	txPutIfUnconsumed
	txDelete
)

type txOp struct {
	kind  txOpKind
	table string
	pk    string
	item  item

	// consumedAtGuard is set for txPutIfUnconsumed: the commit asserts
	// the stored item is still unconsumed before stamping it.
	consumedAtGuard bool
}

// txBuffer accumulates the writes of one transaction.
type txBuffer struct {
	parent *Store

	// ops is keyed by (table, primary key). TransactWriteItems rejects
	// a request that touches the same item twice and does not say which
	// item offended, so the buffer collapses repeated writes to one
	// action and the ordinary "write then overwrite" pattern keeps
	// working.
	ops   map[string]*txOp
	order []string

	settled bool
}

func newTxBuffer(parent *Store) *txBuffer {
	return &txBuffer{parent: parent, ops: make(map[string]*txOp)}
}

func bufferKey(table, pk string) string { return table + "\x00" + pk }

func (b *txBuffer) record(op *txOp) error {
	if b.settled {
		return store.ErrTxRequired
	}
	k := bufferKey(op.table, op.pk)
	if _, ok := b.ops[k]; !ok {
		b.order = append(b.order, k)
	}
	b.ops[k] = op
	return nil
}

func (b *txBuffer) put(table, pk string, i item) error {
	return b.record(&txOp{kind: txPut, table: table, pk: pk, item: i})
}

func (b *txBuffer) putIfAbsent(table string, i item) error {
	return b.record(&txOp{
		kind:  txPutIfAbsent,
		table: table,
		pk:    readS(i, attrPK),
		item:  i,
	})
}

func (b *txBuffer) delete(table, pk string) error {
	return b.record(&txOp{kind: txDelete, table: table, pk: pk})
}

// stampConsumed marks a record consumed inside the transaction. The
// buffered action re-asserts on commit that the item is still
// unconsumed, so a concurrent redemption between the read and the
// commit aborts the transaction instead of double-spending the record.
func (b *txBuffer) stampConsumed(ctx context.Context, table, pk string, at time.Time) error {
	if b.settled {
		return store.ErrTxRequired
	}
	base, err := b.get(ctx, table, pk)
	if err != nil {
		return err
	}
	next := cloneItem(base)
	next.setTime(attrConsumedAt, at)
	return b.record(&txOp{
		kind: txPutIfUnconsumed, table: table, pk: pk, item: next, consumedAtGuard: true,
	})
}

// get resolves a read through the buffer first so a caller observes its
// own uncommitted writes, then falls back to a strongly consistent read
// of the table.
func (b *txBuffer) get(ctx context.Context, table, pk string) (item, error) {
	if op, ok := b.ops[bufferKey(table, pk)]; ok {
		if op.kind == txDelete {
			return nil, store.ErrNotFound
		}
		return op.item, nil
	}
	return b.parent.get(ctx, table, pk)
}

func cloneItem(src item) item {
	out := make(item, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func (b *txBuffer) commit(ctx context.Context) error {
	if b.settled {
		return store.ErrTxRequired
	}
	b.settled = true
	if len(b.order) == 0 {
		return nil
	}
	if len(b.order) > maxTransactionItems {
		return fmt.Errorf("%w: %d writes (limit %d)",
			ErrTransactionTooLarge, len(b.order), maxTransactionItems)
	}

	actions := make([]types.TransactWriteItem, 0, len(b.order))
	for _, k := range b.order {
		actions = append(actions, b.ops[k].action())
	}
	_, err := b.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: actions,
	})
	if err != nil {
		if isTransactionCanceledByCondition(err) {
			return store.ErrConflict
		}
		return wrapErr("tx.Commit", err)
	}
	return nil
}

func (b *txBuffer) rollback() {
	b.settled = true
	b.ops = make(map[string]*txOp)
	b.order = nil
}

func (o *txOp) action() types.TransactWriteItem {
	switch o.kind {
	case txPutIfAbsent:
		return types.TransactWriteItem{Put: &types.Put{
			TableName:           aws.String(o.table),
			Item:                o.item,
			ConditionExpression: aws.String("attribute_not_exists(" + attrPK + ")"),
		}}
	case txPutIfUnconsumed:
		return types.TransactWriteItem{Put: &types.Put{
			TableName:           aws.String(o.table),
			Item:                o.item,
			ConditionExpression: aws.String("attribute_exists(#pk) AND #consumed = :zero"),
			ExpressionAttributeNames: map[string]string{
				"#pk":       attrPK,
				"#consumed": attrConsumedAt,
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":zero": avN(0),
			},
		}}
	case txDelete:
		return types.TransactWriteItem{Delete: &types.Delete{
			TableName: aws.String(o.table),
			Key:       key(o.pk),
		}}
	case txPut:
		fallthrough
	default:
		return types.TransactWriteItem{Put: &types.Put{
			TableName: aws.String(o.table),
			Item:      o.item,
		}}
	}
}

// tx is the [store.Tx] handle. Its substore accessors return handles
// bound to the same buffer.
type tx struct {
	buffer *txBuffer
	parent *Store

	// ctx is the context BeginTx was called with. [store.Tx.Commit]
	// takes no context of its own, and the transaction's lifetime is
	// the caller's request, so the commit is issued under it: a
	// cancelled request aborts the write rather than racing the
	// handler's teardown.
	ctx context.Context
}

// BeginTx implements [store.Transactional].
func (s *Store) BeginTx(ctx context.Context) (store.Tx, error) {
	return &tx{buffer: newTxBuffer(s), parent: s, ctx: ctx}, nil
}

// AuthorizationCodes implements [store.Tx].
func (t *tx) AuthorizationCodes() store.AuthorizationCodeStore {
	return &authCodeStore{parent: t.parent, tx: t.buffer}
}

// Grants implements [store.Tx].
func (t *tx) Grants() store.GrantStore {
	return &grantStore{parent: t.parent, tx: t.buffer}
}

// RefreshTokens implements [store.Tx].
func (t *tx) RefreshTokens() store.RefreshTokenStore {
	return &refreshStore{parent: t.parent, tx: t.buffer}
}

// PushedAuthRequests implements [store.Tx].
func (t *tx) PushedAuthRequests() store.PushedAuthRequestStore {
	return &parStore{parent: t.parent, tx: t.buffer}
}

// AccessTokens implements [store.Tx].
func (t *tx) AccessTokens() store.AccessTokenRegistry {
	return &accessTokenStore{parent: t.parent, tx: t.buffer}
}

// OpaqueAccessTokens implements [store.Tx].
func (t *tx) OpaqueAccessTokens() store.OpaqueAccessTokenStore {
	return &opaqueAccessTokenStore{parent: t.parent, tx: t.buffer}
}

// GrantRevocations implements [store.Tx].
func (t *tx) GrantRevocations() store.GrantRevocationStore {
	return &grantRevocationStore{parent: t.parent, tx: t.buffer}
}

// Commit implements [store.Tx].
func (t *tx) Commit() error {
	return t.buffer.commit(t.ctx)
}

// Rollback implements [store.Tx]. It is a no-op after Commit so a
// deferred Rollback works as a cleanup pattern.
func (t *tx) Rollback() error {
	if t.buffer.settled {
		return nil
	}
	t.buffer.rollback()
	return nil
}

var _ store.Tx = (*tx)(nil)
