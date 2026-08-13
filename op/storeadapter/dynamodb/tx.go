package oidcdynamo

import (
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

// errTxClosed is what the buffer reports once the transaction has
// settled. [store.Tx] requires every call made through a committed or
// rolled-back handle to fail with an error satisfying errors.Is(err,
// [store.ErrTxRequired]): holding onto the handle is a programming
// error, and an embedder that cannot tell it from a transport fault
// retries it forever.
var errTxClosed = fmt.Errorf("oidcdynamo: transaction already closed: %w", store.ErrTxRequired)

type txOpKind int

const (
	txPut txOpKind = iota
	txPutIfAbsent
	txPutIfPresent
	txPutIfUnconsumed
	txPutIfMatch
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

	// match is set for txPutIfMatch: the attribute values the stored
	// item carried when the transaction first read it. The commit
	// asserts each of them again; a nil value asserts the attribute is
	// still absent.
	match map[string]types.AttributeValue
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

	// seen is the transaction's read set, keyed the same way: the stored
	// item as it looked the first time the transaction read it, or nil
	// for a key that was unused. It is what a guarded write conditions
	// on, so the guard covers the whole span between the caller's read
	// and the commit rather than only the write itself.
	seen map[string]item

	settled bool
}

func newTxBuffer(parent *Store) *txBuffer {
	return &txBuffer{parent: parent, ops: make(map[string]*txOp), seen: make(map[string]item)}
}

func bufferKey(table, pk string) string { return table + "\x00" + pk }

// assertOpen refuses a call made through a handle whose transaction has
// already settled. The nil receiver is the substore handle that was
// never bound to a transaction at all, which is always open.
//
// Every operation that reaches the buffer is guarded on its own, so this
// exists for the operations that do not: a bulk revocation enumerates
// its targets through the parent store, because a secondary index cannot
// see staged writes, and only then acts on each candidate through the
// buffer. The per-candidate writes carry the guard, so such an operation
// reports the sentinel whenever its enumeration found something — and
// returns silent success when the index matched nothing. Those two
// answers have to be the same one. A caller holding a leaked handle is
// otherwise told the revocation completed, which is exactly the reading
// [store.Tx] requires a settled handle never to produce.
//
// Callers put it first, ahead of argument validation, so a settled
// handle reports the closed-handle sentinel whatever it was passed.
func (b *txBuffer) assertOpen() error {
	if b != nil && b.settled {
		return errTxClosed
	}
	return nil
}

// record stages one action, replacing whatever the transaction had
// staged for the same item.
//
// The ceiling is enforced here rather than only at commit so an
// operation that stages per-record writes — a revocation cascade walking
// a long rotation chain — reports [ErrTransactionTooLarge] from the call
// that overflowed the buffer. The commit would fail either way; failing
// at the overflow names the operation responsible and stops the walk
// from reading the rest of a chain it can no longer retire.
func (b *txBuffer) record(op *txOp) error {
	if b.settled {
		return errTxClosed
	}
	k := bufferKey(op.table, op.pk)
	if _, ok := b.ops[k]; !ok {
		if len(b.order) >= maxTransactionItems {
			return fmt.Errorf("%w: %d writes (limit %d)",
				ErrTransactionTooLarge, len(b.order)+1, maxTransactionItems)
		}
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

// observe returns the stored state of an item as the transaction first
// saw it, reading the table once and reporting that same observation on
// every later call. A nil item means the key was unused.
//
// The read set exists because DynamoDB has no row lock to hold from a
// read to the write it justifies. Re-asserting the observed state on
// commit is the closest equivalent: a writer that landed in between
// aborts the transaction instead of having its work overwritten.
//
// A settled transaction is refused here as well as at the staging
// paths. This is the one place the buffer reaches the live table, so
// without the guard a lookup made through a handle the caller already
// committed would answer from the table with no error at all — telling
// the caller it is still inside a transaction that no longer exists.
func (b *txBuffer) observe(ctx context.Context, table, pk string) (item, error) {
	if b.settled {
		return nil, errTxClosed
	}
	k := bufferKey(table, pk)
	if base, ok := b.seen[k]; ok {
		return base, nil
	}
	base, err := b.parent.get(ctx, table, pk)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		base = nil
	}
	b.seen[k] = base
	return base, nil
}

// putGuarded stages a write that asserts, at commit, that the named
// attributes still hold the values the transaction observed. An item
// that was unused when the transaction read it is staged as an insert
// instead, so a record created meanwhile fails the commit rather than
// being replaced by a write that never saw it.
func (b *txBuffer) putGuarded(ctx context.Context, table, pk string, i item, guarded ...string) error {
	if b.settled {
		return errTxClosed
	}
	if op, ok := b.ops[bufferKey(table, pk)]; ok && op.kind != txDelete {
		// A second write to an item this transaction already staged joins
		// that action, so the buffer still holds one write for the item
		// and the guard the first write established survives.
		op.item = i
		return nil
	}
	base, err := b.observe(ctx, table, pk)
	if err != nil {
		return err
	}
	if base == nil {
		return b.record(&txOp{kind: txPutIfAbsent, table: table, pk: pk, item: i})
	}
	match := make(map[string]types.AttributeValue, len(guarded))
	for _, attr := range guarded {
		match[attr] = base[attr]
	}
	return b.record(&txOp{kind: txPutIfMatch, table: table, pk: pk, item: i, match: match})
}

// putVersioned stages a write that carries the record's next version and
// asserts, at commit, that the version it was derived from is still the
// stored one.
//
// It is how a record the OP reads, amends, and writes back inside a
// transaction survives a concurrent amendment: without the guard the
// later commit would replace the record wholesale, dropping whatever the
// earlier one added to it.
func (b *txBuffer) putVersioned(ctx context.Context, table, pk string, i item, attr string) error {
	if b.settled {
		return errTxClosed
	}
	if op, ok := b.ops[bufferKey(table, pk)]; ok && op.kind != txDelete {
		if version := op.item[attr]; version != nil {
			// The version the staged write already assigned still
			// describes the single action the buffer holds for this item.
			i[attr] = version
			op.item = i
			return nil
		}
	}
	base, err := b.observe(ctx, table, pk)
	if err != nil {
		return err
	}
	i[attr] = avN(readN(base, attr) + 1)
	return b.putGuarded(ctx, table, pk, i, attr)
}

// stampConsumed marks a record consumed inside the transaction. The
// buffered action re-asserts on commit that the item is still
// unconsumed, so a concurrent redemption between the read and the
// commit aborts the transaction instead of double-spending the record.
func (b *txBuffer) stampConsumed(ctx context.Context, table, pk string, at time.Time) error {
	if b.settled {
		return errTxClosed
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

// attach adds one attribute to a record inside the transaction.
//
// When the item is already staged — the predecessor a rotation has just
// stamped consumed, say — the attribute joins that staged write, so the
// buffer still holds a single action for it and the guard the earlier
// write carried survives. Otherwise the stored item is read and
// re-staged with the attribute under an existence guard, which is what
// makes a missing record fail the transaction instead of creating one.
func (b *txBuffer) attach(ctx context.Context, table, pk, attr string, value types.AttributeValue) error {
	if b.settled {
		return errTxClosed
	}
	if op, ok := b.ops[bufferKey(table, pk)]; ok {
		if op.kind == txDelete {
			return store.ErrNotFound
		}
		op.item[attr] = value
		return nil
	}
	base, err := b.get(ctx, table, pk)
	if err != nil {
		return err
	}
	next := cloneItem(base)
	next[attr] = value
	return b.record(&txOp{kind: txPutIfPresent, table: table, pk: pk, item: next})
}

// get resolves a read through the buffer first so a caller observes its
// own uncommitted writes, then falls back to the transaction's read set,
// which reads the table once and remembers what it saw.
//
// Every substore read bound to a transaction lands here, so the settle
// check is what makes a lookup through a committed handle fail the way
// [store.Tx] requires rather than serving the staged item the buffer
// still holds.
func (b *txBuffer) get(ctx context.Context, table, pk string) (item, error) {
	if b.settled {
		return nil, errTxClosed
	}
	if op, ok := b.ops[bufferKey(table, pk)]; ok {
		if op.kind == txDelete {
			return nil, store.ErrNotFound
		}
		return op.item, nil
	}
	base, err := b.observe(ctx, table, pk)
	if err != nil {
		return nil, err
	}
	if base == nil {
		return nil, store.ErrNotFound
	}
	return base, nil
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
		return errTxClosed
	}
	b.settled = true
	if len(b.order) == 0 {
		return nil
	}
	// [txBuffer.record] refuses the write that would overflow the buffer,
	// so this is the backstop for a future staging path that bypasses it:
	// the service reports an over-sized request as an opaque
	// ValidationException, and the sentinel is what a caller can act on.
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
	b.seen = make(map[string]item)
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
	case txPutIfPresent:
		return types.TransactWriteItem{Put: &types.Put{
			TableName:           aws.String(o.table),
			Item:                o.item,
			ConditionExpression: aws.String("attribute_exists(" + attrPK + ")"),
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
	case txPutIfMatch:
		return types.TransactWriteItem{Put: o.matchPut()}
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

// matchPut renders the read-set assertion of a txPutIfMatch action. The
// attributes are walked in sorted order so the expression a given guard
// produces is stable and reads the same in a service log every time.
func (o *txOp) matchPut() *types.Put {
	names := map[string]string{"#pk": attrPK}
	values := make(map[string]types.AttributeValue, len(o.match))
	clauses := make([]string, 0, len(o.match)+1)
	clauses = append(clauses, "attribute_exists(#pk)")
	for i, attr := range slices.Sorted(maps.Keys(o.match)) {
		alias := "#m" + formatInt(int64(i))
		names[alias] = attr
		if o.match[attr] == nil {
			clauses = append(clauses, "attribute_not_exists("+alias+")")
			continue
		}
		placeholder := ":m" + formatInt(int64(i))
		values[placeholder] = o.match[attr]
		clauses = append(clauses, alias+" = "+placeholder)
	}
	put := &types.Put{
		TableName:                aws.String(o.table),
		Item:                     o.item,
		ConditionExpression:      aws.String(strings.Join(clauses, " AND ")),
		ExpressionAttributeNames: names,
	}
	if len(values) > 0 {
		put.ExpressionAttributeValues = values
	}
	return put
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
