package oidcdynamo

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// refreshStore holds refresh tokens and the rotation chains they form.
//
// The token is a bearer secret, so items are keyed on its digest and
// the parent pointer stores the parent's digest — chain traversal is
// digest-against-digest and never needs a raw credential. Two lookup
// modes exist deliberately: Find and Consume hash what they are given
// (possession of a stored digest must not redeem a token), while the
// chain resolver accepts either representation because it is reachable
// only from the OP's own revocation walk.
type refreshStore struct {
	parent *Store
	tx     *txBuffer
}

func (s *refreshStore) Save(ctx context.Context, t *store.RefreshToken) error {
	if t == nil {
		return errors.New("oidcdynamo: nil refresh token")
	}
	entry, err := refreshItem(t)
	if err != nil {
		return err
	}
	if s.tx != nil {
		if err := s.tx.putIfAbsent(s.parent.names.refreshes, entry); err != nil {
			return err
		}
		if t.ParentID == nil {
			return nil
		}
		return s.assertParentAlive(ctx, *t.ParentID)
	}

	placed, err := s.parent.putIfAbsent(ctx, s.parent.names.refreshes, entry)
	if err != nil {
		return wrapErr("refreshes.Save", err)
	}
	if !placed {
		return store.ErrAlreadyExists
	}
	if t.ParentID == nil {
		return nil
	}
	// A rotation must not survive a concurrent chain revocation: RFC
	// 9700 §2.2.2 requires the whole chain to die once a replay is
	// detected, and a descendant written after the cascade scanned
	// would keep the attacker's chain redeemable until natural expiry.
	// DynamoDB cannot hold a row lock across the insert and the
	// re-check, so the descendant is removed again when the parent
	// turns out to have been revoked meanwhile.
	if err := s.assertParentAlive(ctx, *t.ParentID); err != nil {
		if _, delErr := s.parent.deleteKey(ctx, s.parent.names.refreshes, digestKey(t.ID)); delErr != nil {
			return wrapErr("refreshes.Save.undoRotation", delErr)
		}
		return err
	}
	return nil
}

// assertParentAlive reports [store.ErrAlreadyConsumed] when the parent
// of a rotation has already been revoked. A missing parent proves no
// revocation happened — it may simply have been collected — so the
// rotation is kept.
func (s *refreshStore) assertParentAlive(ctx context.Context, parentID string) error {
	parent, err := s.findByHandle(ctx, parentID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if parent.Revoked {
		return store.ErrAlreadyConsumed
	}
	return nil
}

// SaveRotationWithRetry implements [store.RefreshRetryResponseStore].
// The successor and the sealed response cache land in one
// TransactWriteItems, so a failure leaves neither behind. Splitting
// them would let a successor persist while its cache write failed, and
// the client — which sees only the 5xx — would then retry with the
// predecessor it still holds: the grace window would find no cached
// response, take the presentation for a replay, and revoke a chain the
// client legitimately owns.
//
// The parent guard folded into the transaction is the same
// replay-revocation check [refreshStore.Save] makes after the fact
// (RFC 9700 §2.2.2), except that here it cannot leave a descendant to
// undo: a chain tombstoned meanwhile simply fails the rotation.
func (s *refreshStore) SaveRotationWithRetry(ctx context.Context, t *store.RefreshToken, sealed []byte) error {
	if t == nil || t.ParentID == nil || len(sealed) == 0 {
		return errors.New("oidcdynamo: retryable refresh rotation requires successor, parent, and sealed response")
	}
	parentDigest := digestKey(*t.ParentID)
	if s.tx != nil {
		// Inside a caller-owned transaction both writes are buffered and
		// commit together with everything else the token endpoint staged.
		if err := s.Save(ctx, t); err != nil {
			return err
		}
		err := s.tx.attach(ctx, s.parent.names.refreshes, parentDigest, attrRetryResponse, avB(sealed))
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}

	entry, err := refreshItem(t)
	if err != nil {
		return err
	}
	_, err = s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName:           aws.String(s.parent.names.refreshes),
				Item:                entry,
				ConditionExpression: aws.String("attribute_not_exists(" + attrPK + ")"),
			}},
			{Update: &types.Update{
				TableName:        aws.String(s.parent.names.refreshes),
				Key:              key(parentDigest),
				UpdateExpression: aws.String("SET #retry = :sealed"),
				ConditionExpression: aws.String(
					"attribute_exists(#pk) AND (attribute_not_exists(#revoked) OR #revoked = :false)",
				),
				ExpressionAttributeNames: map[string]string{
					"#pk":      attrPK,
					"#retry":   attrRetryResponse,
					"#revoked": attrRevoked,
				},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":sealed": avB(sealed),
					":false":  avBool(false),
				},
			}},
		},
	})
	if err != nil {
		if isTransactionCanceledByCondition(err) {
			rejected := s.rotationRejected(ctx, *t.ParentID, transactionCancellationCodes(err))
			if errors.Is(rejected, store.ErrNotFound) {
				// The predecessor row is gone rather than revoked, so
				// there is nothing to hang the cache on and nothing that
				// says the chain died. [refreshStore.Save] keeps the
				// rotation on exactly this input, and the two calls are
				// declared to share its semantics; the grace window is
				// the optional half and degrades on its own terms.
				return s.Save(ctx, t)
			}
			return rejected
		}
		return wrapErr("refreshes.SaveRotationWithRetry", err)
	}
	return nil
}

// rotationRejected maps a rejected rotation onto the sentinel the token
// endpoint expects. The parent guard is the one that carries meaning:
// it fails when the predecessor is no longer stored or its chain was
// tombstoned by a replay cascade, and the two drive different
// responses. codes is the transaction's per-action reason list, whose
// entries follow the submitted order (successor, then predecessor).
func (s *refreshStore) rotationRejected(ctx context.Context, parentID string, codes []string) error {
	if len(codes) < 2 || codes[1] == conditionalCheckFailed {
		parent, err := s.findByHandle(ctx, parentID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return store.ErrNotFound
		case err != nil:
			return err
		case parent.Revoked:
			return store.ErrAlreadyConsumed
		}
	}
	if len(codes) > 0 && codes[0] == conditionalCheckFailed {
		return store.ErrAlreadyExists
	}
	// A guard turned the write away but neither cause survives a
	// re-read: the rotation lost a race it must not silently win.
	return store.ErrConflict
}

// LoadRetryResponse implements [store.RefreshRetryResponseStore]. The
// read goes through the transaction when the handle came from one, so a
// rotation that has just staged the sealed response reads it back
// instead of reporting the grace window empty and taking the client's
// retry for a replay.
//
// The sealed bytes are an attribute of the predecessor's own item — the
// rotation attaches them there rather than to the successor it writes —
// so the record read here carries the lifetime the response may be kept
// for. Past it the response reads as absent: the predecessor is refused
// everywhere else by then, and answering out of the cache would
// re-deliver a token set for a credential the endpoint has stopped
// accepting, from an encrypted copy the backend owed the deployment it
// would let go of.
func (s *refreshStore) LoadRetryResponse(ctx context.Context, predecessorID string) ([]byte, error) {
	found, err := s.read(ctx, digestKey(predecessorID))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("refreshes.LoadRetryResponse", err)
	}
	if s.parent.expired(found) {
		return nil, store.ErrNotFound
	}
	sealed := readBytes(found, attrRetryResponse)
	if len(sealed) == 0 {
		return nil, store.ErrNotFound
	}
	return sealed, nil
}

func (s *refreshStore) Find(ctx context.Context, id string) (*store.RefreshToken, error) {
	rec, err := s.findByCredential(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.parent.isExpired(rec.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

// FindByStoredHandle implements [store.RefreshChainResolver]. The
// handle is an internal chain pointer, not a credential, so both the
// raw id and the stored digest resolve.
func (s *refreshStore) FindByStoredHandle(ctx context.Context, handle string) (*store.RefreshToken, error) {
	return s.findByHandle(ctx, handle)
}

func (s *refreshStore) findByCredential(ctx context.Context, id string) (*store.RefreshToken, error) {
	rec, err := s.load(ctx, digestKey(id))
	if err != nil {
		return nil, err
	}
	rec.ID = id
	return rec, nil
}

func (s *refreshStore) findByHandle(ctx context.Context, handle string) (*store.RefreshToken, error) {
	rec, err := s.load(ctx, digestKey(handle))
	if err == nil {
		rec.ID = handle
		return rec, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	rec, err = s.load(ctx, handle)
	if err != nil {
		return nil, err
	}
	rec.ID = handle
	return rec, nil
}

func (s *refreshStore) load(ctx context.Context, pk string) (*store.RefreshToken, error) {
	found, err := s.read(ctx, pk)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("refreshes.Find", err)
	}
	var rec store.RefreshToken
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	rec.ConsumedAt = optionalTime(found, attrConsumedAt)
	rec.Revoked = readBool(found, attrRevoked)
	return &rec, nil
}

func (s *refreshStore) read(ctx context.Context, pk string) (item, error) {
	if s.tx != nil {
		return s.tx.get(ctx, s.parent.names.refreshes, pk)
	}
	return s.parent.get(ctx, s.parent.names.refreshes, pk)
}

func (s *refreshStore) Consume(ctx context.Context, id string) (*store.RefreshToken, error) {
	rec, err := s.findByCredential(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.parent.isExpired(rec.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		return rec, store.ErrAlreadyConsumed
	}
	now := s.parent.now()
	digest := digestKey(id)

	if s.tx != nil {
		if err := s.tx.stampConsumed(ctx, s.parent.names.refreshes, digest, now); err != nil {
			return nil, err
		}
		rec.ConsumedAt = &now
		return rec, nil
	}

	_, err = s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.parent.names.refreshes),
		Key:                 key(digest),
		UpdateExpression:    aws.String("SET #consumed = :now"),
		ConditionExpression: aws.String("attribute_exists(#pk) AND #consumed = :zero"),
		ExpressionAttributeNames: map[string]string{
			"#pk":       attrPK,
			"#consumed": attrConsumedAt,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now":  avTime(now),
			":zero": avN(0),
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			if replay, findErr := s.findByCredential(ctx, id); findErr == nil && replay.ConsumedAt != nil {
				return replay, store.ErrAlreadyConsumed
			}
			return nil, store.ErrAlreadyConsumed
		}
		return nil, wrapErr("refreshes.Consume", err)
	}
	rec.ConsumedAt = &now
	return rec, nil
}

// RevokeChain walks the rotation tree breadth-first from rootID and
// stamps every node consumed and revoked.
//
// Outside a transaction the walk is not one atomic operation, but it is
// idempotent and converges: a descendant written while it runs is caught
// either by this walk or by the parent-alive re-check in
// [refreshStore.Save].
//
// Inside one it is atomic, and bounded: every node costs one of the
// transaction's actions, so a chain longer than the TransactWriteItems
// ceiling reports [ErrTransactionTooLarge] rather than retiring part of
// itself. The caller's fallback is the same walk outside a transaction,
// which has no ceiling.
//
// The child enumeration is an index read either way, so a descendant
// this transaction has staged but not committed is not part of the walk.
// The OP does not produce that shape — a rotation's successor is written
// onto a chain the same request is not also revoking — and a descendant
// that arrives afterwards is caught by the parent-alive re-check.
func (s *refreshStore) RevokeChain(ctx context.Context, rootID string) error {
	root, err := s.resolveChainRoot(ctx, rootID)
	if err != nil {
		return err
	}
	now := s.parent.now()
	visited := map[string]struct{}{root: {}}
	queue := []string{root}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if err := s.revokeOne(ctx, current, now); err != nil {
			return err
		}
		children, err := s.parent.queryIndex(
			ctx, s.parent.names.refreshes, indexByParent, attrParentID, current,
		)
		if err != nil {
			return wrapErr("refreshes.RevokeChain.children", err)
		}
		for _, child := range children {
			id := readS(child, attrPK)
			if id == "" {
				continue
			}
			if _, seen := visited[id]; seen {
				continue
			}
			visited[id] = struct{}{}
			queue = append(queue, id)
		}
	}
	return nil
}

// resolveChainRoot maps the caller's handle onto the stored key the
// parent index is expressed in. The probe reads through the transaction
// when there is one, so a chain whose root this transaction has just
// written resolves rather than reading as an unknown handle.
func (s *refreshStore) resolveChainRoot(ctx context.Context, rootID string) (string, error) {
	digest := digestKey(rootID)
	if _, err := s.read(ctx, digest); err == nil {
		return digest, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", wrapErr("refreshes.RevokeChain.resolve", err)
	}
	if _, err := s.read(ctx, rootID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", store.ErrNotFound
		}
		return "", wrapErr("refreshes.RevokeChain.resolve", err)
	}
	return rootID, nil
}

func (s *refreshStore) revokeOne(ctx context.Context, pk string, now time.Time) error {
	if s.tx != nil {
		return s.revokeOneStaged(ctx, pk, now)
	}
	_, err := s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.parent.names.refreshes),
		Key:                 key(pk),
		UpdateExpression:    aws.String("SET #revoked = :true"),
		ConditionExpression: aws.String("attribute_exists(#pk)"),
		ExpressionAttributeNames: map[string]string{
			"#pk":      attrPK,
			"#revoked": attrRevoked,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":true": avBool(true),
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return nil
		}
		return wrapErr("refreshes.revoke", err)
	}
	return s.stampConsumedIfUnset(ctx, pk, now)
}

// revokeOneStaged retires one chain node inside a transaction. The
// cascade is part of whatever the caller is deciding — a rotation, a
// replay response — so it has to be undoable: a write that reached the
// table immediately would survive a Rollback and retire a chain on the
// strength of a request that failed.
//
// Both attributes join a single staged action for the item, so a node
// costs one of the transaction's actions rather than two, and a node
// this transaction has already stamped consumed keeps the guard that
// stamping carried.
func (s *refreshStore) revokeOneStaged(ctx context.Context, pk string, now time.Time) error {
	found, err := s.tx.get(ctx, s.parent.names.refreshes, pk)
	if errors.Is(err, store.ErrNotFound) {
		// Nothing is stored under the key, so there is nothing to retire.
		// The direct path reaches the same outcome through its existence
		// guard.
		return nil
	}
	if err != nil {
		return wrapErr("refreshes.revoke", err)
	}
	// consumed_at is read before the revoked flag is staged, so the
	// decision below is made against the record as it stood rather than
	// against the copy this call is amending.
	consumed := readTime(found, attrConsumedAt)
	if err := s.tx.attach(ctx, s.parent.names.refreshes, pk, attrRevoked, avBool(true)); err != nil {
		return err
	}
	if !consumed.IsZero() {
		// See [refreshStore.stampConsumedIfUnset]: the instant a
		// legitimate rotation recorded is not overwritten.
		return nil
	}
	return s.tx.attach(ctx, s.parent.names.refreshes, pk, attrConsumedAt, avTime(now))
}

// stampConsumedIfUnset sets consumed_at only when it is still zero, so
// a revocation does not overwrite the instant a legitimate rotation
// consumed the token.
func (s *refreshStore) stampConsumedIfUnset(ctx context.Context, pk string, now time.Time) error {
	_, err := s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.parent.names.refreshes),
		Key:                 key(pk),
		UpdateExpression:    aws.String("SET #consumed = :now"),
		ConditionExpression: aws.String("attribute_exists(#pk) AND #consumed = :zero"),
		ExpressionAttributeNames: map[string]string{
			"#pk":       attrPK,
			"#consumed": attrConsumedAt,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now":  avTime(now),
			":zero": avN(0),
		},
	})
	if err != nil && !isConditionalCheckFailed(err) {
		return wrapErr("refreshes.revoke.consume", err)
	}
	return nil
}

// RevokeByGrant stamps every token of a grant consumed and revoked. A
// grant with no tokens is not an error.
func (s *refreshStore) RevokeByGrant(ctx context.Context, grantID string) error {
	return s.revokeByIndex(ctx, indexByGrant, attrGrantID, grantID, "refreshes.RevokeByGrant")
}

// RevokeByClient implements [store.RevokeByClient]. The dynamic
// registration cascade calls it after a client is deleted.
func (s *refreshStore) RevokeByClient(ctx context.Context, clientID string) error {
	if clientID == "" {
		return nil
	}
	return s.revokeByIndex(ctx, indexByClient, attrClientID, clientID, "refreshes.RevokeByClient")
}

// revokeByIndex retires every token an index points at. Inside a
// transaction the enumeration still reads the index — DynamoDB has no
// way to query staged writes — while each retirement is buffered, so the
// set is the committed one and the writes are undoable. The same
// per-node action cost as [refreshStore.RevokeChain] applies.
//
// The enumeration runs outside the buffer, so the settled-handle guard
// has to be explicit here: without it an index that matches nothing
// reports success through a handle that is no longer in a transaction.
func (s *refreshStore) revokeByIndex(ctx context.Context, index, attr, value, op string) error {
	if err := s.tx.assertOpen(); err != nil {
		return err
	}
	matches, err := s.parent.queryIndex(ctx, s.parent.names.refreshes, index, attr, value)
	if err != nil {
		return wrapErr(op, err)
	}
	now := s.parent.now()
	for _, match := range matches {
		pk := readS(match, attrPK)
		if pk == "" {
			continue
		}
		if err := s.revokeOne(ctx, pk, now); err != nil {
			return err
		}
	}
	return nil
}

func refreshItem(t *store.RefreshToken) (item, error) {
	digest := digestKey(t.ID)
	stored := *t
	stored.ID = digest
	stored.ConsumedAt = nil
	stored.Revoked = false

	var parentDigest string
	if t.ParentID != nil {
		parentDigest = patterns.Digest(*t.ParentID)
		stored.ParentID = &parentDigest
	}

	entry, err := newItem(digest).doc(&stored)
	if err != nil {
		return nil, err
	}
	entry.expires(t.ExpiresAt)
	entry.set(attrClientID, t.ClientID)
	entry.set(attrGrantID, t.GrantID)
	entry.set(attrParentID, parentDigest)
	entry.setTime(attrConsumedAt, timeOrZero(t.ConsumedAt))
	entry.setBool(attrRevoked, t.Revoked)
	return entry, nil
}

var (
	_ store.RefreshTokenStore         = (*refreshStore)(nil)
	_ store.RefreshChainResolver      = (*refreshStore)(nil)
	_ store.RefreshRetryResponseStore = (*refreshStore)(nil)
	_ store.RevokeByClient            = (*refreshStore)(nil)
)
