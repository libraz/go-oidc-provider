package oidcdynamo

import (
	"bytes"
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// clientStore is the registered-client table. Clients never expire, so
// the table carries no TTL and no expiry is evaluated on read.
type clientStore struct {
	parent *Store
}

func (s *clientStore) GetClient(ctx context.Context, id string) (*store.Client, error) {
	found, err := s.parent.get(ctx, s.parent.names.clients, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("clients.GetClient", err)
	}
	var c store.Client
	if err := unmarshalDoc(found, &c); err != nil {
		return nil, err
	}
	// A nil json.RawMessage marshals to the four bytes "null" and
	// unmarshals back as those bytes rather than as nil. Left alone it
	// would make an unchanged client compare unequal to the one the
	// embedder declared, which surfaces as a spurious static-client
	// conflict at startup.
	if bytes.Equal(c.JWKs, []byte("null")) {
		c.JWKs = nil
	}
	return &c, nil
}

// RegisterClient implements [store.ClientRegistry]. The conditional
// write is what makes a duplicate registration fail rather than
// silently overwrite a live client's secret hash.
func (s *clientStore) RegisterClient(ctx context.Context, c *store.Client) error {
	if c == nil {
		return errors.New("oidcdynamo: nil client")
	}
	i, err := clientItem(c)
	if err != nil {
		return err
	}
	placed, err := s.parent.putIfAbsent(ctx, s.parent.names.clients, i)
	if err != nil {
		return wrapErr("clients.RegisterClient", err)
	}
	if !placed {
		return store.ErrAlreadyExists
	}
	return nil
}

// Register is the internal spelling used by the static-client
// reconciliation path.
func (s *clientStore) Register(ctx context.Context, c *store.Client) error {
	return s.RegisterClient(ctx, c)
}

// UpdateClient implements [store.ClientRegistry]. It refuses to create:
// an update against an absent client is a caller error, not an upsert.
func (s *clientStore) UpdateClient(ctx context.Context, c *store.Client) error {
	if c == nil {
		return errors.New("oidcdynamo: nil client")
	}
	i, err := clientItem(c)
	if err != nil {
		return err
	}
	_, err = s.parent.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.parent.names.clients),
		Item:                i,
		ConditionExpression: aws.String("attribute_exists(" + attrPK + ")"),
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return store.ErrNotFound
		}
		return wrapErr("clients.UpdateClient", err)
	}
	return nil
}

func (s *clientStore) DeleteClient(ctx context.Context, id string) error {
	existed, err := s.parent.deleteKey(ctx, s.parent.names.clients, id)
	if err != nil {
		return wrapErr("clients.DeleteClient", err)
	}
	if !existed {
		return store.ErrNotFound
	}
	return nil
}

// ReconcileStaticClients implements [store.StaticClientReconciler].
//
// The whole batch is validated and compared before anything is
// written, and the inserts are then issued as one TransactWriteItems.
// A client that differs from its stored equivalent aborts the batch
// with [store.ErrConflict] having written nothing, which is the
// atomicity the contract requires: a partially applied static-client
// set would leave the OP serving a mix of two configurations.
func (s *clientStore) ReconcileStaticClients(ctx context.Context, clients []*store.Client) error {
	seen := make(map[string]struct{}, len(clients))
	var inserts []types.TransactWriteItem

	for _, desired := range clients {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateStaticClient(desired, seen); err != nil {
			return err
		}
		insert, err := s.staticClientInsert(ctx, desired)
		if err != nil {
			return err
		}
		if insert != nil {
			inserts = append(inserts, *insert)
		}
	}

	if len(inserts) == 0 {
		return nil
	}
	if len(inserts) > maxTransactionItems {
		return ErrTransactionTooLarge
	}
	_, err := s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: inserts,
	})
	if err != nil {
		// A condition failure here means another process registered one
		// of these ids between the comparison and the commit.
		if isTransactionCanceledByCondition(err) {
			return store.ErrConflict
		}
		return wrapErr("clients.ReconcileStaticClients", err)
	}
	return nil
}

// validateStaticClient rejects the declarations that cannot be
// reconciled at all: a nil entry, one claiming a non-static source, and
// a duplicate id within the same batch.
func validateStaticClient(desired *store.Client, seen map[string]struct{}) error {
	if desired == nil {
		return errors.New("oidcdynamo: nil static client")
	}
	if desired.Source != "" && desired.Source != store.ClientSourceStatic {
		return store.ErrConflict
	}
	if _, duplicate := seen[desired.ID]; duplicate {
		return store.ErrConflict
	}
	seen[desired.ID] = struct{}{}
	return nil
}

// staticClientInsert returns the transaction action that registers
// desired, or nil when an equivalent client is already stored. A stored
// client that differs reports [store.ErrConflict] so the caller aborts
// the whole batch before writing anything.
func (s *clientStore) staticClientInsert(
	ctx context.Context,
	desired *store.Client,
) (*types.TransactWriteItem, error) {
	existing, err := s.GetClient(ctx, desired.ID)
	switch {
	case err == nil:
		if !store.StaticClientEquivalent(existing, desired) {
			return nil, store.ErrConflict
		}
		return nil, nil //nolint:nilnil // "already equivalent" is an absent action, not an error.
	case errors.Is(err, store.ErrNotFound):
	default:
		return nil, err
	}

	i, err := clientItem(desired)
	if err != nil {
		return nil, err
	}
	return &types.TransactWriteItem{
		Put: &types.Put{
			TableName:           aws.String(s.parent.names.clients),
			Item:                i,
			ConditionExpression: aws.String("attribute_not_exists(" + attrPK + ")"),
		},
	}, nil
}

func clientItem(c *store.Client) (item, error) {
	return newItem(c.ID).doc(c)
}

var (
	_ store.ClientStore    = (*clientStore)(nil)
	_ store.ClientRegistry = (*clientStore)(nil)
)
