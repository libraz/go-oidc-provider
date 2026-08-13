package oidcdynamo

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// interactionStore holds in-flight login / consent state.
//
// It implements [store.InteractionStoreCAS], which the OP requires
// whenever a grant mounts the browser authorize endpoint. The
// compare-and-swap conditions on the opaque RawState blob: two browser
// tabs advancing the same interaction cannot both win, and the loser is
// told so rather than silently overwriting the winner's step.
type interactionStore struct {
	parent *Store
}

func (s *interactionStore) Save(ctx context.Context, i *store.Interaction) error {
	if i == nil {
		return errors.New("oidcdynamo: nil interaction")
	}
	entry, err := interactionItem(i)
	if err != nil {
		return err
	}
	if err := s.parent.overwrite(ctx, s.parent.names.interactions, entry); err != nil {
		return wrapErr("interactions.Save", err)
	}
	return nil
}

func (s *interactionStore) Find(ctx context.Context, id string) (*store.Interaction, error) {
	found, err := s.parent.getLive(ctx, s.parent.names.interactions, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("interactions.Find", err)
	}
	var rec store.Interaction
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// Delete removes the interaction and reports whether what it removed
// was live. An expired item is absent on every read path, and TTL
// reclamation is asynchronous, so answering from mere presence would
// make the result depend on when DynamoDB got around to the row.
func (s *interactionStore) Delete(ctx context.Context, id string) error {
	live, err := s.parent.deleteLiveKey(ctx, s.parent.names.interactions, id)
	if err != nil {
		return wrapErr("interactions.Delete", err)
	}
	if !live {
		return store.ErrNotFound
	}
	return nil
}

// CompareAndSwap implements [store.InteractionStoreCAS].
func (s *interactionStore) CompareAndSwap(ctx context.Context, previous, next *store.Interaction) error {
	if previous == nil || next == nil || previous.ID == "" || previous.ID != next.ID {
		return errors.New("oidcdynamo: invalid interaction compare-and-swap")
	}
	entry, err := interactionItem(next)
	if err != nil {
		return err
	}
	_, err = s.parent.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.parent.names.interactions),
		Item:      entry,
		ConditionExpression: aws.String(
			"attribute_exists(#pk) AND #state = :state AND (#exp = :zero OR #exp >= :now)",
		),
		ExpressionAttributeNames: map[string]string{
			"#pk":    attrPK,
			"#state": attrRawState,
			"#exp":   attrExpiresAt,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":state": avB(previous.RawState),
			":zero":  avN(0),
			":now":   avTime(s.parent.now()),
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return s.explainRejectedWrite(ctx, previous.ID)
		}
		return wrapErr("interactions.CompareAndSwap", err)
	}
	return nil
}

// DeleteIfUnchanged implements [store.InteractionStoreCAS].
func (s *interactionStore) DeleteIfUnchanged(ctx context.Context, previous *store.Interaction) error {
	if previous == nil || previous.ID == "" {
		return errors.New("oidcdynamo: invalid conditional interaction delete")
	}
	_, err := s.parent.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.parent.names.interactions),
		Key:       key(previous.ID),
		ConditionExpression: aws.String(
			"attribute_exists(#pk) AND #state = :state AND (#exp = :zero OR #exp >= :now)",
		),
		ExpressionAttributeNames: map[string]string{
			"#pk":    attrPK,
			"#state": attrRawState,
			"#exp":   attrExpiresAt,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":state": avB(previous.RawState),
			":zero":  avN(0),
			":now":   avTime(s.parent.now()),
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return s.explainRejectedWrite(ctx, previous.ID)
		}
		return wrapErr("interactions.DeleteIfUnchanged", err)
	}
	return nil
}

// explainRejectedWrite separates "the interaction is gone" from
// "someone else advanced it", which the caller needs in order to decide
// between restarting the flow and reporting a conflict.
func (s *interactionStore) explainRejectedWrite(ctx context.Context, id string) error {
	if _, err := s.Find(ctx, id); errors.Is(err, store.ErrNotFound) {
		return store.ErrNotFound
	} else if err != nil {
		return err
	}
	return store.ErrConflict
}

func interactionItem(i *store.Interaction) (item, error) {
	entry, err := newItem(i.ID).doc(i)
	if err != nil {
		return nil, err
	}
	entry.expires(i.ExpiresAt)
	entry[attrRawState] = avB(i.RawState)
	return entry, nil
}

var (
	_ store.InteractionStore    = (*interactionStore)(nil)
	_ store.InteractionStoreCAS = (*interactionStore)(nil)
)
