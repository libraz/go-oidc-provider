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

// cibaRequestStore backs OpenID Connect CIBA Core 1.0 backchannel
// authentication. The auth_req_id the client polls with is a bearer
// secret, so items are keyed on its digest, and every state transition
// is guarded by the status it expects to still find.
type cibaRequestStore struct {
	parent *Store
}

func (s *cibaRequestStore) Save(ctx context.Context, req *store.CIBARequest) error {
	if req == nil {
		return errors.New("oidcdynamo: nil ciba request")
	}
	pk := digestKey(req.ID)
	entry, err := cibaItem(req, pk)
	if err != nil {
		return err
	}
	placed, err := s.parent.putIfAbsent(ctx, s.parent.names.cibaRequests, entry)
	if err != nil {
		return wrapErr("cibaRequests.Save", err)
	}
	if placed {
		return nil
	}
	// An expired record no longer identifies anything redeemable, so it
	// releases its id to a fresh request; a live one is a collision.
	if _, err := s.findLive(ctx, pk); errors.Is(err, store.ErrNotFound) {
		if err := s.parent.put(ctx, s.parent.names.cibaRequests, entry); err != nil {
			return wrapErr("cibaRequests.Save.replaceExpired", err)
		}
		return nil
	} else if err != nil {
		return err
	}
	return store.ErrAlreadyExists
}

func (s *cibaRequestStore) FindByAuthReqID(ctx context.Context, authReqID string) (*store.CIBARequest, error) {
	rec, err := s.findLive(ctx, digestKey(authReqID))
	if err != nil {
		return nil, err
	}
	rec.ID = authReqID
	return rec, nil
}

func (s *cibaRequestStore) findLive(ctx context.Context, pk string) (*store.CIBARequest, error) {
	found, err := s.parent.get(ctx, s.parent.names.cibaRequests, pk)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("cibaRequests.Find", err)
	}
	var rec store.CIBARequest
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	if s.parent.isExpired(rec.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	return &rec, nil
}

func (s *cibaRequestStore) Approve(
	ctx context.Context,
	authReqID, subject, acr string,
	authTime time.Time,
) error {
	return s.transition(ctx, digestKey(authReqID), func(rec *store.CIBARequest) error {
		if rec.Status != store.CIBARequestStatusPending {
			return store.ErrConflict
		}
		rec.Status = store.CIBARequestStatusApproved
		rec.Subject = subject
		rec.ACR = acr
		rec.AuthTime = authTime
		return nil
	}, int64(store.CIBARequestStatusPending))
}

func (s *cibaRequestStore) Deny(ctx context.Context, authReqID, reason string) error {
	return s.transition(ctx, digestKey(authReqID), func(rec *store.CIBARequest) error {
		if rec.Status != store.CIBARequestStatusPending {
			return store.ErrConflict
		}
		rec.Status = store.CIBARequestStatusDenied
		rec.DenyReason = reason
		return nil
	}, int64(store.CIBARequestStatusPending))
}

func (s *cibaRequestStore) RecordPoll(
	ctx context.Context,
	authReqID string,
	when time.Time,
	nextInterval time.Duration,
) error {
	return s.transition(ctx, digestKey(authReqID), func(rec *store.CIBARequest) error {
		polled := when
		rec.LastPolledAt = &polled
		// The interval only escalates: accepting a smaller value would
		// let a client that polled too fast re-arm the gate it tripped.
		if nextInterval > rec.Interval {
			rec.Interval = nextInterval
		}
		return nil
	}, -1)
}

func (s *cibaRequestStore) IncrementPollViolation(ctx context.Context, authReqID string) (uint8, error) {
	var out uint8
	err := s.transition(ctx, digestKey(authReqID), func(rec *store.CIBARequest) error {
		if rec.PollViolations < ^uint8(0) {
			rec.PollViolations++
		}
		out = rec.PollViolations
		return nil
	}, -1)
	return out, err
}

// Consume redeems an approved request exactly once. The status guard is
// the single-use guarantee: a second poll that races the first loses
// the conditional write rather than issuing a second token set.
func (s *cibaRequestStore) Consume(ctx context.Context, authReqID string) (*store.CIBARequest, error) {
	pk := digestKey(authReqID)
	rec, err := s.findLive(ctx, pk)
	if err != nil {
		return nil, err
	}
	switch rec.Status {
	case store.CIBARequestStatusConsumed:
		return nil, store.ErrAlreadyConsumed
	case store.CIBARequestStatusApproved:
	default:
		return nil, store.ErrConflict
	}

	if err := s.transition(ctx, pk, func(current *store.CIBARequest) error {
		if current.Status != store.CIBARequestStatusApproved {
			return store.ErrAlreadyConsumed
		}
		current.Status = store.CIBARequestStatusConsumed
		return nil
	}, int64(store.CIBARequestStatusApproved)); err != nil {
		return nil, err
	}
	rec.ID = authReqID
	rec.Status = store.CIBARequestStatusConsumed
	return rec, nil
}

func (s *cibaRequestStore) transition(
	ctx context.Context,
	pk string,
	mutate func(*store.CIBARequest) error,
	expectStatus int64,
) error {
	rec, err := s.findLive(ctx, pk)
	if err != nil {
		return err
	}
	if err := mutate(rec); err != nil {
		return err
	}
	entry, err := cibaItem(rec, pk)
	if err != nil {
		return err
	}

	in := &dynamodb.PutItemInput{
		TableName: aws.String(s.parent.names.cibaRequests),
		Item:      entry,
	}
	if expectStatus >= 0 {
		in.ConditionExpression = aws.String("attribute_exists(#pk) AND #status = :expected")
		in.ExpressionAttributeNames = map[string]string{"#pk": attrPK, "#status": attrStatus}
		in.ExpressionAttributeValues = map[string]types.AttributeValue{":expected": avN(expectStatus)}
	} else {
		in.ConditionExpression = aws.String("attribute_exists(#pk)")
		in.ExpressionAttributeNames = map[string]string{"#pk": attrPK}
	}

	if _, err := s.parent.api.PutItem(ctx, in); err != nil {
		if isConditionalCheckFailed(err) {
			return store.ErrConflict
		}
		return wrapErr("cibaRequests.transition", err)
	}
	return nil
}

func cibaItem(req *store.CIBARequest, pk string) (item, error) {
	stored := *req
	stored.ID = pk
	// A record enters the table pending. Save takes the zero status as
	// "not stated" rather than persisting an unspecified state the
	// transition guards would then never match.
	if stored.Status == 0 {
		stored.Status = store.CIBARequestStatusPending
	}

	entry, err := newItem(pk).doc(&stored)
	if err != nil {
		return nil, err
	}
	entry.expires(req.ExpiresAt)
	entry.set(attrClientID, req.ClientID)
	entry.setN(attrStatus, int64(stored.Status))
	entry.setTime(attrIssuedAt, req.IssuedAt)
	return entry, nil
}

var _ store.CIBARequestStore = (*cibaRequestStore)(nil)
