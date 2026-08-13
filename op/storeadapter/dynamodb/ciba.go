package oidcdynamo

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

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
	// An expired record no longer identifies anything redeemable, so it
	// releases its id to a fresh request; a live one is a collision. The
	// takeover is part of that decision and rides the same conditional
	// write, so two requests landing on one expired record cannot both be
	// told they own the id.
	placed, err := s.parent.putIfKeyFree(ctx, s.parent.names.cibaRequests, entry)
	if err != nil {
		return wrapErr("cibaRequests.Save", err)
	}
	if !placed {
		return store.ErrAlreadyExists
	}
	return nil
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
	// The poll-violation counter is incremented in place, so the copy
	// carried by the document may lag the projected attribute; the
	// attribute is what the record reports.
	rec.PollViolations = counter8(found, attrPollViolations)
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
	}, int64(store.CIBARequestStatusPending), subject)
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

// IncrementPollViolation records one poll that arrived too early. The
// counter gates a lockout against clients that ignore the backoff, so
// it is incremented atomically rather than through
// [cibaRequestStore.transition]: polls arrive in parallel, and a
// read-modify-write would record a burst of them as one.
func (s *cibaRequestStore) IncrementPollViolation(ctx context.Context, authReqID string) (uint8, error) {
	return s.parent.incrementCounter(
		ctx, "cibaRequests.IncrementPollViolation", s.parent.names.cibaRequests,
		digestKey(authReqID), attrPollViolations,
	)
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

// transition applies mutate to the stored record and writes it back
// under the status it expects to still find. The write is an update
// rather than a replacement so it leaves the poll-violation counter
// alone: it is incremented in place by callers that race this one, and
// a full item write would roll back whichever increments landed since
// the record was read.
//
//nolint:gocognit // The atomic status and legacy-subject predicates must stay adjacent to the mutation they protect.
func (s *cibaRequestStore) transition(
	ctx context.Context,
	pk string,
	mutate func(*store.CIBARequest) error,
	expectStatus int64,
	expectedSubject ...string,
) error {
	rec, err := s.findLive(ctx, pk)
	if err != nil {
		return err
	}
	// Keep the identity observed before mutate. Approve deliberately fills
	// an empty legacy/deferred subject, so inspecting rec.Subject after the
	// mutation would turn the one allowed population into an equality check
	// against an attribute that is still absent in the stored item.
	subjectWasEmpty := false
	if len(expectedSubject) > 0 {
		subjectWasEmpty = rec.Subject == ""
		if !subjectWasEmpty && rec.Subject != expectedSubject[0] {
			return store.ErrConflict
		}
	}
	if err := mutate(rec); err != nil {
		return err
	}
	entry, err := cibaItem(rec, pk)
	if err != nil {
		return err
	}

	in := updateFromItem(s.parent.names.cibaRequests, entry, attrPollViolations)
	in.ExpressionAttributeNames["#pk"] = attrPK
	if expectStatus >= 0 {
		in.ConditionExpression = aws.String("attribute_exists(#pk) AND #status = :expected")
		in.ExpressionAttributeNames["#status"] = attrStatus
		in.ExpressionAttributeValues[":expected"] = avN(expectStatus)
	} else {
		in.ConditionExpression = aws.String("attribute_exists(#pk)")
	}
	if len(expectedSubject) > 0 {
		in.ExpressionAttributeNames["#subject"] = attrSubject
		// cibaItem omits an empty subject, so a missing projection means
		// that this is the one legacy/deferred population allowed by the
		// contract. A non-empty subject must already be projected and is
		// compared exactly. Deriving the predicate from the strongly
		// consistent record read also keeps old rows written before the
		// projection was introduced safe: a non-empty subject with no
		// projection fails closed instead of being treated as deferred.
		if subjectWasEmpty {
			in.ConditionExpression = aws.String(*in.ConditionExpression +
				" AND attribute_not_exists(#subject)")
		} else {
			in.ConditionExpression = aws.String(*in.ConditionExpression +
				" AND #subject = :subject")
			in.ExpressionAttributeValues[":subject"] = avS(expectedSubject[0])
		}
	}

	if _, err := s.parent.api.UpdateItem(ctx, in); err != nil {
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
	entry.set(attrSubject, req.Subject)
	entry.setN(attrStatus, int64(stored.Status))
	entry.setTime(attrIssuedAt, req.IssuedAt)
	// The poll-violation counter is projected so it can be incremented
	// atomically. A transition preserves whatever the table holds; only
	// a Save (a fresh record, or one replacing an expired holder) writes
	// it, which is what resets it.
	entry.setN(attrPollViolations, int64(req.PollViolations))
	return entry, nil
}

var _ store.CIBARequestStore = (*cibaRequestStore)(nil)
