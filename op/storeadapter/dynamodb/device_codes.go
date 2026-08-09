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

// deviceCodeStore backs RFC 8628 device authorization.
//
// Two identifiers address the same record: the device_code the device
// polls with (a bearer secret, so items are keyed on its digest) and the
// user_code the human reads aloud, which is claimed as a reservation
// item under its own key. Every state transition is a conditional update
// on the status attribute, so approve, deny, and consume cannot race
// each other into an inconsistent record.
type deviceCodeStore struct {
	parent *Store
}

// userCodePrefix namespaces the user_code reservations inside the device
// code table. Record keys are hex digests, so the two key shapes cannot
// collide.
const userCodePrefix = "uc#"

func userCodeKey(userCode string) string { return userCodePrefix + userCode }

// Save writes the record and, when it carries a user_code, claims that
// code in the same transaction.
//
// The claim is a conditional write onto the code's own key rather than a
// lookup followed by an insert. DynamoDB cannot enforce uniqueness on a
// secondary index, and checking one first leaves a window in which two
// device authorization requests both find the code free: the verification
// page would then approve whichever record the eventually consistent
// index happened to surface, and the other device would poll forever.
func (s *deviceCodeStore) Save(ctx context.Context, code *store.DeviceCode) error {
	if code == nil {
		return errors.New("oidcdynamo: nil device code")
	}
	entry, err := deviceCodeItem(code)
	if err != nil {
		return err
	}
	if code.UserCode == "" {
		placed, err := s.parent.putIfKeyFree(ctx, s.parent.names.deviceCodes, entry)
		if err != nil {
			return wrapErr("deviceCodes.Save", err)
		}
		if !placed {
			return store.ErrAlreadyExists
		}
		return nil
	}
	return s.saveWithUserCode(ctx, entry, code)
}

// saveWithUserCode writes the record and its user_code reservation as
// one all-or-nothing transaction, so a reservation can never outlive a
// record that failed to land and block the code until it expires.
func (s *deviceCodeStore) saveWithUserCode(ctx context.Context, entry item, code *store.DeviceCode) error {
	reservation := newItem(userCodeKey(code.UserCode)).set(attrReservedFor, readS(entry, attrPK))
	reservation.expires(code.ExpiresAt)

	names, values := freeKeyNames(), s.parent.freeKeyValues()
	claim := func(i item) types.TransactWriteItem {
		return types.TransactWriteItem{Put: &types.Put{
			TableName:                 aws.String(s.parent.names.deviceCodes),
			Item:                      i,
			ConditionExpression:       aws.String(freeKeyCondition),
			ExpressionAttributeNames:  names,
			ExpressionAttributeValues: values,
		}}
	}
	_, err := s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{claim(reservation), claim(entry)},
	})
	if err != nil {
		// Either key is held by a live record: the user_code is in use, or
		// the device_code itself was issued twice.
		if isTransactionCanceledByCondition(err) {
			return store.ErrAlreadyExists
		}
		return wrapErr("deviceCodes.Save", err)
	}
	return nil
}

func (s *deviceCodeStore) FindByDeviceCode(ctx context.Context, deviceCode string) (*store.DeviceCode, error) {
	rec, _, err := s.findLive(ctx, digestKey(deviceCode))
	if err != nil {
		return nil, err
	}
	rec.ID = deviceCode
	return rec, nil
}

func (s *deviceCodeStore) FindByUserCode(ctx context.Context, userCode string) (*store.DeviceCode, error) {
	pk, err := s.resolveUserCode(ctx, userCode)
	if err != nil {
		return nil, err
	}
	rec, _, err := s.findLive(ctx, pk)
	if err != nil {
		return nil, err
	}
	// The user_code lookup must never hand back the wire device_code: a
	// malicious verification page could otherwise poll on the device's
	// behalf. The stored id is a digest, but blanking it removes even
	// that as an oracle.
	rec.ID = ""
	return rec, nil
}

// resolveUserCode maps a user code onto the partition key of the live
// record holding it, through the reservation [deviceCodeStore.Save]
// claimed for it.
//
// Resolving through the reservation rather than through a secondary
// index is what keeps the answer single-valued: the reservation is the
// uniqueness constraint, its read is strongly consistent, and an expired
// reservation reports nothing even while DynamoDB still holds the item.
func (s *deviceCodeStore) resolveUserCode(ctx context.Context, userCode string) (string, error) {
	if userCode == "" {
		return "", store.ErrNotFound
	}
	found, err := s.parent.get(ctx, s.parent.names.deviceCodes, userCodeKey(userCode))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", store.ErrNotFound
		}
		return "", wrapErr("deviceCodes.FindByUserCode", err)
	}
	if s.parent.expired(found) {
		return "", store.ErrNotFound
	}
	pk := readS(found, attrReservedFor)
	if pk == "" {
		return "", store.ErrNotFound
	}
	return pk, nil
}

func (s *deviceCodeStore) findLive(ctx context.Context, pk string) (*store.DeviceCode, item, error) {
	found, err := s.parent.get(ctx, s.parent.names.deviceCodes, pk)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, store.ErrNotFound
		}
		return nil, nil, wrapErr("deviceCodes.Find", err)
	}
	var rec store.DeviceCode
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, nil, err
	}
	// The brute-force counters are incremented in place, so the copy
	// carried by the document may lag the projected attributes; the
	// attributes are what the record reports.
	rec.UserCodeStrikes = counter8(found, attrUserCodeStrikes)
	rec.PollViolations = counter8(found, attrPollViolations)
	if s.parent.isExpired(rec.ExpiresAt) {
		return nil, nil, store.ErrNotFound
	}
	return &rec, found, nil
}

func (s *deviceCodeStore) Approve(ctx context.Context, deviceCode, subject string, authTime time.Time) error {
	return s.approve(ctx, digestKey(deviceCode), subject, authTime)
}

func (s *deviceCodeStore) ApproveByUserCode(ctx context.Context, userCode, subject string, authTime time.Time) error {
	pk, err := s.resolveUserCode(ctx, userCode)
	if err != nil {
		return err
	}
	return s.approve(ctx, pk, subject, authTime)
}

// approve moves a pending record to approved. The status guard is what
// stops a second approval, a denial that raced it, or an approval of an
// already-consumed record.
func (s *deviceCodeStore) approve(ctx context.Context, pk, subject string, authTime time.Time) error {
	return s.transition(ctx, pk, func(rec *store.DeviceCode) error {
		if rec.Status != store.DeviceCodeStatusPending {
			return store.ErrConflict
		}
		rec.Status = store.DeviceCodeStatusApproved
		rec.Subject = subject
		rec.AuthTime = authTime
		return nil
	}, int64(store.DeviceCodeStatusPending))
}

func (s *deviceCodeStore) Deny(ctx context.Context, deviceCode, reason string) error {
	return s.deny(ctx, digestKey(deviceCode), reason)
}

func (s *deviceCodeStore) DenyByUserCode(ctx context.Context, userCode, reason string) error {
	pk, err := s.resolveUserCode(ctx, userCode)
	if err != nil {
		return err
	}
	return s.deny(ctx, pk, reason)
}

func (s *deviceCodeStore) deny(ctx context.Context, pk, reason string) error {
	return s.transition(ctx, pk, func(rec *store.DeviceCode) error {
		if rec.Status != store.DeviceCodeStatusPending {
			return store.ErrConflict
		}
		rec.Status = store.DeviceCodeStatusDenied
		rec.DenyReason = reason
		return nil
	}, int64(store.DeviceCodeStatusPending))
}

// Revoke is the administrative kill switch. It denies a record that is
// still pending or approved and is a no-op on one that has already
// reached a terminal state: a denial keeps the reason the user's own
// refusal recorded, and a consumed record has already produced its
// tokens, so rewriting either would only lose information. Revoke is
// idempotent for the same reason.
func (s *deviceCodeStore) Revoke(ctx context.Context, deviceCode, reason string) error {
	pk := digestKey(deviceCode)
	rec, _, err := s.findLive(ctx, pk)
	if err != nil {
		return err
	}
	if rec.Status != store.DeviceCodeStatusPending && rec.Status != store.DeviceCodeStatusApproved {
		return nil
	}
	err = s.transition(ctx, pk, func(current *store.DeviceCode) error {
		if current.Status != store.DeviceCodeStatusPending &&
			current.Status != store.DeviceCodeStatusApproved {
			return errDeviceCodeTerminal
		}
		current.Status = store.DeviceCodeStatusDenied
		current.DenyReason = reason
		return nil
	}, -1)
	if errors.Is(err, errDeviceCodeTerminal) {
		return nil
	}
	return err
}

// errDeviceCodeTerminal signals that a record reached a terminal state
// between the read and the guarded write. It never escapes Revoke.
var errDeviceCodeTerminal = errors.New("oidcdynamo: device code already terminal")

func (s *deviceCodeStore) RecordPoll(
	ctx context.Context,
	deviceCode string,
	when time.Time,
	nextInterval time.Duration,
) error {
	return s.transition(ctx, digestKey(deviceCode), func(rec *store.DeviceCode) error {
		polled := when
		rec.LastPolledAt = &polled
		// The interval only escalates. Accepting a smaller value would
		// let a device that polled too fast re-arm the gate it just
		// tripped by passing the original interval back.
		if nextInterval > rec.Interval {
			rec.Interval = nextInterval
		}
		return nil
	}, -1)
}

func (s *deviceCodeStore) IncrementUserCodeStrike(ctx context.Context, deviceCode string) (uint8, error) {
	return s.incrementStrike(ctx, digestKey(deviceCode))
}

func (s *deviceCodeStore) IncrementUserCodeStrikeByUserCode(ctx context.Context, userCode string) (uint8, error) {
	pk, err := s.resolveUserCode(ctx, userCode)
	if err != nil {
		return 0, err
	}
	return s.incrementStrike(ctx, pk)
}

// incrementStrike records one user_code mismatch. The counter gates a
// brute-force lockout, so it is incremented atomically rather than
// through [deviceCodeStore.transition]: guesses arrive in parallel by
// design, and a read-modify-write would record a burst of them as one.
func (s *deviceCodeStore) incrementStrike(ctx context.Context, pk string) (uint8, error) {
	return s.parent.incrementCounter(
		ctx, "deviceCodes.IncrementUserCodeStrike", s.parent.names.deviceCodes, pk, attrUserCodeStrikes)
}

func (s *deviceCodeStore) IncrementPollViolation(ctx context.Context, deviceCode string) (uint8, error) {
	return s.parent.incrementCounter(
		ctx, "deviceCodes.IncrementPollViolation", s.parent.names.deviceCodes,
		digestKey(deviceCode), attrPollViolations)
}

// Consume redeems an approved record exactly once.
func (s *deviceCodeStore) Consume(ctx context.Context, deviceCode string) (*store.DeviceCode, error) {
	pk := digestKey(deviceCode)
	rec, _, err := s.findLive(ctx, pk)
	if err != nil {
		return nil, err
	}
	switch rec.Status {
	case store.DeviceCodeStatusConsumed:
		return nil, store.ErrAlreadyConsumed
	case store.DeviceCodeStatusApproved:
	case store.DeviceCodeStatusPending, store.DeviceCodeStatusDenied:
		return nil, store.ErrConflict
	default:
		return nil, store.ErrConflict
	}

	if err := s.transition(ctx, pk, func(current *store.DeviceCode) error {
		if current.Status != store.DeviceCodeStatusApproved {
			return store.ErrAlreadyConsumed
		}
		current.Status = store.DeviceCodeStatusConsumed
		return nil
	}, int64(store.DeviceCodeStatusApproved)); err != nil {
		return nil, err
	}
	rec.ID = deviceCode
	rec.Status = store.DeviceCodeStatusConsumed
	return rec, nil
}

// transition applies mutate to the stored record and writes it back
// under a status guard, so the write only lands if the state the
// decision was made against is still the state in the table.
//
// expectStatus is the status the record must still carry, or -1 when
// the transition does not depend on one.
//
// The write is an update rather than a replacement so it leaves the
// brute-force counters alone: they are incremented in place by callers
// that race this one, and a full item write would roll back whichever
// increments landed since the record was read.
func (s *deviceCodeStore) transition(
	ctx context.Context,
	pk string,
	mutate func(*store.DeviceCode) error,
	expectStatus int64,
) error {
	rec, found, err := s.findLive(ctx, pk)
	if err != nil {
		return err
	}
	if err := mutate(rec); err != nil {
		return err
	}
	entry, err := deviceCodeItemFrom(rec, readS(found, attrPK), readS(found, attrUserCode))
	if err != nil {
		return err
	}

	in := updateFromItem(s.parent.names.deviceCodes, entry, attrUserCodeStrikes, attrPollViolations)
	in.ExpressionAttributeNames["#pk"] = attrPK
	if expectStatus >= 0 {
		in.ConditionExpression = aws.String("attribute_exists(#pk) AND #status = :expected")
		in.ExpressionAttributeNames["#status"] = attrStatus
		in.ExpressionAttributeValues[":expected"] = avN(expectStatus)
	} else {
		in.ConditionExpression = aws.String("attribute_exists(#pk)")
	}

	if _, err := s.parent.api.UpdateItem(ctx, in); err != nil {
		if isConditionalCheckFailed(err) {
			return store.ErrConflict
		}
		return wrapErr("deviceCodes.transition", err)
	}
	return nil
}

func deviceCodeItem(code *store.DeviceCode) (item, error) {
	digest := digestKey(code.ID)
	return deviceCodeItemFrom(code, digest, code.UserCode)
}

func deviceCodeItemFrom(code *store.DeviceCode, pk, userCode string) (item, error) {
	stored := *code
	stored.ID = pk
	// A record enters the table pending. Save takes the zero status as
	// "not stated" rather than persisting an unspecified state the
	// transition guards would then never match.
	if stored.Status == 0 {
		stored.Status = store.DeviceCodeStatusPending
	}

	entry, err := newItem(pk).doc(&stored)
	if err != nil {
		return nil, err
	}
	entry.expires(code.ExpiresAt)
	entry.set(attrUserCode, userCode)
	entry.set(attrClientID, code.ClientID)
	entry.setN(attrStatus, int64(stored.Status))
	entry.setTime(attrIssuedAt, code.IssuedAt)
	// The brute-force counters are projected so they can be incremented
	// atomically. A transition preserves whatever the table holds; only
	// a Save (a fresh record, or one replacing an expired holder) writes
	// them, which is what resets them.
	entry.setN(attrUserCodeStrikes, int64(code.UserCodeStrikes))
	entry.setN(attrPollViolations, int64(code.PollViolations))
	return entry, nil
}

var _ store.DeviceCodeStore = (*deviceCodeStore)(nil)
