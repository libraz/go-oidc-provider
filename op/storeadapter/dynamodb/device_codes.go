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
// polls with (a bearer secret, so items are keyed on its digest) and
// the user_code the human reads aloud (canonicalised and carried on an
// index). Every state transition is a conditional update on the status
// attribute, so approve, deny, and consume cannot race each other into
// an inconsistent record.
type deviceCodeStore struct {
	parent *Store
}

func (s *deviceCodeStore) Save(ctx context.Context, code *store.DeviceCode) error {
	if code == nil {
		return errors.New("oidcdynamo: nil device code")
	}
	entry, err := deviceCodeItem(code)
	if err != nil {
		return err
	}
	// The user_code is unique among live records. DynamoDB cannot
	// enforce uniqueness on a secondary index, so the check is explicit:
	// an expired holder releases the code, a live one does not.
	if err := s.assertUserCodeFree(ctx, code.UserCode); err != nil {
		return err
	}
	placed, err := s.parent.putIfAbsent(ctx, s.parent.names.deviceCodes, entry)
	if err != nil {
		return wrapErr("deviceCodes.Save", err)
	}
	if placed {
		return nil
	}
	// The key is taken. A record that has expired no longer identifies
	// anything redeemable, so the fresh Save replaces it; a live one is
	// a genuine collision.
	if _, _, err := s.findLive(ctx, digestKey(code.ID)); errors.Is(err, store.ErrNotFound) {
		if err := s.parent.put(ctx, s.parent.names.deviceCodes, entry); err != nil {
			return wrapErr("deviceCodes.Save.replaceExpired", err)
		}
		return nil
	} else if err != nil {
		return err
	}
	return store.ErrAlreadyExists
}

// assertUserCodeFree reports [store.ErrAlreadyExists] when a live
// record already holds userCode. resolveUserCode already skips expired
// holders, so finding one at all is the collision.
func (s *deviceCodeStore) assertUserCodeFree(ctx context.Context, userCode string) error {
	if userCode == "" {
		return nil
	}
	_, err := s.resolveUserCode(ctx, userCode)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return store.ErrAlreadyExists
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
// record holding it.
//
// Two things make this more than an index lookup. The index is
// eventually consistent, so a candidate is confirmed against the item
// itself before any transition is issued against it. And an expired
// record releases its user code to a fresh request without being
// deleted — DynamoDB reclaims it asynchronously — so several items can
// legitimately carry the same code and only the live one counts.
func (s *deviceCodeStore) resolveUserCode(ctx context.Context, userCode string) (string, error) {
	if userCode == "" {
		return "", store.ErrNotFound
	}
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.deviceCodes, indexByUserCode, attrUserCode, userCode)
	if err != nil {
		return "", wrapErr("deviceCodes.FindByUserCode", err)
	}
	for _, match := range matches {
		pk := readS(match, attrPK)
		if pk == "" {
			continue
		}
		found, err := s.parent.get(ctx, s.parent.names.deviceCodes, pk)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return "", wrapErr("deviceCodes.FindByUserCode.reread", err)
		}
		if readS(found, attrUserCode) != userCode {
			continue
		}
		if s.parent.expired(found) {
			continue
		}
		return pk, nil
	}
	return "", store.ErrNotFound
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

func (s *deviceCodeStore) incrementStrike(ctx context.Context, pk string) (uint8, error) {
	var out uint8
	err := s.transition(ctx, pk, func(rec *store.DeviceCode) error {
		if rec.UserCodeStrikes < ^uint8(0) {
			rec.UserCodeStrikes++
		}
		out = rec.UserCodeStrikes
		return nil
	}, -1)
	return out, err
}

func (s *deviceCodeStore) IncrementPollViolation(ctx context.Context, deviceCode string) (uint8, error) {
	var out uint8
	err := s.transition(ctx, digestKey(deviceCode), func(rec *store.DeviceCode) error {
		if rec.PollViolations < ^uint8(0) {
			rec.PollViolations++
		}
		out = rec.PollViolations
		return nil
	}, -1)
	return out, err
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

	in := &dynamodb.PutItemInput{
		TableName: aws.String(s.parent.names.deviceCodes),
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
	return entry, nil
}

var _ store.DeviceCodeStore = (*deviceCodeStore)(nil)
