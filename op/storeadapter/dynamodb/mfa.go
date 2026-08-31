package oidcdynamo

import (
	"bytes"
	"context"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/op/store"
)

// The authentication-factor substores. They sit outside [store.Store]
// because the login flow receives them directly, and outside the
// transactional cluster because their writes are localised to one item
// and never need to be atomic with token issuance.
//
// Their compare-and-swap contracts use the backend-issued generation stored
// beside the opaque document. The public records deliberately omit Version
// from JSON; DynamoDB therefore projects it into attrRecordVersion so a
// stale snapshot can be rejected without exposing the token in the document.

// stampConsumedAt resolves the ConsumedAt a redemption writes onto a
// single-use record. A value the caller already carried is kept — it is
// the OP's own clock reading for the verification that just succeeded —
// and a zero is stamped from the adapter's clock instead.
//
// Both [store.EmailOTPStore.Consume] and [store.RecoveryStore.Consume]
// state the same post-condition: a nil return leaves the stored record
// with a non-zero ConsumedAt, whether or not the caller presented one.
// Writing the presented value through breaks it, because every one of
// these redemptions is guarded on the record still being unconsumed:
// the write then stores the value the guard requires the record to
// already hold, so the redemption reports success and the code stays
// redeemable for whoever reads it next.
func stampConsumedAt(presented, now time.Time) time.Time {
	if !presented.IsZero() {
		return presented
	}
	return now
}

// totpStore is the SQL-free RFC 6238 enrolment table.
type totpStore struct {
	parent *Store
}

func (s *totpStore) Get(ctx context.Context, subject string) (*store.TOTPRecord, error) {
	found, err := s.parent.get(ctx, s.parent.names.totpSecrets, subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("totp.Get", err)
	}
	var rec store.TOTPRecord
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	version, err := mfaVersionFromItem(found)
	if err != nil {
		return nil, err
	}
	rec.Version = version
	return &rec, nil
}

func (s *totpStore) Put(ctx context.Context, r *store.TOTPRecord) error {
	if r == nil {
		return errors.New("oidcdynamo: nil totp record")
	}
	if r.Subject == "" {
		return errors.New("oidcdynamo: totp record missing Subject")
	}
	if err := s.parent.putMFAVersioned(ctx, s.parent.names.totpSecrets, r.Subject, func(version uint64) (item, error) {
		stored := *r
		stored.Version = version
		return totpItem(&stored)
	}, nil); err != nil {
		return wrapErr("totp.Put", err)
	}
	return nil
}

func (s *totpStore) CompareAndSwap(ctx context.Context, previous, next *store.TOTPRecord) error {
	if previous == nil || next == nil || previous.Subject == "" || next.Subject != previous.Subject {
		return errors.New("oidcdynamo: invalid totp compare-and-swap record")
	}
	if next.Version != previous.Version || !validMFARecordVersion(previous.Version) {
		return store.ErrAlreadyConsumed
	}
	version, err := newMFARecordVersion(previous.Version)
	if err != nil {
		return err
	}
	stored := *next
	stored.Version = version
	entry, err := totpItem(&stored)
	if err != nil {
		return err
	}
	expectedDoc, err := marshalDoc(previous)
	if err != nil {
		return err
	}
	err = s.parent.putMFAIfVersion(ctx, s.parent.names.totpSecrets, entry, previous.Version, expectedDoc)
	if errors.Is(err, store.ErrConflict) {
		return store.ErrAlreadyConsumed
	}
	if err != nil {
		return wrapErr("totp.CompareAndSwap", err)
	}
	return nil
}

// Accept is the single-use success transition: it lands only when the
// stored step is strictly behind the one being redeemed, so replaying a
// code inside the same 30-second window cannot redeem twice.
//
//nolint:gocognit,cyclop // Each predicate maps to a distinct single-use or stale-snapshot failure outcome.
func (s *totpStore) Accept(ctx context.Context, r *store.TOTPRecord) error {
	if r == nil {
		return errors.New("oidcdynamo: nil totp record")
	}
	if r.LastAcceptedStep == 0 {
		return store.ErrAlreadyConsumed
	}
	if !validMFARecordVersion(r.Version) {
		return store.ErrAlreadyConsumed
	}
	current, err := s.Get(ctx, r.Subject)
	if err != nil {
		return err
	}
	// The generation CAS below makes this read/validate/write sequence
	// atomic. Reading the identity from the document also keeps Accept
	// compatible with legacy rows, which predate the projected secret and
	// confirmation attributes added for this predicate.
	if current.Version != r.Version ||
		!bytes.Equal(current.SecretCiphertext, r.SecretCiphertext) ||
		!current.ConfirmedAt.Equal(r.ConfirmedAt) ||
		current.LastAcceptedStep >= r.LastAcceptedStep {
		return store.ErrAlreadyConsumed
	}
	version, err := newMFARecordVersion(r.Version)
	if err != nil {
		return err
	}
	expectedVersion, err := mfaVersionValue(r.Version)
	if err != nil {
		return err
	}
	stored := *r
	stored.Version = version
	entry, err := totpItem(&stored)
	if err != nil {
		return err
	}
	expectedDoc, err := marshalDoc(current)
	if err != nil {
		return err
	}
	_, err = s.parent.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.parent.names.totpSecrets),
		Item:                entry,
		ConditionExpression: aws.String("attribute_exists(#pk) AND " + mfaVersionCondition(r.Version) + " AND #step < :step AND #doc = :expected_doc"),
		ExpressionAttributeNames: map[string]string{
			"#pk":      attrPK,
			"#version": attrRecordVersion,
			"#step":    attrTOTPStep,
			"#doc":     attrDoc,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":version":      expectedVersion,
			":step":         avN(r.LastAcceptedStep),
			":expected_doc": expectedDoc,
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			if _, getErr := s.Get(ctx, r.Subject); errors.Is(getErr, store.ErrNotFound) {
				return store.ErrNotFound
			}
			return store.ErrAlreadyConsumed
		}
		return wrapErr("totp.Accept", err)
	}
	return nil
}

func (s *totpStore) Delete(ctx context.Context, subject string) error {
	existed, err := s.parent.deleteKey(ctx, s.parent.names.totpSecrets, subject)
	if err != nil {
		return wrapErr("totp.Delete", err)
	}
	if !existed {
		return store.ErrNotFound
	}
	return nil
}

func totpItem(r *store.TOTPRecord) (item, error) {
	entry, err := newItem(r.Subject).doc(r)
	if err != nil {
		return nil, err
	}
	entry.setN(attrTOTPStep, r.LastAcceptedStep)
	entry[attrTOTPSecret] = avB(r.SecretCiphertext)
	entry[attrTOTPConfirmedAt] = avTime(r.ConfirmedAt)
	version, err := mfaVersionValue(r.Version)
	if err != nil {
		return nil, err
	}
	entry[attrRecordVersion] = version
	return entry, nil
}

// emailOTPStore is the pending email-OTP challenge table.
//
// Retention deserves the same care it gets in the SQL adapter: the item
// stays readable until RetainUntil, not until the code's ExpiresAt.
// Dropping it when the code dies would reset the resend cap and the
// brute-force counter, so pacing sends to the code TTL would never
// accumulate either.
type emailOTPStore struct {
	parent *Store
}

func (s *emailOTPStore) Get(ctx context.Context, subject string) (*store.EmailOTPRecord, error) {
	rec, err := s.load(ctx, subject)
	if err != nil {
		return nil, err
	}
	if emailOTPRetentionElapsed(rec, s.parent.now()) {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

func (s *emailOTPStore) load(ctx context.Context, subject string) (*store.EmailOTPRecord, error) {
	found, err := s.parent.get(ctx, s.parent.names.emailOTPs, subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("emailOTP.Get", err)
	}
	var rec store.EmailOTPRecord
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	version, err := mfaVersionFromItem(found)
	if err != nil {
		return nil, err
	}
	rec.Version = version
	return &rec, nil
}

func (s *emailOTPStore) Put(ctx context.Context, r *store.EmailOTPRecord) error {
	if r == nil {
		return errors.New("oidcdynamo: nil email otp record")
	}
	if r.Subject == "" {
		return errors.New("oidcdynamo: email otp record missing Subject")
	}
	if err := s.parent.putMFAVersioned(ctx, s.parent.names.emailOTPs, r.Subject, func(version uint64) (item, error) {
		stored := *r
		stored.Version = version
		return emailOTPItem(&stored)
	}, nil); err != nil {
		return wrapErr("emailOTP.Put", err)
	}
	return nil
}

func (s *emailOTPStore) CompareAndSwap(ctx context.Context, previous, next *store.EmailOTPRecord) error {
	if next == nil || next.Subject == "" {
		return errors.New("oidcdynamo: invalid email otp compare-and-swap record")
	}
	if previous == nil {
		return s.createIfAbsent(ctx, next)
	}
	if previous.Subject != next.Subject {
		return errors.New("oidcdynamo: invalid email otp compare-and-swap record")
	}
	if next.Version != previous.Version || !validMFARecordVersion(previous.Version) {
		return store.ErrAlreadyConsumed
	}
	version, err := newMFARecordVersion(previous.Version)
	if err != nil {
		return err
	}
	stored := *next
	stored.Version = version
	entry, err := emailOTPItem(&stored)
	if err != nil {
		return err
	}
	expectedDoc, err := marshalDoc(previous)
	if err != nil {
		return err
	}
	err = s.parent.putMFAIfVersion(ctx, s.parent.names.emailOTPs, entry, previous.Version, expectedDoc)
	if errors.Is(err, store.ErrConflict) {
		return store.ErrAlreadyConsumed
	}
	if err != nil {
		return wrapErr("emailOTP.CompareAndSwap", err)
	}
	return nil
}

// createIfAbsent handles the nil-previous form, which reserves the
// first challenge for a subject. A record that is still retained means
// another send won the race.
//
// The reservation is what caps how many messages a subject can be sent,
// so the write carries the free-key condition rather than following a
// read: two first sends arriving together would otherwise both find the
// key empty and both deliver a code, rolling the send-count ceiling
// back to one. [emailOTPItem] projects the retention horizon onto the
// expiry attribute the condition reads, so a retained challenge holds
// the key and a lapsed one does not.
func (s *emailOTPStore) createIfAbsent(ctx context.Context, next *store.EmailOTPRecord) error {
	err := s.parent.putMFAVersioned(ctx, s.parent.names.emailOTPs, next.Subject, func(version uint64) (item, error) {
		stored := *next
		stored.Version = version
		return emailOTPItem(&stored)
	}, func(found item) (bool, error) {
		var current store.EmailOTPRecord
		if err := unmarshalDoc(found, &current); err != nil {
			return false, err
		}
		return emailOTPRetentionElapsed(&current, s.parent.now()), nil
	})
	if errors.Is(err, store.ErrAlreadyConsumed) {
		return err
	}
	if err != nil {
		return wrapErr("emailOTP.CompareAndSwap.create", err)
	}
	return nil
}

// Consume stamps the redemption. The condition asserts the challenge is
// still unconsumed and still carries the code material the caller
// verified, so a stale success cannot redeem the challenge that
// replaced it.
//
// The stamp itself is resolved by [stampConsumedAt] rather than copied
// from the caller: a challenge written back unstamped still reads as
// pending, and the generation the write advances does not keep the next
// reader from redeeming it again with the generation it just read.
func (s *emailOTPStore) Consume(ctx context.Context, r *store.EmailOTPRecord) error {
	if r == nil {
		return errors.New("oidcdynamo: nil email otp record")
	}
	if !validMFARecordVersion(r.Version) {
		return store.ErrAlreadyConsumed
	}
	current, err := s.load(ctx, r.Subject)
	if err != nil {
		return err
	}
	now := s.parent.now()
	if !current.ExpiresAt.IsZero() && current.ExpiresAt.Before(now) {
		return store.ErrNotFound
	}
	if !current.ConsumedAt.IsZero() {
		return store.ErrAlreadyConsumed
	}
	if current.Version != r.Version {
		return store.ErrAlreadyConsumed
	}
	if !bytes.Equal(current.CodeSalt, r.CodeSalt) || !bytes.Equal(current.CodeHash, r.CodeHash) {
		return store.ErrAlreadyConsumed
	}

	version, err := newMFARecordVersion(r.Version)
	if err != nil {
		return err
	}
	stored := *r
	stored.Version = version
	stored.ConsumedAt = stampConsumedAt(r.ConsumedAt, now)
	entry, err := emailOTPItem(&stored)
	if err != nil {
		return err
	}
	expectedDoc, err := marshalDoc(current)
	if err != nil {
		return err
	}
	err = s.parent.putMFAIfVersion(ctx, s.parent.names.emailOTPs, entry, r.Version, expectedDoc)
	if errors.Is(err, store.ErrConflict) {
		return store.ErrAlreadyConsumed
	}
	if err != nil {
		return wrapErr("emailOTP.Consume", err)
	}
	return nil
}

func (s *emailOTPStore) Delete(ctx context.Context, subject string) error {
	existed, err := s.parent.deleteKey(ctx, s.parent.names.emailOTPs, subject)
	if err != nil {
		return wrapErr("emailOTP.Delete", err)
	}
	if !existed {
		return store.ErrNotFound
	}
	return nil
}

func emailOTPItem(r *store.EmailOTPRecord) (item, error) {
	entry, err := newItem(r.Subject).doc(r)
	if err != nil {
		return nil, err
	}
	// The TTL tracks retention, not the code's own expiry: the counters
	// have to outlive the code they were accumulated against.
	horizon := r.RetainUntil
	if horizon.IsZero() {
		horizon = r.ExpiresAt
	}
	entry.expires(horizon)
	version, err := mfaVersionValue(r.Version)
	if err != nil {
		return nil, err
	}
	entry[attrRecordVersion] = version
	return entry, nil
}

func emailOTPRetentionElapsed(rec *store.EmailOTPRecord, now time.Time) bool {
	horizon := rec.RetainUntil
	if horizon.IsZero() {
		horizon = rec.ExpiresAt
	}
	return !horizon.IsZero() && horizon.Before(now)
}

const mfaPutAttempts = 8

// mfaVersionFromItem reads the independent opaque token attribute. Items
// written before Version was public have no projection and are exposed as
// token one solely for the one-time legacy transition predicate. A stored
// signed maximum remains readable for diagnostics but is rejected by
// conditional caller-snapshot transitions; an explicit Put may replace it
// with a fresh token.
func mfaVersionFromItem(found item) (uint64, error) {
	value, ok := found[attrRecordVersion]
	if !ok {
		return 1, nil
	}
	number, ok := value.(*types.AttributeValueMemberN)
	if !ok {
		return 0, errors.New("oidcdynamo: invalid MFA record version attribute")
	}
	parsed, err := parseInt(number.Value)
	if err != nil {
		return 0, err
	}
	if parsed < 1 {
		return 0, errors.New("oidcdynamo: invalid MFA record version")
	}
	return uint64(parsed), nil
}

const maxMFARecordVersion = ^uint64(0) >> 1

func validMFARecordVersion(version uint64) bool {
	return version > 0 && version < maxMFARecordVersion
}

// newMFARecordVersion generates an opaque signed-63-bit token. A transition
// excludes its prior token so a stale snapshot cannot accidentally pass the
// generation predicate after a replacement. Random generation is deliberate:
// DynamoDB rows may be physically deleted and recreated, so arithmetic
// versions would make a fresh row look like an old snapshot.
func newMFARecordVersion(excluded ...uint64) (uint64, error) {
	var excludedToken uint64
	if len(excluded) > 0 {
		excludedToken = excluded[0]
	}
	return keys.RandomUint63Except(excludedToken)
}

//nolint:ireturn // types.AttributeValue is the DynamoDB SDK's own sum type.
func mfaVersionValue(version uint64) (types.AttributeValue, error) {
	// This encoder accepts the signed maximum so an explicit Put can match
	// and heal a terminal stored row. Caller-snapshot transitions gate through
	// validMFARecordVersion before reaching this representation helper.
	if version == 0 || version > maxMFARecordVersion {
		return nil, errors.New("oidcdynamo: invalid MFA record version")
	}
	return avN(int64(version)), nil
}

// mfaVersionCondition returns the version predicate used by all successful
// state transitions. A missing projection is accepted only for generation
// one, which is the migration path for legacy rows; every newer generation
// must carry the exact attribute value.
func mfaVersionCondition(expected uint64) string {
	if expected == 1 {
		return "(attribute_not_exists(#version) OR #version = :version)"
	}
	return "#version = :version"
}

// putMFAIfVersion replaces an existing factor row only when its old opaque
// token and document still equal the caller's snapshot. The item already
// contains a newly allocated token.
func (s *Store) putMFAIfVersion(
	ctx context.Context,
	table string,
	entry item,
	expected uint64,
	expectedDoc types.AttributeValue,
) error {
	if expectedDoc == nil {
		return errors.New("oidcdynamo: missing expected MFA document")
	}
	version, err := mfaVersionValue(expected)
	if err != nil {
		return err
	}
	_, err = s.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(table),
		Item:                entry,
		ConditionExpression: aws.String("attribute_exists(#pk) AND " + mfaVersionCondition(expected) + " AND #doc = :expected_doc"),
		ExpressionAttributeNames: map[string]string{
			"#pk":      attrPK,
			"#version": attrRecordVersion,
			"#doc":     attrDoc,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":version":      version,
			":expected_doc": expectedDoc,
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

// putMFAVersioned assigns a fresh token to a Put. Existing records are
// replaced under a version-plus-document predicate, so a concurrent Put or
// delete/recreate cannot reuse an old snapshot. canReplace is used by EmailOTP's nil-
// previous reservation to admit only rows past their retention horizon.
//
//nolint:gocognit,cyclop // The bounded retry keeps allocation, conditional write, and conflict handling in their required order.
func (s *Store) putMFAVersioned(
	ctx context.Context,
	table, subject string,
	build func(uint64) (item, error),
	canReplace func(item) (bool, error),
) error {
	for range mfaPutAttempts {
		found, err := s.get(ctx, table, subject)
		exists := err == nil
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		currentVersion := uint64(0)
		if exists {
			if canReplace != nil {
				allowed, checkErr := canReplace(found)
				if checkErr != nil {
					return checkErr
				}
				if !allowed {
					return store.ErrAlreadyConsumed
				}
			}
			currentVersion, err = mfaVersionFromItem(found)
			if err != nil {
				return err
			}
		}
		nextVersion, err := newMFARecordVersion(currentVersion)
		if err != nil {
			return err
		}
		entry, err := build(nextVersion)
		if err != nil {
			return err
		}
		if exists {
			err = s.putMFAIfVersion(ctx, table, entry, currentVersion, found[attrDoc])
		} else {
			_, err = s.api.PutItem(ctx, &dynamodb.PutItemInput{
				TableName:           aws.String(table),
				Item:                entry,
				ConditionExpression: aws.String("attribute_not_exists(#pk)"),
				ExpressionAttributeNames: map[string]string{
					"#pk": attrPK,
				},
			})
			if err != nil && isConditionalCheckFailed(err) {
				err = store.ErrConflict
			}
		}
		if err == nil {
			return nil
		}
		if !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return store.ErrConflict
}

// recoveryStore holds recovery-code batches as one item per slot, keyed
// (subject, slot_index). Redeeming a code is then a conditional update
// against that one item: two concurrent redemptions of the same code
// cannot both win, and redeeming a different slot is not forced to lose
// the race.
type recoveryStore struct {
	parent *Store
}

func (s *recoveryStore) Get(ctx context.Context, subject string) (*store.RecoveryBatch, error) {
	slots, err := s.parent.queryPartition(ctx, s.parent.names.recoveryCodes, subject)
	if err != nil {
		return nil, wrapErr("recovery.Get", err)
	}
	if len(slots) == 0 {
		return nil, store.ErrNotFound
	}
	batch := &store.RecoveryBatch{Subject: subject}
	for _, slot := range slots {
		batch.GeneratedAt = readTime(slot, attrIssuedAt)
		batch.Codes = append(batch.Codes, store.RecoveryCode{
			Hash:       readS(slot, attrCodeHash),
			ConsumedAt: readTime(slot, attrConsumedAt),
		})
	}
	return batch, nil
}

// Put replaces the batch wholesale. The delete and the re-insert go out
// as one transaction so a regeneration cannot leave a partially
// replaced slot list behind — a reader that observed one could redeem a
// code the user believes they revoked.
func (s *recoveryStore) Put(ctx context.Context, b *store.RecoveryBatch) error {
	if b == nil {
		return errors.New("oidcdynamo: nil recovery batch")
	}
	if b.Subject == "" {
		return errors.New("oidcdynamo: recovery batch missing Subject")
	}
	existing, err := s.parent.queryPartition(ctx, s.parent.names.recoveryCodes, b.Subject)
	if err != nil {
		return wrapErr("recovery.Put.read", err)
	}

	var actions []types.TransactWriteItem
	for _, slot := range existing {
		// The key comes from the slot's own index rather than from a loop
		// position: a partition left with a gap by an older adapter would
		// otherwise keep the slots this batch does not overwrite, and the
		// user would still be able to redeem a code the regeneration was
		// meant to revoke. Deriving the key from the item repairs such a
		// partition as a side effect of the next regeneration.
		if index := readN(slot, attrSlotIndex); index >= int64(len(b.Codes)) {
			actions = append(actions, types.TransactWriteItem{Delete: &types.Delete{
				TableName: aws.String(s.parent.names.recoveryCodes),
				Key:       recoverySlotKey(b.Subject, int(index)),
			}})
		}
	}
	for i, code := range b.Codes {
		entry := newCompositeItem(b.Subject, attrSlotIndex, avN(int64(i)))
		entry[attrCodeHash] = avS(code.Hash)
		entry.setTime(attrConsumedAt, code.ConsumedAt)
		entry.setTime(attrIssuedAt, b.GeneratedAt)
		actions = append(actions, types.TransactWriteItem{Put: &types.Put{
			TableName: aws.String(s.parent.names.recoveryCodes),
			Item:      entry,
		}})
	}
	if len(actions) == 0 {
		return nil
	}
	if len(actions) > maxTransactionItems {
		return ErrTransactionTooLarge
	}
	if _, err := s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: actions,
	}); err != nil {
		return wrapErr("recovery.Put", err)
	}
	return nil
}

func (s *recoveryStore) Consume(ctx context.Context, b *store.RecoveryBatch, index int) error {
	if b == nil {
		return errors.New("oidcdynamo: nil recovery batch")
	}
	if index < 0 || index >= len(b.Codes) {
		return store.ErrNotFound
	}
	slot := b.Codes[index]
	_, err := s.parent.api.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.parent.names.recoveryCodes),
		Key:       recoverySlotKey(b.Subject, index),
		// The stamp is resolved here rather than copied from the caller:
		// the predicate below requires the slot to be unconsumed, so
		// writing a zero back would set the attribute to the value it
		// already holds, and the redemption would report success while
		// leaving the code redeemable.
		UpdateExpression: aws.String("SET #consumed = :now"),
		// The hash predicate is what makes regenerating a batch revoke
		// the codes it replaced: a slot whose hash has moved on refuses
		// the redemption rather than burning a fresh slot.
		ConditionExpression: aws.String("attribute_exists(#pk) AND #hash = :hash AND #consumed = :zero"),
		ExpressionAttributeNames: map[string]string{
			"#pk":       attrPK,
			"#hash":     attrCodeHash,
			"#consumed": attrConsumedAt,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":hash": avS(slot.Hash),
			":now":  avTime(stampConsumedAt(slot.ConsumedAt, s.parent.now())),
			":zero": avN(0),
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return s.explainRejectedConsume(ctx, b.Subject, index)
		}
		return wrapErr("recovery.Consume", err)
	}
	return nil
}

func (s *recoveryStore) explainRejectedConsume(ctx context.Context, subject string, index int) error {
	current, err := s.Get(ctx, subject)
	if errors.Is(err, store.ErrNotFound) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	if index >= len(current.Codes) {
		return store.ErrNotFound
	}
	return store.ErrAlreadyConsumed
}

// Delete removes the whole batch in one transaction, the same shape
// [recoveryStore.Put] takes. A per-slot loop would let a failure part-way
// through leave the remaining slots behind: Get would keep reporting a
// live batch, the account UI would keep showing recovery codes as
// enabled, and the codes in those slots would stay redeemable. Each key
// comes from the slot's own index rather than from the loop position, so
// a retry against a partition an older adapter left with a gap still
// removes every slot instead of deleting keys that do not exist.
func (s *recoveryStore) Delete(ctx context.Context, subject string) error {
	slots, err := s.parent.queryPartition(ctx, s.parent.names.recoveryCodes, subject)
	if err != nil {
		return wrapErr("recovery.Delete.read", err)
	}
	if len(slots) == 0 {
		return store.ErrNotFound
	}
	if len(slots) > maxTransactionItems {
		return ErrTransactionTooLarge
	}
	actions := make([]types.TransactWriteItem, 0, len(slots))
	for _, slot := range slots {
		actions = append(actions, types.TransactWriteItem{Delete: &types.Delete{
			TableName: aws.String(s.parent.names.recoveryCodes),
			Key:       recoverySlotKey(subject, int(readN(slot, attrSlotIndex))),
		}})
	}
	if _, err := s.parent.api.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: actions,
	}); err != nil {
		return wrapErr("recovery.Delete", err)
	}
	return nil
}

func recoverySlotKey(subject string, index int) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		attrPK:        avS(subject),
		attrSlotIndex: avN(int64(index)),
	}
}

// passkeyStore holds registered WebAuthn credentials.
type passkeyStore struct {
	parent *Store
}

func (s *passkeyStore) Get(ctx context.Context, credentialID []byte) (*store.PasskeyRecord, error) {
	found, err := s.parent.get(ctx, s.parent.names.passkeys, credentialKey(credentialID))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("passkeys.Get", err)
	}
	return decodePasskey(found)
}

func (s *passkeyStore) ListBySubject(ctx context.Context, subject string) ([]*store.PasskeyRecord, error) {
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.passkeys, indexBySubject, attrSubject, subject,
	)
	if err != nil {
		return nil, wrapErr("passkeys.ListBySubject", err)
	}
	// A subject with no passkeys yields an empty, non-nil slice: the
	// interface forbids reporting "none registered" as ErrNotFound.
	out := make([]*store.PasskeyRecord, 0, len(matches))
	for _, match := range matches {
		rec, err := decodePasskey(match)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	slices.SortFunc(out, func(a, b *store.PasskeyRecord) int {
		if a.CreatedAt.Equal(b.CreatedAt) {
			return bytes.Compare(a.CredentialID, b.CredentialID)
		}
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		}
		return 1
	})
	return out, nil
}

// Put upserts the credential record under a condition that admits only
// a first registration or a rewrite by the subject that already holds
// the credential. Reading the owner first and writing afterwards would
// leave a window in which a concurrent registration moves the record to
// another subject; the condition closes it inside the write itself.
func (s *passkeyStore) Put(ctx context.Context, r *store.PasskeyRecord) error {
	if r == nil {
		return errors.New("oidcdynamo: nil passkey record")
	}
	if len(r.CredentialID) == 0 {
		return errors.New("oidcdynamo: passkey record missing CredentialID")
	}
	entry, err := passkeyItem(r)
	if err != nil {
		return err
	}
	if _, err := s.parent.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.parent.names.passkeys),
		Item:                entry,
		ConditionExpression: aws.String("attribute_not_exists(#pk) OR #subject = :subject"),
		ExpressionAttributeNames: map[string]string{
			"#pk":      attrPK,
			"#subject": attrSubject,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":subject": avS(r.Subject),
		},
	}); err != nil {
		if isConditionalCheckFailed(err) {
			// The credential belongs to somebody else. Replacing it
			// here would unlink their authenticator.
			return store.ErrAlreadyExists
		}
		return wrapErr("passkeys.Put", err)
	}
	return nil
}

// UpdateAssertion applies one verified assertion. The read, the
// monotonicity comparison, and the write have to be one atomic
// operation, which here is a read followed by a write conditioned on
// the record not having moved: a concurrent assertion makes this one
// retry its comparison rather than rewinding the sign counter.
func (s *passkeyStore) UpdateAssertion(
	ctx context.Context,
	credentialID []byte,
	update store.PasskeyAssertionUpdate,
) (*store.PasskeyRecord, error) {
	pk := credentialKey(credentialID)
	for range passkeyUpdateAttempts {
		next, err := s.tryAssertionSwap(ctx, pk, update)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return next, nil
	}
	return nil, store.ErrConflict
}

// tryAssertionSwap performs one read-compare-write cycle, reporting
// [store.ErrConflict] when the record moved underneath it.
func (s *passkeyStore) tryAssertionSwap(
	ctx context.Context,
	pk string,
	update store.PasskeyAssertionUpdate,
) (*store.PasskeyRecord, error) {
	found, err := s.parent.get(ctx, s.parent.names.passkeys, pk)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("passkeys.UpdateAssertion", err)
	}
	current, err := decodePasskey(found)
	if err != nil {
		return nil, err
	}
	next := applyAssertion(*current, update)
	entry, err := passkeyItem(&next)
	if err != nil {
		return nil, err
	}
	expected, err := marshalDoc(current)
	if err != nil {
		return nil, err
	}
	if err := s.parent.putIfDocMatches(ctx, s.parent.names.passkeys, entry, expected); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, store.ErrConflict
		}
		return nil, wrapErr("passkeys.UpdateAssertion", err)
	}
	return &next, nil
}

// passkeyUpdateAttempts bounds the compare-and-swap retry. Contention
// on one credential is a user tapping twice, not a hot key, so a small
// bound is enough and an unbounded loop would only hide a real problem.
const passkeyUpdateAttempts = 5

// applyAssertion implements the monotonicity rules [store.PasskeyStore]
// declares: the sign counter never moves backwards, the clone warning
// is sticky once raised, and a counterless authenticator (all three
// counters zero) still refreshes the ceremony flags.
func applyAssertion(rec store.PasskeyRecord, update store.PasskeyAssertionUpdate) store.PasskeyRecord {
	counterless := rec.SignCount == 0 && update.ExpectedSignCount == 0 && update.SignCount == 0
	if update.SignCount > rec.SignCount || counterless {
		rec.SignCount = update.SignCount
		rec.UserPresent = update.UserPresent
		rec.UserVerified = update.UserVerified
		rec.BackupState = update.BackupState
	}
	rec.CloneWarning = rec.CloneWarning || update.CloneWarning
	return rec
}

func (s *passkeyStore) Delete(ctx context.Context, credentialID []byte) error {
	existed, err := s.parent.deleteKey(ctx, s.parent.names.passkeys, credentialKey(credentialID))
	if err != nil {
		return wrapErr("passkeys.Delete", err)
	}
	if !existed {
		return store.ErrNotFound
	}
	return nil
}

func passkeyItem(r *store.PasskeyRecord) (item, error) {
	entry, err := newItem(credentialKey(r.CredentialID)).doc(r)
	if err != nil {
		return nil, err
	}
	entry.set(attrSubject, r.Subject)
	return entry, nil
}

func decodePasskey(found item) (*store.PasskeyRecord, error) {
	var rec store.PasskeyRecord
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// credentialKey renders a binary credential id as the table's string
// partition key. WebAuthn credential ids are opaque bytes; hex keeps
// them inside the key attribute's character constraints without
// changing what they identify.
func credentialKey(credentialID []byte) string {
	return hexEncode(credentialID)
}

// authnLockoutStore is the cross-factor brute-force counter. It is the
// one factor substore whose record carries a version, so its
// compare-and-swap is a version guard rather than a whole-document
// comparison.
type authnLockoutStore struct {
	parent *Store
}

func (s *authnLockoutStore) Get(ctx context.Context, subject string) (*store.AuthnLockoutRecord, error) {
	found, err := s.parent.get(ctx, s.parent.names.authnLockouts, subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("authnLockouts.Get", err)
	}
	var rec store.AuthnLockoutRecord
	if err := unmarshalDoc(found, &rec); err != nil {
		return nil, err
	}
	rec.Version = uint64(readN(found, attrRecordVersion)) //nolint:gosec // the attribute only holds values this adapter wrote, from 1 upwards.
	return &rec, nil
}

// CompareAndSwap implements [store.AuthnLockoutStore]. expectedVersion
// zero means "create": it succeeds only when no record exists yet, so
// two racing first failures cannot both install a fresh counter.
func (s *authnLockoutStore) CompareAndSwap(
	ctx context.Context,
	expectedVersion uint64,
	next *store.AuthnLockoutRecord,
) (bool, error) {
	if next == nil {
		return false, errors.New("oidcdynamo: nil authn lockout record")
	}
	if next.Subject == "" {
		return false, errors.New("oidcdynamo: authn lockout record missing Subject")
	}
	if expectedVersion == math.MaxUint64 {
		return false, errors.New("oidcdynamo: authn lockout version overflow")
	}
	nextVersion := expectedVersion + 1

	stored := *next
	stored.Version = nextVersion
	entry, err := newItem(next.Subject).doc(&stored)
	if err != nil {
		return false, err
	}
	entry.setN(attrRecordVersion, int64(nextVersion)) //nolint:gosec // bounded by the MaxUint64 guard above.

	in := &dynamodb.PutItemInput{
		TableName: aws.String(s.parent.names.authnLockouts),
		Item:      entry,
	}
	if expectedVersion == 0 {
		in.ConditionExpression = aws.String("attribute_not_exists(#pk)")
		in.ExpressionAttributeNames = map[string]string{"#pk": attrPK}
	} else {
		in.ConditionExpression = aws.String("attribute_exists(#pk) AND #ver = :expected")
		in.ExpressionAttributeNames = map[string]string{"#pk": attrPK, "#ver": attrRecordVersion}
		in.ExpressionAttributeValues = map[string]types.AttributeValue{
			":expected": avN(int64(expectedVersion)), //nolint:gosec // versions originate from this adapter's own attribute.
		}
	}

	if _, err := s.parent.api.PutItem(ctx, in); err != nil {
		if isConditionalCheckFailed(err) {
			return false, nil
		}
		return false, wrapErr("authnLockouts.CompareAndSwap", err)
	}
	return true, nil
}

// putIfDocMatches writes entry only when the stored document still equals
// expected. Passkey assertions retain whole-document CAS because their
// record has not adopted the MFA generation token.
func (s *Store) putIfDocMatches(
	ctx context.Context,
	table string,
	entry item,
	expected types.AttributeValue,
) error {
	_, err := s.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(table),
		Item:                entry,
		ConditionExpression: aws.String("attribute_exists(#pk) AND #doc = :expected"),
		ExpressionAttributeNames: map[string]string{
			"#pk":  attrPK,
			"#doc": attrDoc,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":expected": expected,
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return store.ErrConflict
		}
		return err
	}
	return nil
}

var (
	_ store.TOTPStore         = (*totpStore)(nil)
	_ store.EmailOTPStore     = (*emailOTPStore)(nil)
	_ store.RecoveryStore     = (*recoveryStore)(nil)
	_ store.PasskeyStore      = (*passkeyStore)(nil)
	_ store.AuthnLockoutStore = (*authnLockoutStore)(nil)
)
