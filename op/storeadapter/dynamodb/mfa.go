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

	"github.com/libraz/go-oidc-provider/op/store"
)

// The authentication-factor substores. They sit outside [store.Store]
// because the login flow receives them directly, and outside the
// transactional cluster because their writes are localised to one item
// and never need to be atomic with token issuance.
//
// Their compare-and-swap contracts match on the whole stored record
// rather than on a version counter, because the record types carry no
// version. On DynamoDB that is a condition expression over the document
// attribute: the document is a deterministic JSON encoding of the same
// struct, so comparing it is exactly comparing every field.

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
	return &rec, nil
}

func (s *totpStore) Put(ctx context.Context, r *store.TOTPRecord) error {
	if r == nil {
		return errors.New("oidcdynamo: nil totp record")
	}
	if r.Subject == "" {
		return errors.New("oidcdynamo: totp record missing Subject")
	}
	entry, err := totpItem(r)
	if err != nil {
		return err
	}
	if err := s.parent.put(ctx, s.parent.names.totpSecrets, entry); err != nil {
		return wrapErr("totp.Put", err)
	}
	return nil
}

func (s *totpStore) CompareAndSwap(ctx context.Context, previous, next *store.TOTPRecord) error {
	if previous == nil || next == nil || previous.Subject == "" || next.Subject != previous.Subject {
		return errors.New("oidcdynamo: invalid totp compare-and-swap record")
	}
	entry, err := totpItem(next)
	if err != nil {
		return err
	}
	expected, err := marshalDoc(previous)
	if err != nil {
		return err
	}
	err = s.parent.putIfDocMatches(ctx, s.parent.names.totpSecrets, entry, expected)
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
func (s *totpStore) Accept(ctx context.Context, r *store.TOTPRecord) error {
	if r == nil {
		return errors.New("oidcdynamo: nil totp record")
	}
	if r.LastAcceptedStep == 0 {
		return store.ErrAlreadyConsumed
	}
	entry, err := totpItem(r)
	if err != nil {
		return err
	}
	_, err = s.parent.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.parent.names.totpSecrets),
		Item:                entry,
		ConditionExpression: aws.String("attribute_exists(#pk) AND #step < :step"),
		ExpressionAttributeNames: map[string]string{
			"#pk":   attrPK,
			"#step": attrTOTPStep,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":step": avN(r.LastAcceptedStep),
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
	return &rec, nil
}

func (s *emailOTPStore) Put(ctx context.Context, r *store.EmailOTPRecord) error {
	if r == nil {
		return errors.New("oidcdynamo: nil email otp record")
	}
	if r.Subject == "" {
		return errors.New("oidcdynamo: email otp record missing Subject")
	}
	entry, err := emailOTPItem(r)
	if err != nil {
		return err
	}
	if err := s.parent.put(ctx, s.parent.names.emailOTPs, entry); err != nil {
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
	entry, err := emailOTPItem(next)
	if err != nil {
		return err
	}
	expected, err := marshalDoc(previous)
	if err != nil {
		return err
	}
	err = s.parent.putIfDocMatches(ctx, s.parent.names.emailOTPs, entry, expected)
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
func (s *emailOTPStore) createIfAbsent(ctx context.Context, next *store.EmailOTPRecord) error {
	current, err := s.load(ctx, next.Subject)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return err
	case !emailOTPRetentionElapsed(current, s.parent.now()):
		return store.ErrAlreadyConsumed
	}
	return s.Put(ctx, next)
}

// Consume stamps the redemption. The condition asserts the challenge is
// still unconsumed and still carries the code material the caller
// verified, so a stale success cannot redeem the challenge that
// replaced it.
func (s *emailOTPStore) Consume(ctx context.Context, r *store.EmailOTPRecord) error {
	if r == nil {
		return errors.New("oidcdynamo: nil email otp record")
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
	if !bytes.Equal(current.CodeSalt, r.CodeSalt) || !bytes.Equal(current.CodeHash, r.CodeHash) {
		return store.ErrAlreadyConsumed
	}

	entry, err := emailOTPItem(r)
	if err != nil {
		return err
	}
	expected, err := marshalDoc(current)
	if err != nil {
		return err
	}
	err = s.parent.putIfDocMatches(ctx, s.parent.names.emailOTPs, entry, expected)
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
	return entry, nil
}

func emailOTPRetentionElapsed(rec *store.EmailOTPRecord, now time.Time) bool {
	horizon := rec.RetainUntil
	if horizon.IsZero() {
		horizon = rec.ExpiresAt
	}
	return !horizon.IsZero() && horizon.Before(now)
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
	for i := len(b.Codes); i < len(existing); i++ {
		actions = append(actions, types.TransactWriteItem{Delete: &types.Delete{
			TableName: aws.String(s.parent.names.recoveryCodes),
			Key:       recoverySlotKey(b.Subject, i),
		}})
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
		TableName:        aws.String(s.parent.names.recoveryCodes),
		Key:              recoverySlotKey(b.Subject, index),
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
			":now":  avTime(slot.ConsumedAt),
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

func (s *recoveryStore) Delete(ctx context.Context, subject string) error {
	slots, err := s.parent.queryPartition(ctx, s.parent.names.recoveryCodes, subject)
	if err != nil {
		return wrapErr("recovery.Delete.read", err)
	}
	if len(slots) == 0 {
		return store.ErrNotFound
	}
	for i := range slots {
		if _, err := s.parent.api.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: aws.String(s.parent.names.recoveryCodes),
			Key:       recoverySlotKey(subject, i),
		}); err != nil {
			return wrapErr("recovery.Delete", err)
		}
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
		ctx, s.parent.names.passkeys, indexBySubject, attrSubject, subject)
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
	if err := s.parent.put(ctx, s.parent.names.passkeys, entry); err != nil {
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

// putIfDocMatches writes entry only when the stored document still
// equals expected. It is the whole-record compare-and-swap the factor
// substores need: their record types carry no version, so the document
// itself is the comparison.
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
