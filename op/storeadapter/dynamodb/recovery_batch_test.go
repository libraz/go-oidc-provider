//go:build testcontainers

package oidcdynamo_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// The recovery-code partition is keyed (subject, slot_index) and each
// slot carries its code hash. The names are spelled out here because a
// test that seeds the partition an older adapter left behind has to
// write it the way that adapter did, without going through the code
// under test.
const (
	slotIndexAttr = "slot_index"
	codeHashAttr  = "code_hash"
)

// errDeleteBudgetSpent is what the fault injector reports once a removal
// has been interrupted.
var errDeleteBudgetSpent = errors.New("oidcdynamo_test: injected delete failure")

// haltingDeleteAPI refuses deletes once its budget is spent, so a test
// can interrupt a batch removal part-way through and observe what the
// store is left holding.
//
// The budget is charged by single DeleteItem calls and by the individual
// Delete actions inside a transaction alike, which is what makes the two
// removal shapes comparable: a loop of single deletes is interrupted
// after the budget, while a transaction that would spend more than the
// budget is refused as a whole and writes nothing.
type haltingDeleteAPI struct {
	oidcdynamo.API

	// budget is the number of items that may still be deleted. A
	// negative value means unlimited.
	budget atomic.Int64
}

func (a *haltingDeleteAPI) spend(items int64) bool {
	if a.budget.Load() < 0 {
		return true
	}
	return a.budget.Add(-items) >= 0
}

func (a *haltingDeleteAPI) DeleteItem(
	ctx context.Context,
	in *awsdynamodb.DeleteItemInput,
	opts ...func(*awsdynamodb.Options),
) (*awsdynamodb.DeleteItemOutput, error) {
	if !a.spend(1) {
		return nil, errDeleteBudgetSpent
	}
	return a.API.DeleteItem(ctx, in, opts...)
}

func (a *haltingDeleteAPI) TransactWriteItems(
	ctx context.Context,
	in *awsdynamodb.TransactWriteItemsInput,
	opts ...func(*awsdynamodb.Options),
) (*awsdynamodb.TransactWriteItemsOutput, error) {
	deletes := int64(0)
	for _, action := range in.TransactItems {
		if action.Delete != nil {
			deletes++
		}
	}
	if deletes > 0 && !a.spend(deletes) {
		return nil, errDeleteBudgetSpent
	}
	return a.API.TransactWriteItems(ctx, in, opts...)
}

func newRecoveryBatch(subject string, codes int) *store.RecoveryBatch {
	b := &store.RecoveryBatch{Subject: subject, GeneratedAt: contract.Reference}
	for i := range codes {
		b.Codes = append(b.Codes, store.RecoveryCode{Hash: fmt.Sprintf("$argon2id$hash-%s-%d", subject, i)})
	}
	return b
}

// TestRecoveryCodes_DeleteIsAllOrNothing pins what disabling recovery
// codes owes the user. An interrupted removal that took some slots with
// it and reported an error would leave a batch the account UI still
// shows as enabled and whose surviving codes are still redeemable — the
// user believes the credentials are gone while they are not.
//
// The retry is the second half of it: the slots that survive an
// interruption are not the low ones, so a removal that derives its keys
// from a loop position deletes keys that were never there and reports
// success over a partition it did not empty.
func TestRecoveryCodes_DeleteIsAllOrNothing(t *testing.T) {
	t.Parallel()

	api := &haltingDeleteAPI{}
	api.budget.Store(-1)
	s, _ := newWrappedStore(t, "recdel_", func(inner oidcdynamo.API) oidcdynamo.API {
		api.API = inner
		return api
	})
	ctx := t.Context()
	codes := s.RecoveryCodes()

	const (
		subject = "sub-recovery-delete"
		slots   = 10
	)
	batch := newRecoveryBatch(subject, slots)
	if err := codes.Put(ctx, batch); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Interrupt the removal after two slots. A loop deletes those two and
	// stops; a transaction is refused whole.
	api.budget.Store(2)
	if err := codes.Delete(ctx, subject); err == nil {
		t.Fatal("Delete: want the injected failure to surface, got nil")
	}
	api.budget.Store(-1)

	interrupted, err := codes.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get after the interrupted Delete: %v", err)
	}
	if len(interrupted.Codes) != slots {
		t.Fatalf("Get after the interrupted Delete returned %d slots, want the stored batch unchanged at %d; "+
			"a removal that fails must leave the batch it could not finish exactly as it found it",
			len(interrupted.Codes), slots)
	}

	if err := codes.Delete(ctx, subject); err != nil {
		t.Fatalf("Delete retry: %v", err)
	}
	if _, err := codes.Get(ctx, subject); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after a successful Delete: want ErrNotFound, got %v; "+
			"a nil Delete means no slot of the batch survives",
			err)
	}
	if err := codes.Consume(ctx, batch, 0); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Consume after a successful Delete: want ErrNotFound, got %v; "+
			"a deleted code must not stay redeemable", err)
	}
}

// TestRecoveryCodes_DeleteEmptiesAPartitionWithAGap covers the partition
// an older adapter's interrupted removal left behind: the surviving
// slots sit at the high indexes, so a removal that walks positions
// 0..len-1 issues deletes against keys that do not exist and — DeleteItem
// being silent about an absent key — reports success over a batch that
// is still there and still redeemable.
func TestRecoveryCodes_DeleteEmptiesAPartitionWithAGap(t *testing.T) {
	t.Parallel()

	s, client := newWrappedStore(t, "recgap_", nil)
	ctx := t.Context()
	const (
		subject = "sub-recovery-gap"
		table   = "recgap_recovery_codes"
	)
	seedRecoverySlots(t, client, table, subject, 5, 10)

	codes := s.RecoveryCodes()
	before, err := codes.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get seeded partition: %v", err)
	}
	if len(before.Codes) != 5 {
		t.Fatalf("seeded partition holds %d slots, want 5", len(before.Codes))
	}

	if err := codes.Delete(ctx, subject); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if remaining := countRecoverySlots(t, client, table, subject); remaining != 0 {
		t.Errorf("%d slot(s) survived a Delete that reported success", remaining)
	}
	if _, err := codes.Get(ctx, subject); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get after Delete: want ErrNotFound, got %v", err)
	}
}

// TestRecoveryCodes_PutReplacesAPartitionWithAGap pins the same key
// derivation for a regeneration. Replacing a batch has to revoke every
// slot the previous one occupied, whatever indexes those slots sit at:
// a survivor is a code the user believes they replaced.
func TestRecoveryCodes_PutReplacesAPartitionWithAGap(t *testing.T) {
	t.Parallel()

	s, client := newWrappedStore(t, "recgapput_", nil)
	ctx := t.Context()
	const (
		subject = "sub-recovery-gap-put"
		table   = "recgapput_recovery_codes"
	)
	seedRecoverySlots(t, client, table, subject, 5, 10)

	codes := s.RecoveryCodes()
	fresh := newRecoveryBatch(subject, 3)
	if err := codes.Put(ctx, fresh); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if slots := countRecoverySlots(t, client, table, subject); slots != 3 {
		t.Errorf("partition holds %d slots after a 3-code regeneration, want 3; "+
			"the slots the previous batch occupied must not survive it", slots)
	}
	got, err := codes.Get(ctx, subject)
	if err != nil {
		t.Fatalf("Get after Put: %v", err)
	}
	if len(got.Codes) != 3 {
		t.Fatalf("Get returned %d slots after a 3-code regeneration, want 3", len(got.Codes))
	}
	for i, code := range got.Codes {
		if code.Hash != fresh.Codes[i].Hash {
			t.Errorf("slot %d holds %q, want the regenerated %q", i, code.Hash, fresh.Codes[i].Hash)
		}
	}
}

// seedRecoverySlots writes the slot items for the half-open index range
// [from, to) directly, which is how a partition an interrupted removal
// left behind looks: occupied at the high indexes with nothing below.
func seedRecoverySlots(t *testing.T, client *awsdynamodb.Client, table, subject string, from, to int) {
	t.Helper()
	for i := from; i < to; i++ {
		_, err := client.PutItem(t.Context(), &awsdynamodb.PutItemInput{
			TableName: aws.String(table),
			Item: map[string]types.AttributeValue{
				"pk":          &types.AttributeValueMemberS{Value: subject},
				slotIndexAttr: &types.AttributeValueMemberN{Value: strconv.Itoa(i)},
				codeHashAttr:  &types.AttributeValueMemberS{Value: fmt.Sprintf("$argon2id$legacy-%d", i)},
			},
		})
		if err != nil {
			t.Fatalf("seed slot %d: %v", i, err)
		}
	}
}

func countRecoverySlots(t *testing.T, client *awsdynamodb.Client, table, subject string) int {
	t.Helper()
	out, err := client.Query(t.Context(), &awsdynamodb.QueryInput{
		TableName:                 aws.String(table),
		KeyConditionExpression:    aws.String("#k = :v"),
		ExpressionAttributeNames:  map[string]string{"#k": "pk"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": &types.AttributeValueMemberS{Value: subject}},
		ConsistentRead:            aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("query recovery slots: %v", err)
	}
	return len(out.Items)
}
