package oidcdynamo

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ssfTransactAPI scripts TransactWriteItems: a transaction naming the
// event in missing is cancelled by a failed condition on that event.
type ssfTransactAPI struct {
	API
	missing string
	sizes   []int
}

func (a *ssfTransactAPI) TransactWriteItems(
	_ context.Context,
	in *dynamodb.TransactWriteItemsInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.TransactWriteItemsOutput, error) {
	a.sizes = append(a.sizes, len(in.TransactItems))
	for i, w := range in.TransactItems {
		if w.Delete == nil || w.Delete.ConditionExpression == nil {
			continue
		}
		if readS(w.Delete.Key, attrSSFSort) != ssfEventPrefix+a.missing {
			continue
		}
		reasons := make([]types.CancellationReason, len(in.TransactItems))
		for j := range reasons {
			reasons[j].Code = aws.String("None")
		}
		reasons[i].Code = aws.String(conditionalCheckFailed)
		return nil, &types.TransactionCanceledException{CancellationReasons: reasons}
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func ssfRemoveJTIs(n int) []string {
	jtis := make([]string, n)
	for i := range jtis {
		jtis[i] = fmt.Sprintf("jti-%03d", i)
	}
	return jtis
}

func TestSSFEventStore_RemoveManyBatchesTransactions(t *testing.T) {
	t.Parallel()

	api := &ssfTransactAPI{missing: "none"}
	events := &ssfEventStore{parent: &Store{api: api, names: defaultNames("t_")}}

	// 120 events at 49 per transaction is 3 transactions, not 120.
	if err := events.removeMany(t.Context(), "stream", ssfRemoveJTIs(120)); err != nil {
		t.Fatalf("removeMany: %v", err)
	}
	if want := []int{98, 98, 44}; fmt.Sprint(api.sizes) != fmt.Sprint(want) {
		t.Fatalf("transaction sizes = %v, want %v", api.sizes, want)
	}
	for _, size := range api.sizes {
		if size > maxTransactionItems {
			t.Fatalf("transaction of %d actions exceeds the limit", size)
		}
	}
}

func TestSSFEventStore_RemoveManyRedoesACancelledBatchPerEvent(t *testing.T) {
	t.Parallel()

	api := &ssfTransactAPI{missing: "jti-001"}
	events := &ssfEventStore{parent: &Store{api: api, names: defaultNames("t_")}}

	if err := events.removeMany(t.Context(), "stream", ssfRemoveJTIs(3)); err != nil {
		t.Fatalf("removeMany: %v", err)
	}
	// The batch, then one transaction per event; the missing one is tolerated.
	if want := []int{6, 2, 2, 2}; fmt.Sprint(api.sizes) != fmt.Sprint(want) {
		t.Fatalf("transaction sizes = %v, want %v", api.sizes, want)
	}
}

func TestSSFEventStore_RemoveManyIgnoresRepeatedJTIs(t *testing.T) {
	t.Parallel()

	api := &ssfTransactAPI{missing: "none"}
	events := &ssfEventStore{parent: &Store{api: api, names: defaultNames("t_")}}

	if err := events.removeMany(t.Context(), "stream", []string{"a", "a", "b"}); err != nil {
		t.Fatalf("removeMany: %v", err)
	}
	if want := []int{4}; fmt.Sprint(api.sizes) != fmt.Sprint(want) {
		t.Fatalf("transaction sizes = %v, want %v", api.sizes, want)
	}
}
