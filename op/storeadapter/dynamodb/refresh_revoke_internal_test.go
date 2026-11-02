package oidcdynamo

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// revokeUpdateAPI answers every UpdateItem with the item it would hold
// after the revoking write and counts the calls.
type revokeUpdateAPI struct {
	API
	after map[string]types.AttributeValue
	calls int
}

func (a *revokeUpdateAPI) UpdateItem(
	context.Context,
	*dynamodb.UpdateItemInput,
	...func(*dynamodb.Options),
) (*dynamodb.UpdateItemOutput, error) {
	a.calls++
	return &dynamodb.UpdateItemOutput{Attributes: a.after}, nil
}

func TestRefreshRevokeOne_StampsConsumedOnlyWhenUnset(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	for name, tc := range map[string]struct {
		consumed int64
		calls    int
	}{
		"unset":            {consumed: 0, calls: 2},
		"already consumed": {consumed: 42, calls: 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api := &revokeUpdateAPI{after: map[string]types.AttributeValue{
				attrPK:         avS("pk"),
				attrConsumedAt: avN(tc.consumed),
				attrChildren:   &types.AttributeValueMemberSS{Value: []string{"child"}},
			}}
			rs := &refreshStore{parent: &Store{api: api, names: defaultNames("t_")}}
			children, err := rs.revokeOne(t.Context(), "pk", "", now)
			if err != nil {
				t.Fatalf("revokeOne: %v", err)
			}
			if len(children) != 1 || children[0] != "child" {
				t.Fatalf("children = %v", children)
			}
			if api.calls != tc.calls {
				t.Fatalf("UpdateItem calls = %d, want %d", api.calls, tc.calls)
			}
		})
	}
}
