package oidcdynamo

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestRotationWrites_RetryCacheIsTheOnlyVariation(t *testing.T) {
	t.Parallel()

	rs := &refreshStore{parent: &Store{names: defaultNames("t_")}}
	entry := item{attrPK: avS("child")}

	plain := rs.rotationWrites(entry, "parent", "child", nil)
	cached := rs.rotationWrites(entry, "parent", "child", []byte("sealed"))

	for name, writes := range map[string][]types.TransactWriteItem{"plain": plain, "cached": cached} {
		if len(writes) != 2 || writes[0].Put == nil || writes[1].Update == nil {
			t.Fatalf("%s: want [Put, Update], got %+v", name, writes)
		}
		if got := aws.ToString(writes[1].Update.ConditionExpression); got != parentAliveCondition {
			t.Fatalf("%s: parent guard = %q", name, got)
		}
		if got := aws.ToString(writes[0].Put.ConditionExpression); got != "attribute_not_exists("+attrPK+")" {
			t.Fatalf("%s: successor guard = %q", name, got)
		}
	}

	if got := aws.ToString(plain[1].Update.UpdateExpression); got != "ADD #children :child" {
		t.Fatalf("plain expression = %q", got)
	}
	if _, ok := plain[1].Update.ExpressionAttributeNames["#retry"]; ok {
		t.Fatal("plain rotation must not bind the retry attribute")
	}
	if got := aws.ToString(cached[1].Update.UpdateExpression); got != "SET #retry = :sealed ADD #children :child" {
		t.Fatalf("cached expression = %q", got)
	}
	if cached[1].Update.ExpressionAttributeNames["#retry"] != attrRetryResponse {
		t.Fatalf("cached names = %v", cached[1].Update.ExpressionAttributeNames)
	}
	if _, ok := cached[1].Update.ExpressionAttributeValues[":sealed"]; !ok {
		t.Fatal("cached rotation must bind :sealed")
	}
}

func TestStampConsumedInput_GuardsOnUnsetConsumedAt(t *testing.T) {
	t.Parallel()

	rs := &refreshStore{parent: &Store{names: defaultNames("t_")}}
	in := rs.stampConsumedInput("pk", time.Unix(1, 0))
	if got := aws.ToString(in.ConditionExpression); got != "attribute_exists(#pk) AND #consumed = :zero" {
		t.Fatalf("condition = %q", got)
	}
	if got := aws.ToString(in.TableName); got != rs.parent.names.refreshes {
		t.Fatalf("table = %q", got)
	}
}
