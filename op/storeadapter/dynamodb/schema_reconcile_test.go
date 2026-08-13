//go:build testcontainers

package oidcdynamo_test

import (
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// TestCreateTables_AddsIndexesMissingFromAnExistingTable pins the
// upgrade path. A deployment that provisioned its tables through
// [Store.CreateTables] before the access-token registry gained its
// client index has a table DynamoDB reports as present and healthy;
// CreateTables used to return early on it, leaving the client-deletion
// cascade to fail its query at the moment it was needed rather than at
// provisioning time.
//
// The test builds exactly that table by hand — the current definition
// minus the index — and asserts CreateTables converges it.
func TestCreateTables_AddsIndexesMissingFromAnExistingTable(t *testing.T) {
	t.Parallel()

	client := newEmulatorClient(t)
	ctx := t.Context()
	clock := &fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}

	const prefix = "reconcile_"
	table := prefix + "access_tokens"

	// The pre-upgrade shape: the by_grant index only.
	_, err := client.CreateTable(ctx, &awsdynamodb.CreateTableInput{
		TableName: aws.String(table),
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("pk"), KeyType: types.KeyTypeHash},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("pk"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("grant_id"), AttributeType: types.ScalarAttributeTypeS},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{{
			IndexName: aws.String("by_grant"),
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("grant_id"), KeyType: types.KeyTypeHash},
			},
			Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll},
		}},
		BillingMode: types.BillingModePayPerRequest,
	})
	if err != nil {
		t.Fatalf("create the pre-upgrade table: %v", err)
	}

	s, err := oidcdynamo.New(client,
		oidcdynamo.WithTablePrefix(prefix),
		oidcdynamo.WithClock(clock),
	)
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	if err := s.CreateTables(ctx); err != nil {
		t.Fatalf("CreateTables over an existing table: %v", err)
	}
	// The hand-built table never had TTL turned on, so the emulator's
	// janitor cannot reach the record this case seeds and there is
	// nothing to switch off.

	described, err := client.DescribeTable(ctx, &awsdynamodb.DescribeTableInput{
		TableName: aws.String(table),
	})
	if err != nil {
		t.Fatalf("DescribeTable: %v", err)
	}
	indexes := make([]string, 0, len(described.Table.GlobalSecondaryIndexes))
	for _, idx := range described.Table.GlobalSecondaryIndexes {
		indexes = append(indexes, aws.ToString(idx.IndexName))
	}
	if !slices.Contains(indexes, "by_client") {
		t.Fatalf("existing table still carries %v; the client index was not added", indexes)
	}

	// The index is only worth anything if the cascade can drive it, so
	// exercise the query rather than trusting the schema report.
	registry := s.AccessTokens()
	rec := store.AccessTokenRecord{
		JTI:       "reconcile-jti",
		GrantID:   "reconcile-grant",
		Subject:   "sub",
		ClientID:  "reconcile-client",
		IssuedAt:  clock.now,
		ExpiresAt: clock.now.Add(time.Hour),
	}
	if err := registry.Register(ctx, rec); err != nil {
		t.Fatalf("Register: %v", err)
	}
	revoke, ok := registry.(store.RevokeByClient)
	if !ok {
		t.Fatalf("%T does not implement store.RevokeByClient", registry)
	}
	if err := revoke.RevokeByClient(ctx, rec.ClientID); err != nil {
		t.Fatalf("RevokeByClient over the reconciled table: %v", err)
	}
	got, err := registry.Find(ctx, rec.JTI)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got != nil && !got.Revoked {
		t.Fatalf("record %+v survived the cascade on the reconciled table", got)
	}
}
