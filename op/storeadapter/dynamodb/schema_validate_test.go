//go:build testcontainers

package oidcdynamo_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// provisioned returns a store under prefix whose every table exists,
// then removes the tables named by drop (unprefixed WithNaming keys).
func provisioned(t *testing.T, client *awsdynamodb.Client, prefix string, drop ...string) *oidcdynamo.Store {
	t.Helper()
	s, err := oidcdynamo.New(client, oidcdynamo.WithTablePrefix(prefix))
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	if err := s.CreateTables(t.Context()); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}
	for _, key := range drop {
		if _, err := client.DeleteTable(t.Context(), &awsdynamodb.DeleteTableInput{
			TableName: aws.String(prefix + key),
		}); err != nil {
			t.Fatalf("DeleteTable %s: %v", key, err)
		}
	}
	return s
}

func validatorOf(t *testing.T, v any) store.SchemaValidator {
	t.Helper()
	sv, ok := v.(store.SchemaValidator)
	if !ok {
		t.Fatalf("%T does not implement store.SchemaValidator", v)
	}
	return sv
}

func wantSchemaError(t *testing.T, err error, fragments ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("ValidateSchema succeeded, want an error mentioning %q", fragments)
	}
	for _, f := range fragments {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("error does not mention %q: %v", f, err)
		}
	}
}

func TestValidateSchema_AcceptsProvisionedTables(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	s := provisioned(t, client, "valok_")
	if err := s.ValidateSchema(t.Context()); err != nil {
		t.Fatalf("ValidateSchema after CreateTables: %v", err)
	}
}

func TestValidateSchema_ReportsMissingTableOnItsSubstoreOnly(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	ctx := t.Context()
	s := provisioned(t, client, "valmiss_", "grants", "ssf_events")

	wantSchemaError(t, s.ValidateSchema(ctx), "valmiss_grants is missing", "valmiss_ssf_events is missing", "Store.CreateTables")
	wantSchemaError(t, validatorOf(t, s.Grants()).ValidateSchema(ctx), "valmiss_grants is missing")
	// Deleting a stream purges its events, so the stream substore needs both tables.
	wantSchemaError(t, validatorOf(t, s.SSFStreams()).ValidateSchema(ctx), "valmiss_ssf_events is missing")
	if err := validatorOf(t, s.Clients()).ValidateSchema(ctx); err != nil {
		t.Fatalf("Clients().ValidateSchema with its table present: %v", err)
	}
}

func TestValidateSchema_ReportsIndexAndKeyDrift(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	ctx := t.Context()
	const prefix = "valdrift_"
	s := provisioned(t, client, prefix, "sessions", "par_records")

	// sessions without its by_chooser_group index.
	createTable(t, client, prefix+"sessions", types.ScalarAttributeTypeS)
	// par_records keyed on a number instead of a string.
	createTable(t, client, prefix+"par_records", types.ScalarAttributeTypeN)

	wantSchemaError(t, validatorOf(t, s.Sessions()).ValidateSchema(ctx),
		"valdrift_sessions is missing secondary indexes: by_chooser_group")
	wantSchemaError(t, validatorOf(t, s.PushedAuthRequests()).ValidateSchema(ctx),
		"valdrift_par_records has key schema (pk:N:HASH), want (pk:S:HASH)", "recreate the table")
}

func createTable(t *testing.T, client *awsdynamodb.Client, name string, pkType types.ScalarAttributeType) {
	t.Helper()
	if _, err := client.CreateTable(t.Context(), &awsdynamodb.CreateTableInput{
		TableName:            aws.String(name),
		KeySchema:            []types.KeySchemaElement{{AttributeName: aws.String("pk"), KeyType: types.KeyTypeHash}},
		AttributeDefinitions: []types.AttributeDefinition{{AttributeName: aws.String("pk"), AttributeType: pkType}},
		BillingMode:          types.BillingModePayPerRequest,
	}); err != nil {
		t.Fatalf("CreateTable %s: %v", name, err)
	}
}

// TestValidateSchema_OPChecksOnlyConfiguredTables proves op.New consults
// the substore checks: a table the configuration never touches may be
// absent, while one it uses fails construction by name.
func TestValidateSchema_OPChecksOnlyConfiguredTables(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)

	unused := provisioned(t, client, "valopok_", "device_codes", "ciba_requests", "par_records", "ssf_streams", "ssf_events")
	p, err := op.New(testkit.MinimalOptions(t, op.WithStore(unused))...)
	if err != nil {
		t.Fatalf("op.New without tables the configuration does not use: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	used := provisioned(t, client, "valopng_", "grants")
	_, err = op.New(testkit.MinimalOptions(t, op.WithStore(used))...)
	var opErr *op.Error
	if !errors.As(err, &opErr) || opErr.Code != "configuration_error" {
		t.Fatalf("op.New with grants table missing: got %v, want a configuration_error", err)
	}
	wantSchemaError(t, err, "store schema does not match this configuration", "valopng_grants is missing")
}
