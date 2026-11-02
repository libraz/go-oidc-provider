package oidcdynamo

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// ValidateSchema checks every table in [Store.TableDefinitions] against
// DynamoDB: the table exists and is usable, its key schema matches, and
// every secondary index the substores query is present and active. Use
// it as a CI or deploy gate after provisioning. op.New runs the same
// checks on only the tables its configuration uses, through each
// substore's own ValidateSchema.
//
// TTL configuration is not checked: expiry is enforced on read, so a
// table without TTL keeps its expired items but never serves them.
//
// Stable since v1.5.
func (s *Store) ValidateSchema(ctx context.Context) error {
	return s.validateTables(ctx, s.names.all()...)
}

// validateTables runs the [Store.ValidateSchema] checks on the named
// physical tables only.
func (s *Store) validateTables(ctx context.Context, tables ...string) error {
	defs := s.TableDefinitions()
	var problems []error
	for _, table := range tables {
		i := slices.IndexFunc(defs, func(d TableDefinition) bool { return d.Name == table })
		if i < 0 {
			return fmt.Errorf("oidcdynamo: no definition for table %s", table)
		}
		found, err := s.validateTable(ctx, defs[i])
		if err != nil {
			return err
		}
		problems = append(problems, found...)
	}
	return errors.Join(problems...)
}

// validateTable returns the schema problems of one table. The error
// return is reserved for a DescribeTable failure other than an absent
// table, which says nothing about the schema.
func (s *Store) validateTable(ctx context.Context, def TableDefinition) ([]error, error) {
	out, err := s.api.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(def.Name)})
	if err != nil {
		var notFound *types.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return []error{fmt.Errorf("oidcdynamo: table %s is missing; create it with Store.CreateTables or from Store.TableDefinitions", def.Name)}, nil
		}
		return nil, fmt.Errorf("oidcdynamo: describe table %s: %w", def.Name, err)
	}
	have := out.Table
	if have == nil {
		return []error{fmt.Errorf("oidcdynamo: table %s is missing; create it with Store.CreateTables or from Store.TableDefinitions", def.Name)}, nil
	}
	var problems []error
	if st := have.TableStatus; st != types.TableStatusActive && st != types.TableStatusUpdating {
		problems = append(problems, fmt.Errorf("oidcdynamo: table %s is %s, not ACTIVE", def.Name, st))
	}
	want := formatKeys(def.KeySchema, def.AttributeDefinitions)
	if got := formatKeys(have.KeySchema, have.AttributeDefinitions); got != want {
		problems = append(problems, fmt.Errorf(
			"oidcdynamo: table %s has key schema %s, want %s; a key schema cannot change in place, so recreate the table from Store.TableDefinitions",
			def.Name, got, want,
		))
	}
	problems = append(problems, validateIndexes(def, have)...)
	return problems, nil
}

// validateIndexes compares the secondary indexes def requires with the
// ones the described table carries.
func validateIndexes(def TableDefinition, have *types.TableDescription) []error {
	var problems []error
	var missing []string
	for _, idx := range def.GlobalSecondaryIndexes {
		name := aws.ToString(idx.IndexName)
		j := slices.IndexFunc(have.GlobalSecondaryIndexes, func(g types.GlobalSecondaryIndexDescription) bool {
			return aws.ToString(g.IndexName) == name
		})
		if j < 0 {
			missing = append(missing, name)
			continue
		}
		got := have.GlobalSecondaryIndexes[j]
		wantKeys := formatKeys(idx.KeySchema, def.AttributeDefinitions)
		if gotKeys := formatKeys(got.KeySchema, have.AttributeDefinitions); gotKeys != wantKeys {
			problems = append(problems, fmt.Errorf(
				"oidcdynamo: index %s on table %s has key schema %s, want %s; delete the index and run Store.CreateTables to recreate it",
				name, def.Name, gotKeys, wantKeys,
			))
			continue
		}
		if st := got.IndexStatus; st != types.IndexStatusActive && st != types.IndexStatusUpdating {
			problems = append(problems, fmt.Errorf("oidcdynamo: index %s on table %s is %s, not ACTIVE", name, def.Name, st))
		}
	}
	if len(missing) > 0 {
		problems = append(problems, fmt.Errorf(
			"oidcdynamo: table %s is missing secondary indexes: %s; Store.CreateTables adds them to an existing table",
			def.Name, strings.Join(missing, ", "),
		))
	}
	return append(problems, validateLocalIndexes(def, have)...)
}

// validateLocalIndexes compares the local secondary indexes def requires
// with the ones the table carries. A local index exists only from table
// creation, so a missing or mismatched one means recreating the table.
func validateLocalIndexes(def TableDefinition, have *types.TableDescription) []error {
	var problems []error
	for _, idx := range def.LocalSecondaryIndexes {
		name := aws.ToString(idx.IndexName)
		j := slices.IndexFunc(have.LocalSecondaryIndexes, func(l types.LocalSecondaryIndexDescription) bool {
			return aws.ToString(l.IndexName) == name
		})
		if j < 0 {
			problems = append(problems, fmt.Errorf(
				"oidcdynamo: table %s is missing local secondary index %s; a local index cannot be added in place, so recreate the table from Store.TableDefinitions",
				def.Name, name,
			))
			continue
		}
		wantKeys := formatKeys(idx.KeySchema, def.AttributeDefinitions)
		if gotKeys := formatKeys(have.LocalSecondaryIndexes[j].KeySchema, have.AttributeDefinitions); gotKeys != wantKeys {
			problems = append(problems, fmt.Errorf(
				"oidcdynamo: index %s on table %s has key schema %s, want %s; recreate the table from Store.TableDefinitions",
				name, def.Name, gotKeys, wantKeys,
			))
		}
	}
	return problems
}

// formatKeys renders a key schema as "name:TYPE:ROLE" elements in
// declared order, resolving each attribute's scalar type from attrs.
func formatKeys(keys []types.KeySchemaElement, attrs []types.AttributeDefinition) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		name := aws.ToString(k.AttributeName)
		scalar := "?"
		for _, a := range attrs {
			if aws.ToString(a.AttributeName) == name {
				scalar = string(a.AttributeType)
				break
			}
		}
		parts = append(parts, name+":"+scalar+":"+string(k.KeyType))
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// Each substore checks only the tables it reads and writes, so op.New can
// check the tables a configuration uses and leave the rest unprovisioned.

var (
	_ store.SchemaValidator = (*Store)(nil)
	_ store.SchemaValidator = (*clientStore)(nil)
	_ store.SchemaValidator = (*authCodeStore)(nil)
	_ store.SchemaValidator = (*refreshStore)(nil)
	_ store.SchemaValidator = (*accessTokenStore)(nil)
	_ store.SchemaValidator = (*opaqueAccessTokenStore)(nil)
	_ store.SchemaValidator = (*grantRevocationStore)(nil)
	_ store.SchemaValidator = (*grantStore)(nil)
	_ store.SchemaValidator = (*sessionStore)(nil)
	_ store.SchemaValidator = (*parStore)(nil)
	_ store.SchemaValidator = (*interactionStore)(nil)
	_ store.SchemaValidator = (*jtiStore)(nil)
	_ store.SchemaValidator = (*userStore)(nil)
	_ store.SchemaValidator = (*iatStore)(nil)
	_ store.SchemaValidator = (*ratStore)(nil)
	_ store.SchemaValidator = (*metadataStore)(nil)
	_ store.SchemaValidator = (*deviceCodeStore)(nil)
	_ store.SchemaValidator = (*cibaRequestStore)(nil)
	_ store.SchemaValidator = (*totpStore)(nil)
	_ store.SchemaValidator = (*passkeyStore)(nil)
	_ store.SchemaValidator = (*recoveryStore)(nil)
	_ store.SchemaValidator = (*emailOTPStore)(nil)
	_ store.SchemaValidator = (*authnLockoutStore)(nil)
	_ store.SchemaValidator = (*ssfStreamStore)(nil)
	_ store.SchemaValidator = (*ssfEventStore)(nil)
)

// ValidateSchema implements [store.SchemaValidator] for the clients table.
func (s *clientStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.clients)
}

// ValidateSchema implements [store.SchemaValidator] for the authorization
// codes table.
func (s *authCodeStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.authCodes)
}

// ValidateSchema implements [store.SchemaValidator] for the refresh tokens
// table.
func (s *refreshStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.refreshes)
}

// ValidateSchema implements [store.SchemaValidator] for the access tokens
// table.
func (s *accessTokenStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.accessTokens, s.parent.names.cascadeLinks)
}

// ValidateSchema implements [store.SchemaValidator] for the opaque access
// tokens table.
func (s *opaqueAccessTokenStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.opaqueAccessTokens, s.parent.names.cascadeLinks)
}

// ValidateSchema implements [store.SchemaValidator] for the grant
// revocations table.
func (s *grantRevocationStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.grantTombstones)
}

// ValidateSchema implements [store.SchemaValidator] for the grants table.
func (s *grantStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.grants, s.parent.names.cascadeLinks)
}

// ValidateSchema implements [store.SchemaValidator] for the sessions table.
func (s *sessionStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.sessions)
}

// ValidateSchema implements [store.SchemaValidator] for the PAR table.
func (s *parStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.pars)
}

// ValidateSchema implements [store.SchemaValidator] for the interactions
// table.
func (s *interactionStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.interactions)
}

// ValidateSchema implements [store.SchemaValidator] for the consumed JTIs
// table.
func (s *jtiStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.jtis)
}

// ValidateSchema implements [store.SchemaValidator] for the users table.
func (s *userStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.users)
}

// ValidateSchema implements [store.SchemaValidator] for the initial access
// tokens table.
func (s *iatStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.iats)
}

// ValidateSchema implements [store.SchemaValidator] for the registration
// access tokens table.
func (s *ratStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.rats)
}

// ValidateSchema implements [store.SchemaValidator] for the metadata table.
func (s *metadataStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.metadata)
}

// ValidateSchema implements [store.SchemaValidator] for the device codes
// table.
func (s *deviceCodeStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.deviceCodes)
}

// ValidateSchema implements [store.SchemaValidator] for the CIBA requests
// table.
func (s *cibaRequestStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.cibaRequests)
}

// ValidateSchema implements [store.SchemaValidator] for the TOTP table.
func (s *totpStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.totpSecrets)
}

// ValidateSchema implements [store.SchemaValidator] for the passkeys table.
func (s *passkeyStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.passkeys)
}

// ValidateSchema implements [store.SchemaValidator] for the recovery codes
// table.
func (s *recoveryStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.recoveryCodes)
}

// ValidateSchema implements [store.SchemaValidator] for the email OTP
// table.
func (s *emailOTPStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.emailOTPs)
}

// ValidateSchema implements [store.SchemaValidator] for the authentication
// lockouts table.
func (s *authnLockoutStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.authnLockouts)
}

// ValidateSchema implements [store.SchemaValidator] for both tables the
// substore touches: deleting a stream also removes its queued events.
func (s *ssfStreamStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.ssfStreams, s.parent.names.ssfEvents)
}

// ValidateSchema implements [store.SchemaValidator] for the SSF events
// table.
func (s *ssfEventStore) ValidateSchema(ctx context.Context) error {
	return s.parent.validateTables(ctx, s.parent.names.ssfEvents)
}
