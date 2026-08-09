package oidcdynamo

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Index names. Every secondary index exists to serve one documented
// access pattern; the comment on each entry in [TableDefinitions] names
// the substore method that drives it.
const (
	indexBySubject      = "by_subject"
	indexByGrant        = "by_grant"
	indexByClient       = "by_client"
	indexByParent       = "by_parent"
	indexByHandle       = "by_handle"
	indexByUsername     = "by_username"
	indexByChooserGroup = "by_chooser_group"
	indexByHash         = "by_hash"
)

// Projected attribute names. These are the attributes an index or a
// condition expression reads; everything else lives inside the JSON
// document.
const (
	attrPK              = "pk"
	attrSubject         = "subject"
	attrClientID        = "client_id"
	attrGrantID         = "grant_id"
	attrParentID        = "parent_id"
	attrStoredHandle    = "stored_handle"
	attrUserCode        = "user_code"
	attrUsername        = "username"
	attrChooserGroup    = "chooser_group"
	attrTokenHash       = "token_hash"
	attrConsumedAt      = "consumed_at"
	attrRevoked         = "revoked"
	attrSubjectClient   = "subject_client"
	attrStatus          = "status"
	attrIssuedAt        = "issued_at"
	attrRevokedAt       = "revoked_at"
	attrValue           = "value"
	attrRawState        = "raw_state"
	attrUses            = "uses"
	attrSlotIndex       = "slot_index"
	attrCodeHash        = "code_hash"
	attrRetryResponse   = "retry_response"
	attrTOTPStep        = "last_accepted_step"
	attrRecordVersion   = "record_version"
	attrMaxUses         = "max_uses"
	attrUserCodeStrikes = "user_code_strikes"
	attrPollViolations  = "poll_violations"
	attrReservedFor     = "reserved_for"
)

// TableDefinition describes one table the adapter expects. Embedders
// that provision infrastructure through CloudFormation, CDK, or
// Terraform translate these rather than calling [Store.CreateTables].
type TableDefinition struct {
	// Name is the resolved physical table name.
	Name string

	// KeySchema and AttributeDefinitions are the DynamoDB key
	// declarations, expressed in the service's own types so a
	// translation cannot drift from what the adapter queries.
	KeySchema            []types.KeySchemaElement
	AttributeDefinitions []types.AttributeDefinition

	// GlobalSecondaryIndexes lists the indexes the substore's access
	// patterns require.
	GlobalSecondaryIndexes []types.GlobalSecondaryIndex

	// TTLAttribute names the attribute DynamoDB's TTL feature should
	// watch, or is empty for a table whose records never expire.
	TTLAttribute string
}

func keySchema(partition string) []types.KeySchemaElement {
	return []types.KeySchemaElement{
		{AttributeName: aws.String(partition), KeyType: types.KeyTypeHash},
	}
}

func compositeKeySchema(partition, sort string) []types.KeySchemaElement {
	return []types.KeySchemaElement{
		{AttributeName: aws.String(partition), KeyType: types.KeyTypeHash},
		{AttributeName: aws.String(sort), KeyType: types.KeyTypeRange},
	}
}

func stringAttr(names ...string) []types.AttributeDefinition {
	out := make([]types.AttributeDefinition, len(names))
	for i, name := range names {
		out[i] = types.AttributeDefinition{
			AttributeName: aws.String(name),
			AttributeType: types.ScalarAttributeTypeS,
		}
	}
	return out
}

func numberAttr(name string) types.AttributeDefinition {
	return types.AttributeDefinition{
		AttributeName: aws.String(name),
		AttributeType: types.ScalarAttributeTypeN,
	}
}

// gsi builds a global secondary index that projects every attribute.
// The adapter re-reads each enumerated item with a strongly consistent
// GetItem before acting on it, so a full projection is a latency
// optimisation rather than a correctness requirement.
func gsi(name, partition string) types.GlobalSecondaryIndex {
	return types.GlobalSecondaryIndex{
		IndexName:  aws.String(name),
		KeySchema:  keySchema(partition),
		Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll},
	}
}

// TableDefinitions returns the definition of every table the adapter
// uses, with any [WithNaming] override already applied.
//
//nolint:funlen // one entry per table; splitting it would hide the schema.
func (s *Store) TableDefinitions() []TableDefinition {
	n := s.names
	return []TableDefinition{
		{
			Name:                 n.clients,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
		},
		{
			// Consume is a conditional update on consumed_at, so the
			// attribute is projected out of the document.
			Name:                 n.authCodes,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
			TTLAttribute:         attrTTL,
		},
		{
			// by_grant serves RevokeByGrant, by_client serves
			// RevokeByClient, by_parent walks a rotation chain for
			// RevokeChain, and by_handle serves the
			// RefreshChainResolver extension.
			Name:      n.refreshes,
			KeySchema: keySchema(attrPK),
			AttributeDefinitions: stringAttr(
				attrPK, attrGrantID, attrClientID, attrParentID, attrStoredHandle),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				gsi(indexByGrant, attrGrantID),
				gsi(indexByClient, attrClientID),
				gsi(indexByParent, attrParentID),
				gsi(indexByHandle, attrStoredHandle),
			},
			TTLAttribute: attrTTL,
		},
		{
			// by_subject serves ListBySubject and the paged
			// ListClientIDsBySubject; subject_client is the composite
			// FindBySubjectClient looks up directly.
			Name:                 n.grants,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK, attrSubject, attrSubjectClient),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				gsi(indexBySubject, attrSubject),
				gsi(indexByClient, attrSubjectClient),
			},
		},
		{
			Name:                 n.sessions,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK, attrChooserGroup),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				gsi(indexByChooserGroup, attrChooserGroup),
			},
			TTLAttribute: attrTTL,
		},
		{
			Name:                 n.pars,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
			TTLAttribute:         attrTTL,
		},
		{
			// raw_state is projected because InteractionStoreCAS
			// conditions on it.
			Name:                 n.interactions,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
			TTLAttribute:         attrTTL,
		},
		{
			Name:                 n.jtis,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
			TTLAttribute:         attrTTL,
		},
		{
			Name:                 n.users,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK, attrUsername),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				gsi(indexByUsername, attrUsername),
			},
		},
		{
			// GetByHash is the read path; the id is the partition key
			// because IncrementUses and Delete address the record by id.
			Name:                 n.iats,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK, attrTokenHash),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				gsi(indexByHash, attrTokenHash),
			},
			TTLAttribute: attrTTL,
		},
		{
			// Registration access tokens are addressed by client_id in
			// every method, so it is the partition key outright.
			Name:                 n.rats,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
		},
		{
			Name:                 n.accessTokens,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK, attrGrantID),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				gsi(indexByGrant, attrGrantID),
			},
			TTLAttribute: attrTTL,
		},
		{
			Name:                 n.opaqueAccessTokens,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK, attrGrantID, attrClientID),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				gsi(indexByGrant, attrGrantID),
				gsi(indexByClient, attrClientID),
			},
			TTLAttribute: attrTTL,
		},
		{
			// One table holds both tombstone kinds: a grant tombstone
			// keyed "grant#<id>" and a denylisted jti keyed "jti#<id>".
			// IsRevoked reads at most one of each, so a shared table
			// costs nothing and halves the provisioning surface.
			Name:                 n.grantTombstones,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
			TTLAttribute:         attrTTL,
		},
		{
			Name:                 n.metadata,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
		},
		{
			// The table holds two item shapes: the record, keyed by the
			// device_code digest, and the reservation that claims its
			// user_code, keyed "uc#<user_code>". The reservation is the
			// uniqueness constraint DynamoDB cannot express on an index,
			// and the user-facing device flow resolves through it, so no
			// secondary index is needed.
			Name:                 n.deviceCodes,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
			TTLAttribute:         attrTTL,
		},
		{
			Name:                 n.cibaRequests,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
			TTLAttribute:         attrTTL,
		},
		{
			Name:                 n.totpSecrets,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
		},
		{
			Name:                 n.passkeys,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK, attrSubject),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				gsi(indexBySubject, attrSubject),
			},
		},
		{
			// One item per slot, keyed (subject, slot_index), so
			// redeeming a code is a conditional update on that one item.
			Name:      n.recoveryCodes,
			KeySchema: compositeKeySchema(attrPK, attrSlotIndex),
			AttributeDefinitions: append(
				stringAttr(attrPK),
				numberAttr(attrSlotIndex),
			),
		},
		{
			Name:                 n.emailOTPs,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
			TTLAttribute:         attrTTL,
		},
		{
			Name:                 n.authnLockouts,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK),
		},
	}
}

// CreateTables provisions every table the adapter expects, including
// secondary indexes and TTL configuration, and waits for each to become
// active. It is a development and test convenience: production
// deployments provision through their own infrastructure tooling from
// [Store.TableDefinitions].
//
// Existing tables are left untouched, so the call is safe to repeat.
func (s *Store) CreateTables(ctx context.Context) error {
	for _, def := range s.TableDefinitions() {
		if err := s.createTable(ctx, def); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) createTable(ctx context.Context, def TableDefinition) error {
	_, err := s.api.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:              aws.String(def.Name),
		KeySchema:              def.KeySchema,
		AttributeDefinitions:   def.AttributeDefinitions,
		GlobalSecondaryIndexes: def.GlobalSecondaryIndexes,
		BillingMode:            types.BillingModePayPerRequest,
	})
	if err != nil {
		var inUse *types.ResourceInUseException
		if errors.As(err, &inUse) {
			return nil
		}
		return fmt.Errorf("oidcdynamo: create table %s: %w", def.Name, err)
	}
	if err := s.waitForTable(ctx, def.Name); err != nil {
		return err
	}
	return s.enableTTL(ctx, def)
}

func (s *Store) waitForTable(ctx context.Context, name string) error {
	waiter := dynamodb.NewTableExistsWaiter(s.api)
	if err := waiter.Wait(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(name),
	}, tableWaitTimeout); err != nil {
		return fmt.Errorf("oidcdynamo: wait for table %s: %w", name, err)
	}
	return nil
}

func (s *Store) enableTTL(ctx context.Context, def TableDefinition) error {
	if def.TTLAttribute == "" {
		return nil
	}
	_, err := s.api.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(def.Name),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{
			AttributeName: aws.String(def.TTLAttribute),
			Enabled:       aws.Bool(true),
		},
	})
	if err != nil {
		return fmt.Errorf("oidcdynamo: enable ttl on %s: %w", def.Name, err)
	}
	return nil
}
