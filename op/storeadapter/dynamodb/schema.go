package oidcdynamo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Index names. Every secondary index exists to serve one documented
// access pattern; the comment on each entry in [TableDefinitions] names
// the substore method that drives it.
const (
	indexBySubject       = "by_subject"
	indexBySubjectClient = "by_subject_client"
	indexByGrant         = "by_grant"
	indexByClient        = "by_client"
	indexByClientSubject = "by_client_subject"
	indexByParent        = "by_parent"
	indexByUsername      = "by_username"
	indexByChooserGroup  = "by_chooser_group"
	indexByHash          = "by_hash"
)

// Projected attribute names. These are the attributes an index or a
// condition expression reads; everything else lives inside the JSON
// document.
const (
	attrPK            = "pk"
	attrSubject       = "subject"
	attrClientID      = "client_id"
	attrGrantID       = "grant_id"
	attrParentID      = "parent_id"
	attrUserCode      = "user_code"
	attrUsername      = "username"
	attrChooserGroup  = "chooser_group"
	attrTokenHash     = "token_hash"
	attrConsumedAt    = "consumed_at"
	attrRevoked       = "revoked"
	attrSubjectClient = "subject_client"
	attrStatus        = "status"
	attrIssuedAt      = "issued_at"
	attrRevokedAt     = "revoked_at"
	attrValue         = "value"
	attrRawState      = "raw_state"
	attrUses          = "uses"
	attrSlotIndex     = "slot_index"
	attrCodeHash      = "code_hash"
	attrRetryResponse = "retry_response"
	attrTOTPStep      = "last_accepted_step"
	// attrRecordVersion is deliberately independent from attrDoc. During the
	// migration, deploy all writers together: an old writer's PutItem omits
	// this attribute and can reset a newly generated token to the legacy
	// missing-value state. Mixed old/new writers therefore invalidate the CAS
	// guarantee and are unsupported.
	attrRecordVersion   = "record_version"
	attrMaxUses         = "max_uses"
	attrUserCodeStrikes = "user_code_strikes"
	attrPollViolations  = "poll_violations"
	attrReservedFor     = "reserved_for"
	attrTOTPSecret      = "totp_secret"
	attrTOTPConfirmedAt = "totp_confirmed_at"
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

func gsiWithSort(name, partition, sort string) types.GlobalSecondaryIndex {
	return types.GlobalSecondaryIndex{
		IndexName:  aws.String(name),
		KeySchema:  compositeKeySchema(partition, sort),
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
			// RevokeByClient, and by_parent walks a rotation chain for
			// RevokeChain. A token is looked up by its handle through the
			// primary key — the stored key is the handle's digest — so
			// that access pattern needs no index of its own.
			Name:      n.refreshes,
			KeySchema: keySchema(attrPK),
			AttributeDefinitions: stringAttr(
				attrPK, attrGrantID, attrClientID, attrParentID,
			),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				gsi(indexByGrant, attrGrantID),
				gsi(indexByClient, attrClientID),
				gsi(indexByParent, attrParentID),
			},
			TTLAttribute: attrTTL,
		},
		{
			// by_subject_client serves ListBySubject on its partition key
			// alone and the paged ListClientIDsBySubject through its
			// client-id sort key; subject_client is the composite
			// FindBySubjectClient lookup. by_client_subject provides the
			// bounded subject lister for client deletion with subject as
			// the sort key.
			Name:                 n.grants,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK, attrSubject, attrSubjectClient, attrClientID),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				gsiWithSort(indexBySubjectClient, attrSubject, attrClientID),
				gsi(indexByClient, attrSubjectClient),
				gsiWithSort(indexByClientSubject, attrClientID, attrSubject),
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
			// by_grant serves RevokeByGrant and by_client serves
			// RevokeByClient, the same pair the opaque access-token
			// table carries: both formats are retired by grant on a
			// code replay and by client on a registration delete.
			Name:                 n.accessTokens,
			KeySchema:            keySchema(attrPK),
			AttributeDefinitions: stringAttr(attrPK, attrGrantID, attrClientID),
			GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
				gsi(indexByGrant, attrGrantID),
				gsi(indexByClient, attrClientID),
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
// The call is safe to repeat. An existing table keeps its data and its
// TTL configuration; only secondary indexes it is missing are added, so
// a table provisioned by an older version of the adapter converges on
// the index set the substores query today.
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
			return s.reconcileIndexes(ctx, def)
		}
		return fmt.Errorf("oidcdynamo: create table %s: %w", def.Name, err)
	}
	if err := s.waitForTable(ctx, def.Name); err != nil {
		return err
	}
	return s.enableTTL(ctx, def)
}

// reconcileIndexes adds the secondary indexes an already-existing table
// does not have yet.
//
// The index set grows as substores gain access patterns, and a query
// against an index the table lacks fails outright rather than reporting
// nothing to do. Returning early on ResourceInUseException would leave
// exactly that: a table that reads as provisioned while the cascade that
// depends on the new index cannot run. Reconciling here means the
// definitions in [Store.TableDefinitions] are the single description of
// what the adapter queries, for a fresh table and an old one alike.
//
// Indexes are added one per UpdateTable call and each is waited out:
// DynamoDB accepts a single index creation at a time and refuses the
// next while one is still backfilling.
func (s *Store) reconcileIndexes(ctx context.Context, def TableDefinition) error {
	for _, want := range def.GlobalSecondaryIndexes {
		name := aws.ToString(want.IndexName)
		status, err := s.indexStatus(ctx, def.Name, name)
		if err != nil {
			return err
		}
		if status == types.IndexStatusActive {
			continue
		}
		if status == "" {
			if err := s.addIndex(ctx, def, want); err != nil {
				return err
			}
			continue
		}
		// Another process is already creating it.
		if err := s.waitForIndex(ctx, def.Name, name); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) addIndex(ctx context.Context, def TableDefinition, idx types.GlobalSecondaryIndex) error {
	name := aws.ToString(idx.IndexName)
	_, err := s.api.UpdateTable(ctx, &dynamodb.UpdateTableInput{
		TableName: aws.String(def.Name),
		// Only the new index's key attributes may be declared here:
		// UpdateTable rejects a definition the update does not use.
		AttributeDefinitions: indexKeyAttributes(def, idx),
		GlobalSecondaryIndexUpdates: []types.GlobalSecondaryIndexUpdate{{
			Create: &types.CreateGlobalSecondaryIndexAction{
				IndexName:  idx.IndexName,
				KeySchema:  idx.KeySchema,
				Projection: idx.Projection,
			},
		}},
	})
	if err != nil {
		var inUse *types.ResourceInUseException
		if !errors.As(err, &inUse) {
			return fmt.Errorf("oidcdynamo: add index %s to table %s: %w", name, def.Name, err)
		}
		// A concurrent CreateTables call won the race; wait on its work
		// rather than reporting a conflict the caller cannot act on.
	}
	return s.waitForIndex(ctx, def.Name, name)
}

// indexKeyAttributes narrows a table's attribute definitions to the ones
// idx keys on, preserving the declared scalar types.
func indexKeyAttributes(def TableDefinition, idx types.GlobalSecondaryIndex) []types.AttributeDefinition {
	out := make([]types.AttributeDefinition, 0, len(idx.KeySchema))
	for _, k := range idx.KeySchema {
		for _, a := range def.AttributeDefinitions {
			if aws.ToString(a.AttributeName) == aws.ToString(k.AttributeName) {
				out = append(out, a)
				break
			}
		}
	}
	return out
}

// indexStatus reports the status DynamoDB holds for one index of a
// table, or the empty status when the table carries no such index.
func (s *Store) indexStatus(ctx context.Context, table, index string) (types.IndexStatus, error) {
	described, err := s.api.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(table),
	})
	if err != nil {
		return "", fmt.Errorf("oidcdynamo: describe table %s: %w", table, err)
	}
	if described.Table == nil {
		return "", nil
	}
	for _, have := range described.Table.GlobalSecondaryIndexes {
		if aws.ToString(have.IndexName) == index {
			return have.IndexStatus, nil
		}
	}
	return "", nil
}

// waitForIndex blocks until an index finishes backfilling. The bound is
// a poll count rather than a deadline because the adapter is a
// sub-module with no access to the OP's clock abstraction, and the
// caller's context still cuts the wait short.
func (s *Store) waitForIndex(ctx context.Context, table, index string) error {
	for range indexPollAttempts {
		status, err := s.indexStatus(ctx, table, index)
		if err != nil {
			return err
		}
		if status == types.IndexStatusActive {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("oidcdynamo: wait for index %s on table %s: %w", index, table, ctx.Err())
		case <-time.After(indexPollInterval):
		}
	}
	return fmt.Errorf("oidcdynamo: index %s on table %s did not become active", index, table)
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
