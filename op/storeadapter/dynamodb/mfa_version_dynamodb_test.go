//go:build testcontainers

package oidcdynamo_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

const maxStoredMFARecordVersion = "9223372036854775807"

// TestDynamoDB_MFAVersionBoundaries exercises the migration and terminal
// token shapes directly against DynamoDB Local. In particular, a legacy item
// without record_version reads as token one, while a stored signed maximum
// remains readable but cannot be used by caller-snapshot transitions.
func TestDynamoDB_MFAVersionBoundaries(t *testing.T) {
	client := newEmulatorClient(t)
	s, err := oidcdynamo.New(client,
		oidcdynamo.WithTablePrefix("mfa_version_"),
		oidcdynamo.WithClock(&fixedClock{now: contract.Reference}),
	)
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	if err := s.CreateTables(t.Context()); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}
	disableEmulatorTTL(t, client, s)

	totpTable := tableName(t, s, "totp_secrets")
	emailTable := tableName(t, s, "email_otps")
	ctx := t.Context()

	legacyTOTP := &store.TOTPRecord{
		Subject:          "legacy-totp",
		SecretCiphertext: []byte{1, 2, 3},
		ConfirmedAt:      contract.Reference,
	}
	putRawMFAItem(t, client, totpTable, legacyTOTP.Subject, legacyTOTP, false, "")
	legacyGot, err := s.TOTPs().Get(ctx, legacyTOTP.Subject)
	if err != nil {
		t.Fatalf("legacy TOTP Get: %v", err)
	}
	if legacyGot.Version != 1 {
		t.Fatalf("legacy TOTP Version = %d, want 1", legacyGot.Version)
	}
	legacyNext := *legacyGot
	legacyNext.FailedCount++
	if err := s.TOTPs().CompareAndSwap(ctx, legacyGot, &legacyNext); err != nil {
		t.Fatalf("legacy TOTP CAS: %v", err)
	}
	legacyMigrated, err := s.TOTPs().Get(ctx, legacyTOTP.Subject)
	if err != nil {
		t.Fatalf("migrated TOTP Get: %v", err)
	}
	if legacyMigrated.Version == 0 || legacyMigrated.Version == 1 {
		t.Fatalf("legacy TOTP transition did not allocate a fresh token: %d", legacyMigrated.Version)
	}
	legacyAccept := &store.TOTPRecord{
		Subject:          "legacy-accept-totp",
		SecretCiphertext: []byte{15, 16, 17},
		ConfirmedAt:      contract.Reference,
		LastAcceptedStep: 4,
	}
	putRawMFAItem(t, client, totpTable, legacyAccept.Subject, legacyAccept, false, "")
	legacyAcceptGot, err := s.TOTPs().Get(ctx, legacyAccept.Subject)
	if err != nil {
		t.Fatalf("legacy Accept Get: %v", err)
	}
	legacyAcceptGot.LastAcceptedStep++
	if err := s.TOTPs().Accept(ctx, legacyAcceptGot); err != nil {
		t.Fatalf("legacy Accept: %v", err)
	}
	legacyAcceptMigrated, err := s.TOTPs().Get(ctx, legacyAccept.Subject)
	if err != nil {
		t.Fatalf("legacy Accept migrated Get: %v", err)
	}
	if legacyAcceptMigrated.Version == 0 || legacyAcceptMigrated.Version == 1 {
		t.Fatalf("legacy Accept did not allocate a fresh token: %d", legacyAcceptMigrated.Version)
	}

	maxTOTP := &store.TOTPRecord{
		Subject:          "max-totp",
		SecretCiphertext: []byte{4, 5, 6},
		ConfirmedAt:      contract.Reference,
	}
	putRawMFAItem(t, client, totpTable, maxTOTP.Subject, maxTOTP, true, maxStoredMFARecordVersion)
	maxTOTPGot, err := s.TOTPs().Get(ctx, maxTOTP.Subject)
	if err != nil {
		t.Fatalf("max TOTP Get: %v", err)
	}
	if maxTOTPGot.Version != uint64(^uint64(0)>>1) {
		t.Fatalf("max TOTP Version = %d", maxTOTPGot.Version)
	}
	maxTOTPBefore := cloneDynamoTOTP(maxTOTPGot)
	maxTOTPNext := *maxTOTPGot
	maxTOTPNext.FailedCount++
	if err := s.TOTPs().CompareAndSwap(ctx, maxTOTPGot, &maxTOTPNext); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("max TOTP CAS = %v, want ErrAlreadyConsumed", err)
	}
	maxTOTPAccept := *maxTOTPGot
	maxTOTPAccept.LastAcceptedStep = 1
	if err := s.TOTPs().Accept(ctx, &maxTOTPAccept); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("max TOTP Accept = %v, want ErrAlreadyConsumed", err)
	}
	maxTOTPAfter, err := s.TOTPs().Get(ctx, maxTOTP.Subject)
	if err != nil {
		t.Fatalf("max TOTP Get after rejection: %v", err)
	}
	if !reflect.DeepEqual(maxTOTPAfter, maxTOTPBefore) {
		t.Fatalf("max TOTP changed after rejected transitions: before=%+v after=%+v", maxTOTPGot, maxTOTPAfter)
	}
	if err := s.TOTPs().Put(ctx, maxTOTP); err != nil {
		t.Fatalf("max TOTP healing Put: %v", err)
	}
	healedTOTP, err := s.TOTPs().Get(ctx, maxTOTP.Subject)
	if err != nil {
		t.Fatalf("healed TOTP Get: %v", err)
	}
	if healedTOTP.Version == maxTOTPGot.Version || healedTOTP.Version == 0 {
		t.Fatalf("healing Put reused invalid token: %d", healedTOTP.Version)
	}

	legacyEmail := &store.EmailOTPRecord{
		Subject:   "legacy-email",
		CodeSalt:  []byte{7, 8},
		CodeHash:  []byte{9, 10},
		SentAt:    contract.Reference,
		ExpiresAt: contract.Reference.Add(time.Hour),
	}
	putRawMFAItem(t, client, emailTable, legacyEmail.Subject, legacyEmail, false, "")
	legacyEmailGot, err := s.EmailOTPs().Get(ctx, legacyEmail.Subject)
	if err != nil {
		t.Fatalf("legacy email Get: %v", err)
	}
	if legacyEmailGot.Version != 1 {
		t.Fatalf("legacy email Version = %d, want 1", legacyEmailGot.Version)
	}
	legacyEmailPresented := *legacyEmailGot
	legacyEmailPresented.ConsumedAt = contract.Reference
	if err := s.EmailOTPs().Consume(ctx, &legacyEmailPresented); err != nil {
		t.Fatalf("legacy email Consume: %v", err)
	}
	legacyEmailMigrated, err := s.EmailOTPs().Get(ctx, legacyEmail.Subject)
	if err != nil {
		t.Fatalf("migrated email Get: %v", err)
	}
	if legacyEmailMigrated.Version == 0 || legacyEmailMigrated.Version == 1 {
		t.Fatalf("legacy email transition did not allocate a fresh token: %d", legacyEmailMigrated.Version)
	}

	maxEmail := &store.EmailOTPRecord{
		Subject:   "max-email",
		CodeSalt:  []byte{11, 12},
		CodeHash:  []byte{13, 14},
		SentAt:    contract.Reference,
		ExpiresAt: contract.Reference.Add(time.Hour),
	}
	putRawMFAItem(t, client, emailTable, maxEmail.Subject, maxEmail, true, maxStoredMFARecordVersion)
	maxEmailGot, err := s.EmailOTPs().Get(ctx, maxEmail.Subject)
	if err != nil {
		t.Fatalf("max email Get: %v", err)
	}
	maxEmailBefore := cloneDynamoEmailOTP(maxEmailGot)
	maxEmailNext := *maxEmailGot
	maxEmailNext.FailedCount++
	if err := s.EmailOTPs().CompareAndSwap(ctx, maxEmailGot, &maxEmailNext); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("max email CAS = %v, want ErrAlreadyConsumed", err)
	}
	maxEmailPresented := *maxEmailGot
	maxEmailPresented.ConsumedAt = contract.Reference
	if err := s.EmailOTPs().Consume(ctx, &maxEmailPresented); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("max email Consume = %v, want ErrAlreadyConsumed", err)
	}
	maxEmailAfter, err := s.EmailOTPs().Get(ctx, maxEmail.Subject)
	if err != nil {
		t.Fatalf("max email Get after rejection: %v", err)
	}
	if !reflect.DeepEqual(maxEmailAfter, maxEmailBefore) {
		t.Fatalf("max email changed after rejected transitions: before=%+v after=%+v", maxEmailGot, maxEmailAfter)
	}
	if err := s.EmailOTPs().Put(ctx, maxEmail); err != nil {
		t.Fatalf("max email healing Put: %v", err)
	}
	healedEmail, err := s.EmailOTPs().Get(ctx, maxEmail.Subject)
	if err != nil {
		t.Fatalf("healed email Get: %v", err)
	}
	if healedEmail.Version == maxEmailGot.Version || healedEmail.Version == 0 {
		t.Fatalf("email healing Put reused invalid token: %d", healedEmail.Version)
	}
}

func tableName(t *testing.T, s *oidcdynamo.Store, suffix string) string {
	t.Helper()
	for _, definition := range s.TableDefinitions() {
		if strings.HasSuffix(definition.Name, suffix) {
			return definition.Name
		}
	}
	t.Fatalf("table with suffix %q not found", suffix)
	return ""
}

func putRawMFAItem(t *testing.T, client *dynamodb.Client, table, subject string, record any, withVersion bool, version string) {
	t.Helper()
	doc, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal raw MFA record: %v", err)
	}
	item := map[string]types.AttributeValue{
		"pk":  &types.AttributeValueMemberS{Value: subject},
		"doc": &types.AttributeValueMemberB{Value: doc},
	}
	if totp, ok := record.(*store.TOTPRecord); ok {
		item["last_accepted_step"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(totp.LastAcceptedStep, 10)}
	}
	if withVersion {
		item["record_version"] = &types.AttributeValueMemberN{Value: version}
	}
	if _, err := client.PutItem(t.Context(), &dynamodb.PutItemInput{
		TableName: aws.String(table),
		Item:      item,
	}); err != nil {
		t.Fatalf("put raw MFA item: %v", err)
	}
}

func cloneDynamoTOTP(r *store.TOTPRecord) *store.TOTPRecord {
	out := *r
	out.SecretCiphertext = append([]byte(nil), r.SecretCiphertext...)
	return &out
}

func cloneDynamoEmailOTP(r *store.EmailOTPRecord) *store.EmailOTPRecord {
	out := *r
	out.CodeSalt = append([]byte(nil), r.CodeSalt...)
	out.CodeHash = append([]byte(nil), r.CodeHash...)
	return &out
}
