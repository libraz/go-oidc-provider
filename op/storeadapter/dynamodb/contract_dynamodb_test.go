//go:build testcontainers

package oidcdynamo_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	dynamodbmod "github.com/testcontainers/testcontainers-go/modules/dynamodb"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// dynamoImage pins the emulator. amazon/dynamodb-local is a test-time
// container only: it is not a module dependency and nothing it contains
// is redistributed.
const dynamoImage = "amazon/dynamodb-local:2.5.2"

type fixedClock struct{ now time.Time }

// Now reads through the pointer so a Now method value bound once —
// as the contract harness does — still observes later mutations. A
// value receiver would copy the struct at bind time and freeze the
// harness clock while the store's own clock kept moving.
func (c *fixedClock) Now() time.Time { return c.now }

// newEmulatorClient boots one dynamodb-local container for the calling
// test and returns a client pointed at it. Tests isolate themselves
// with a per-case table prefix rather than a container each: the
// emulator creates tables in milliseconds, so one container per test
// binary keeps the suite fast.
func newEmulatorClient(t *testing.T) *awsdynamodb.Client {
	t.Helper()
	ctx := context.Background()

	ctr, err := dynamodbmod.Run(ctx, dynamoImage)
	if err != nil {
		if os.Getenv("RELEASE_CONTRACT_REQUIRED") == "1" {
			t.Fatalf("dynamodb-local container required for release contract: %v", err)
		}
		t.Skipf("dynamodb-local container unavailable (Docker not running?): %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	endpoint, err := ctr.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("ConnectionString: %v", err)
	}
	return awsdynamodb.New(awsdynamodb.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String("http://" + endpoint),
		// DynamoDB Local checks the signature's shape but not the key,
		// so any non-empty static credential works.
		Credentials: credentials.NewStaticCredentialsProvider("local", "local", ""),
	})
}

// disableEmulatorTTL turns the emulator's TTL janitor back off for every
// table s just created.
//
// Fixtures are stamped from [contract.Reference], a fixed instant that is
// already in the past in real time, so every record lands with an expiry
// epoch the janitor considers due. It then deletes them at a moment nothing
// in the test controls, which surfaces as a record that existed a line
// earlier reporting ErrNotFound. Expiry semantics are enforced by the
// adapter's own condition expressions against the injected clock — the
// sweeper is a storage-cost optimisation the tests do not assert on — so
// switching it off removes the race without removing coverage.
func disableEmulatorTTL(t *testing.T, client *awsdynamodb.Client, s *oidcdynamo.Store) {
	t.Helper()

	for _, def := range s.TableDefinitions() {
		if def.TTLAttribute == "" {
			continue
		}
		_, err := client.UpdateTimeToLive(t.Context(), &awsdynamodb.UpdateTimeToLiveInput{
			TableName: aws.String(def.Name),
			TimeToLiveSpecification: &types.TimeToLiveSpecification{
				AttributeName: aws.String(def.TTLAttribute),
				Enabled:       aws.Bool(false),
			},
		})
		if err != nil {
			t.Fatalf("disable ttl on %s: %v", def.Name, err)
		}
	}
}

// newDynamoFactory boots one emulator for the whole suite and hands out
// a fresh, isolated table set per sub-test. Isolation comes from a
// per-sub-test table prefix rather than a per-sub-test container:
// DynamoDB Local creates tables in milliseconds, and one container for
// hundreds of sub-tests keeps the suite fast.
func newDynamoFactory(t *testing.T) contract.Factory {
	t.Helper()
	client := newEmulatorClient(t)

	var seq atomic.Uint64
	clock := &fixedClock{now: contract.Reference}

	return func(t *testing.T) contract.Backend {
		t.Helper()
		prefix := fmt.Sprintf("t%d_", seq.Add(1))
		s, err := oidcdynamo.New(client,
			oidcdynamo.WithTablePrefix(prefix),
			oidcdynamo.WithClock(clock),
		)
		if err != nil {
			t.Fatalf("oidcdynamo.New: %v", err)
		}
		if err := s.CreateTables(t.Context()); err != nil {
			t.Fatalf("CreateTables: %v", err)
		}
		disableEmulatorTTL(t, client, s)
		return contract.Backend{
			Store: s,
			Now:   clock.Now,
			SeedUser: func(t *testing.T, u *store.User, username string, passwordHash []byte) {
				t.Helper()
				if err := s.PutUserWithPassword(t.Context(), u, username, passwordHash); err != nil {
					t.Fatalf("PutUserWithPassword: %v", err)
				}
			},
		}
	}
}

// TestDynamoDB_Contract runs the full store contract harness against
// DynamoDB Local. The test is gated by the `testcontainers` build tag
// so a default `go test` invocation stays Docker-free.
func TestDynamoDB_Contract(t *testing.T) {
	t.Parallel()
	factory := newDynamoFactory(t)
	contract.Run(t, factory)
	runMFAContracts(t, factory)
}

// runMFAContracts drives the authentication-factor contracts. Those
// substores sit outside [store.Store], so the helper reaches them
// through the concrete adapter type.
func runMFAContracts(t *testing.T, f contract.Factory) {
	t.Helper()

	adapter := func(t *testing.T) *oidcdynamo.Store {
		t.Helper()
		b := f(t)
		s, ok := b.Store.(*oidcdynamo.Store)
		if !ok {
			t.Fatalf("factory produced %T, want *oidcdynamo.Store", b.Store)
		}
		return s
	}

	t.Run("TOTPStore", func(t *testing.T) {
		t.Parallel()
		contract.RunTOTPs(t, func(t *testing.T) store.TOTPStore {
			t.Helper()
			return adapter(t).TOTPs()
		})
	})

	t.Run("RecoveryStore", func(t *testing.T) {
		t.Parallel()
		contract.RunRecoveryCodes(t, func(t *testing.T) store.RecoveryStore {
			t.Helper()
			return adapter(t).RecoveryCodes()
		})
	})

	t.Run("PasskeyStore", func(t *testing.T) {
		t.Parallel()
		contract.RunPasskeys(t, func(t *testing.T) store.PasskeyStore {
			t.Helper()
			return adapter(t).Passkeys()
		})
	})

	t.Run("AuthnLockoutStore", func(t *testing.T) {
		t.Parallel()
		contract.RunAuthnLockouts(t, func(t *testing.T) store.AuthnLockoutStore {
			t.Helper()
			return adapter(t).AuthnLockouts()
		})
	})

	t.Run("EmailOTPStore", func(t *testing.T) {
		t.Parallel()
		contract.RunEmailOTPs(t, func(t *testing.T) contract.EmailOTPBackend {
			t.Helper()
			b := f(t)
			s, ok := b.Store.(*oidcdynamo.Store)
			if !ok {
				t.Fatalf("factory produced %T, want *oidcdynamo.Store", b.Store)
			}
			return contract.EmailOTPBackend{Store: s.EmailOTPs(), Now: b.Now}
		})
	})
}
