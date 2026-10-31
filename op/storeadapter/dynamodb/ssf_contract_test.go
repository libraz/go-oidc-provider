//go:build testcontainers

package oidcdynamo_test

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// TestDynamoDB_SSFContract runs the shared-signals contract against
// DynamoDB Local, one table set per sub-test under its own prefix.
func TestDynamoDB_SSFContract(t *testing.T) {
	t.Parallel()
	client := newEmulatorClient(t)
	var seq atomic.Uint64

	contract.RunSSF(t, func(t *testing.T) contract.SSFBackend {
		t.Helper()
		s, err := oidcdynamo.New(client,
			oidcdynamo.WithTablePrefix(fmt.Sprintf("ssf%d_", seq.Add(1))),
			oidcdynamo.WithClock(&fixedClock{now: contract.Reference}),
		)
		if err != nil {
			t.Fatalf("oidcdynamo.New: %v", err)
		}
		if err := s.CreateTables(t.Context()); err != nil {
			t.Fatalf("CreateTables: %v", err)
		}
		disableEmulatorTTL(t, client, s)
		return contract.SSFBackend{Streams: s.SSFStreams(), Events: s.SSFEvents()}
	})
}
