//go:build testcontainers

package oidcdynamo_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// blindIndexAPI stands in for global secondary indexes that have caught
// up with nothing: every index Query comes back empty, while base-table
// reads, scans and writes pass through.
// It also counts Scan calls, which no cascade may issue.
type blindIndexAPI struct {
	oidcdynamo.API
	scans *atomic.Int64
}

func (a blindIndexAPI) Scan(
	ctx context.Context,
	in *awsdynamodb.ScanInput,
	opts ...func(*awsdynamodb.Options),
) (*awsdynamodb.ScanOutput, error) {
	a.scans.Add(1)
	return a.API.Scan(ctx, in, opts...)
}

func (a blindIndexAPI) Query(
	ctx context.Context,
	in *awsdynamodb.QueryInput,
	opts ...func(*awsdynamodb.Options),
) (*awsdynamodb.QueryOutput, error) {
	out, err := a.API.Query(ctx, in, opts...)
	if err != nil || in.IndexName == nil {
		return out, err
	}
	out.Items = nil
	out.LastEvaluatedKey = nil
	return out, nil
}

func newBlindIndexStore(t *testing.T, prefix string) (*oidcdynamo.Store, *atomic.Int64) {
	t.Helper()
	client := newEmulatorClient(t)
	scans := new(atomic.Int64)
	s, err := oidcdynamo.New(blindIndexAPI{API: client, scans: scans},
		oidcdynamo.WithTablePrefix(prefix),
		oidcdynamo.WithClock(&fixedClock{now: contract.Reference}),
	)
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	if err := s.CreateTables(t.Context()); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}
	disableEmulatorTTL(t, client, s)
	return s, scans
}

// TestCascades_ReachItemsTheIndexesDoNotShow pins that access-token,
// opaque-token and grant cascades enumerate with a consistent read: the
// rows were committed before the cascade, and no index shows any of them.
func TestCascades_ReachItemsTheIndexesDoNotShow(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	exp := contract.Reference.Add(time.Hour)

	registryRevoked := func(t *testing.T, s *oidcdynamo.Store, jti string) bool {
		t.Helper()
		rec, err := s.AccessTokens().Find(ctx, jti)
		if err != nil || rec == nil {
			t.Fatalf("registry Find %s: %v %v", jti, rec, err)
		}
		return rec.Revoked
	}
	opaqueRevoked := func(t *testing.T, s *oidcdynamo.Store, id string) bool {
		t.Helper()
		rec, err := s.OpaqueAccessTokens().Find(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return true
		}
		if err != nil {
			t.Fatalf("opaque Find %s: %v", id, err)
		}
		return rec.Revoked
	}
	seedRegistry := func(t *testing.T, s *oidcdynamo.Store, jti, grant, client string) {
		t.Helper()
		err := s.AccessTokens().Register(ctx, store.AccessTokenRecord{
			JTI: jti, GrantID: grant, ClientID: client,
			IssuedAt: contract.Reference, ExpiresAt: exp,
		})
		if err != nil {
			t.Fatalf("Register %s: %v", jti, err)
		}
	}
	seedOpaque := func(t *testing.T, s *oidcdynamo.Store, id, grant, client, chain string) {
		t.Helper()
		err := s.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
			ID: id, GrantID: grant, ClientID: client, ChainID: chain,
			IssuedAt: contract.Reference, ExpiresAt: exp,
		})
		if err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}

	t.Run("JWTRegistry", func(t *testing.T) {
		t.Parallel()
		s, scans := newBlindIndexStore(t, "blindjwt_")
		seedRegistry(t, s, "jti-a", "g1", "c1")
		seedRegistry(t, s, "jti-b", "g1", "c1")
		seedRegistry(t, s, "jti-other", "g2", "c2")
		if n, err := s.AccessTokens().RevokeByGrant(ctx, "g1"); err != nil || n != 2 {
			t.Fatalf("RevokeByGrant = %d, %v; want 2, nil", n, err)
		}
		seedRegistry(t, s, "jti-c", "g3", "c1")
		revoker := s.AccessTokens().(store.RevokeByClient)
		if err := revoker.RevokeByClient(ctx, "c1"); err != nil {
			t.Fatalf("RevokeByClient: %v", err)
		}
		for _, jti := range []string{"jti-a", "jti-b", "jti-c"} {
			if !registryRevoked(t, s, jti) {
				t.Errorf("%s survived the cascade", jti)
			}
		}
		if registryRevoked(t, s, "jti-other") {
			t.Error("bystander was revoked")
		}
		requireNoScan(t, scans)
	})

	t.Run("OpaqueTokens", func(t *testing.T) {
		t.Parallel()
		s, scans := newBlindIndexStore(t, "blindopq_")
		seedOpaque(t, s, "o-a", "g1", "c1", "ch1")
		seedOpaque(t, s, "o-b", "g1", "c1", "ch2")
		seedOpaque(t, s, "o-c", "g4", "c4", "ch1")
		seedOpaque(t, s, "o-other", "g2", "c2", "ch1")

		chain := s.OpaqueAccessTokens().(store.OpaqueAccessTokenChainRevoker)
		if n, err := chain.RevokeByChain(ctx, "g1", "ch1"); err != nil || n != 1 {
			t.Fatalf("RevokeByChain = %d, %v; want 1, nil", n, err)
		}
		if !opaqueRevoked(t, s, "o-a") || opaqueRevoked(t, s, "o-b") {
			t.Fatal("RevokeByChain did not retire exactly the chain's token")
		}
		if n, err := s.OpaqueAccessTokens().RevokeByGrant(ctx, "g1"); err != nil || n != 1 {
			t.Fatalf("RevokeByGrant = %d, %v; want 1, nil", n, err)
		}
		if err := s.OpaqueAccessTokens().(store.RevokeByClient).RevokeByClient(ctx, "c4"); err != nil {
			t.Fatalf("RevokeByClient: %v", err)
		}
		for _, id := range []string{"o-a", "o-b", "o-c"} {
			if !opaqueRevoked(t, s, id) {
				t.Errorf("%s survived the cascade", id)
			}
		}
		if opaqueRevoked(t, s, "o-other") {
			t.Error("bystander was revoked")
		}
		requireNoScan(t, scans)
	})

	t.Run("Grants", func(t *testing.T) {
		t.Parallel()
		s, scans := newBlindIndexStore(t, "blindgrant_")
		for _, g := range []*store.Grant{
			{ID: "gr1", Subject: "alice", ClientID: "c1"},
			{ID: "gr2", Subject: "alice", ClientID: "c2"},
			{ID: "gr3", Subject: "bob", ClientID: "c1"},
		} {
			g.CreatedAt, g.UpdatedAt = contract.Reference, contract.Reference
			if err := s.Grants().Save(ctx, g); err != nil {
				t.Fatalf("Save %s: %v", g.ID, err)
			}
		}
		got, err := s.Grants().ListBySubject(ctx, "alice")
		if err != nil || len(got) != 2 {
			t.Fatalf("ListBySubject = %d grants, %v; want 2", len(got), err)
		}
		if err := s.Grants().(store.RevokeByClient).RevokeByClient(ctx, "c1"); err != nil {
			t.Fatalf("RevokeByClient: %v", err)
		}
		for _, id := range []string{"gr1", "gr3"} {
			if _, err := s.Grants().Find(ctx, id); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("grant %s survived: %v", id, err)
			}
		}
		if _, err := s.Grants().Find(ctx, "gr2"); err != nil {
			t.Errorf("bystander grant lost: %v", err)
		}
		requireNoScan(t, scans)
	})
}

func requireNoScan(t *testing.T, scans *atomic.Int64) {
	t.Helper()
	if n := scans.Load(); n != 0 {
		t.Errorf("cascades issued %d table scans, want 0", n)
	}
}
