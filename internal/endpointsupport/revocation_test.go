package endpointsupport_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

type fakeATRegistry struct {
	revokeByGrant []string
	revokeByJTI   []string
	find          *store.AccessTokenRecord
	findErr       error
}

func (f *fakeATRegistry) Register(context.Context, store.AccessTokenRecord) error { return nil }
func (f *fakeATRegistry) Find(context.Context, string) (*store.AccessTokenRecord, error) {
	return f.find, f.findErr
}
func (f *fakeATRegistry) RevokeByJTI(_ context.Context, jti string) error {
	f.revokeByJTI = append(f.revokeByJTI, jti)
	return nil
}
func (f *fakeATRegistry) RevokeByGrant(_ context.Context, grantID string) (int, error) {
	f.revokeByGrant = append(f.revokeByGrant, grantID)
	return 1, nil
}
func (f *fakeATRegistry) GC(context.Context, time.Time) (int, error) { return 0, nil }

type fakeGrantRevocations struct {
	tombstones  []store.GrantTombstone
	revokedJTIs []store.RevokedJTI
	revoked     bool
	err         error
}

func (f *fakeGrantRevocations) RevokeGrant(_ context.Context, t store.GrantTombstone) error {
	f.tombstones = append(f.tombstones, t)
	return nil
}
func (f *fakeGrantRevocations) RevokeJTI(_ context.Context, r store.RevokedJTI) error {
	f.revokedJTIs = append(f.revokedJTIs, r)
	return nil
}
func (f *fakeGrantRevocations) IsRevoked(context.Context, string, string, time.Time) (bool, error) {
	return f.revoked, f.err
}
func (f *fakeGrantRevocations) GC(context.Context, time.Time) (int, error) { return 0, nil }

func TestRevokeJWTAccessTokensByGrant_GrantTombstoneWritesTombstone(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	revs := &fakeGrantRevocations{}
	err := endpointsupport.RevokeJWTAccessTokensByGrant(context.Background(), endpointsupport.JWTGrantCascadeOpts{
		GrantRevocations:   revs,
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
	}, "grant-1", now, 15*time.Minute, "logout")
	if err != nil {
		t.Fatalf("RevokeJWTAccessTokensByGrant: %v", err)
	}

	if len(revs.tombstones) != 1 {
		t.Fatalf("tombstones=%d want 1", len(revs.tombstones))
	}
	got := revs.tombstones[0]
	if got.GrantID != "grant-1" || got.Reason != "logout" || !got.RevokedAt.Equal(now) || !got.ExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("tombstone=%+v", got)
	}
}

func TestRevokeJWTAccessTokensByGrant_FallsBackToRegistry(t *testing.T) {
	t.Parallel()

	reg := &fakeATRegistry{}
	err := endpointsupport.RevokeJWTAccessTokensByGrant(context.Background(), endpointsupport.JWTGrantCascadeOpts{
		AccessTokens:       reg,
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
	}, "grant-2", time.Now(), time.Minute, "code_replay")
	if err != nil {
		t.Fatalf("RevokeJWTAccessTokensByGrant: %v", err)
	}

	if len(reg.revokeByGrant) != 1 || reg.revokeByGrant[0] != "grant-2" {
		t.Fatalf("revokeByGrant=%v want [grant-2]", reg.revokeByGrant)
	}
}

func TestRevokeJWTAccessTokenByJTI_GrantTombstoneWritesDenylist(t *testing.T) {
	t.Parallel()

	exp := time.Date(2026, 5, 5, 13, 0, 0, 0, time.UTC)
	revs := &fakeGrantRevocations{}
	err := endpointsupport.RevokeJWTAccessTokenByJTI(context.Background(), endpointsupport.JWTGrantCascadeOpts{
		GrantRevocations:   revs,
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
	}, "jti-1", "grant-1", exp)
	if err != nil {
		t.Fatalf("RevokeJWTAccessTokenByJTI: %v", err)
	}

	if len(revs.revokedJTIs) != 1 {
		t.Fatalf("revokedJTIs=%d want 1", len(revs.revokedJTIs))
	}
	got := revs.revokedJTIs[0]
	if got.JTI != "jti-1" || got.GrantID != "grant-1" || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("revokedJTI=%+v", got)
	}
}

func TestRevokeJWTAccessTokenByJTI_FallsBackToRegistry(t *testing.T) {
	t.Parallel()

	reg := &fakeATRegistry{}
	err := endpointsupport.RevokeJWTAccessTokenByJTI(context.Background(), endpointsupport.JWTGrantCascadeOpts{
		AccessTokens:       reg,
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
	}, "jti-2", "grant-2", time.Now().UTC())
	if err != nil {
		t.Fatalf("RevokeJWTAccessTokenByJTI: %v", err)
	}

	if len(reg.revokeByJTI) != 1 || reg.revokeByJTI[0] != "jti-2" {
		t.Fatalf("revokeByJTI=%v want [jti-2]", reg.revokeByJTI)
	}
}

func TestJWTAccessTokenRevoked_GrantTombstoneUsesGrantStore(t *testing.T) {
	t.Parallel()

	revs := &fakeGrantRevocations{revoked: true}
	claims := &tokens.AccessTokenClaims{
		JTI:      "jti-3",
		GrantID:  "grant-3",
		IssuedAt: time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC).Unix(),
	}
	revoked, ok := endpointsupport.JWTAccessTokenRevoked(context.Background(), endpointsupport.JWTRevocationOpts{
		GrantRevocations:   revs,
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
	}, claims)
	if !revoked || !ok {
		t.Fatalf("got revoked=%v ok=%v want true,true", revoked, ok)
	}
}

func TestJWTAccessTokenRevoked_GrantTombstoneFallsBackToRegistry(t *testing.T) {
	t.Parallel()

	reg := &fakeATRegistry{find: &store.AccessTokenRecord{JTI: "jti-4", Revoked: true}}
	claims := &tokens.AccessTokenClaims{JTI: "jti-4"}
	revoked, ok := endpointsupport.JWTAccessTokenRevoked(context.Background(), endpointsupport.JWTRevocationOpts{
		AccessTokens:       reg,
		RevocationStrategy: store.RevocationStrategyGrantTombstone,
	}, claims)
	if !revoked || !ok {
		t.Fatalf("got revoked=%v ok=%v want true,true", revoked, ok)
	}
}

func TestJWTAccessTokenRevoked_LookupErrorReportsNotOK(t *testing.T) {
	t.Parallel()

	reg := &fakeATRegistry{findErr: errors.New("boom")}
	claims := &tokens.AccessTokenClaims{JTI: "jti-1"}
	revoked, ok := endpointsupport.JWTAccessTokenRevoked(context.Background(), endpointsupport.JWTRevocationOpts{
		AccessTokens:       reg,
		RevocationStrategy: store.RevocationStrategyJTIRegistry,
	}, claims)
	if revoked || ok {
		t.Fatalf("got revoked=%v ok=%v want false,false", revoked, ok)
	}
}

func TestJWTAccessTokenRevoked_ErrNotFoundIsTreatedAsAbsent(t *testing.T) {
	t.Parallel()

	reg := &fakeATRegistry{findErr: store.ErrNotFound}
	claims := &tokens.AccessTokenClaims{JTI: "jti-404"}
	revoked, ok := endpointsupport.JWTAccessTokenRevoked(context.Background(), endpointsupport.JWTRevocationOpts{
		AccessTokens:       reg,
		RevocationStrategy: store.RevocationStrategyJTIRegistry,
	}, claims)
	if revoked || !ok {
		t.Fatalf("got revoked=%v ok=%v want false,true", revoked, ok)
	}
}
