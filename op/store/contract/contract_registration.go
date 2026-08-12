package contract

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// This file groups the contract sub-tests for the RFC 7591 / RFC 7592
// substores: InitialAccessTokenStore and RegistrationAccessTokenStore.
// They are split off from contract.go to keep the per-file size budget
// below 800 lines and to mirror the layout used by contract_session.go.

// --- InitialAccessTokenStore ------------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var iatCases = []subtest{
	{"PutGet", iatPutGet},
	{"PutDuplicate", iatPutDuplicate},
	{"GetByHashMissing", iatGetByHashMissing},
	{"GetByHashReturnsExpired", iatGetByHashReturnsExpired},
	{"IncrementUsesSequence", iatIncrementUsesSequence},
	{"IncrementUsesMissing", iatIncrementUsesMissing},
	{"IncrementUsesExceedsCap", iatIncrementUsesExceedsCap},
	{"Delete", iatDelete},
	{"DeleteMissing", iatDeleteMissing},
}

func iatPutGet(t *testing.T, f Factory) {
	b := f(t)
	s := requireIATStore(t, b.Store)
	ctx := context.Background()
	tok := newIAT(b.Now(), "iat-1", "hash-1")
	if err := s.Put(ctx, tok); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetByHash(ctx, "hash-1")
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.ID != "iat-1" {
		t.Fatalf("unexpected IAT: %+v", got)
	}
	if got.Tag != tok.Tag {
		t.Fatalf("Tag not round-tripped: %q want %q", got.Tag, tok.Tag)
	}
	if len(got.AllowedScopes) != len(tok.AllowedScopes) {
		t.Fatalf("AllowedScopes not round-tripped: %v want %v", got.AllowedScopes, tok.AllowedScopes)
	}
}

func iatPutDuplicate(t *testing.T, f Factory) {
	b := f(t)
	s := requireIATStore(t, b.Store)
	ctx := context.Background()
	tok := newIAT(b.Now(), "iat-dup", "hash-dup")
	if err := s.Put(ctx, tok); err != nil {
		t.Fatalf("Put: %v", err)
	}
	err := s.Put(ctx, tok)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate Put: want ErrAlreadyExists, got %v", err)
	}
}

func iatGetByHashMissing(t *testing.T, f Factory) {
	b := f(t)
	s := requireIATStore(t, b.Store)
	_, err := s.GetByHash(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetByHash missing: want ErrNotFound, got %v", err)
	}
}

// iatGetByHashReturnsExpired pins the deliberate exception to the
// expiry-gating convention the sibling substores follow: an IAT whose
// ExpiresAt has passed is still returned, and the library applies the
// gate. The registration endpoint answers a lapsed token differently
// from an unknown one — different message to the client, different
// audit event — so a backend that filters here leaves an operator
// unable to tell an expired credential from a forged one.
func iatGetByHashReturnsExpired(t *testing.T, f Factory) {
	b := f(t)
	s := requireIATStore(t, b.Store)
	ctx := context.Background()
	tok := newIAT(b.Now(), "iat-expired", "hash-expired")
	tok.ExpiresAt = b.Now().Add(-time.Hour)
	if err := s.Put(ctx, tok); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetByHash(ctx, "hash-expired")
	if err != nil {
		t.Fatalf("GetByHash on an expired IAT: want the record, got %v", err)
	}
	if got.ID != "iat-expired" {
		t.Fatalf("unexpected IAT: %+v", got)
	}
	if !got.ExpiresAt.Before(b.Now()) {
		t.Errorf("ExpiresAt=%v is not in the past; the caller's expiry gate would pass", got.ExpiresAt)
	}
}

func iatIncrementUsesSequence(t *testing.T, f Factory) {
	b := f(t)
	s := requireIATStore(t, b.Store)
	ctx := context.Background()
	tok := newIAT(b.Now(), "iat-seq", "hash-seq")
	tok.MaxUses = 3
	if err := s.Put(ctx, tok); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for want := 1; want <= 3; want++ {
		got, err := s.IncrementUses(ctx, "iat-seq")
		if err != nil {
			t.Fatalf("IncrementUses #%d: %v", want, err)
		}
		if got != want {
			t.Fatalf("IncrementUses returned %d, want %d", got, want)
		}
	}
}

func iatIncrementUsesMissing(t *testing.T, f Factory) {
	b := f(t)
	s := requireIATStore(t, b.Store)
	_, err := s.IncrementUses(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("IncrementUses missing: want ErrNotFound, got %v", err)
	}
}

func iatIncrementUsesExceedsCap(t *testing.T, f Factory) {
	b := f(t)
	s := requireIATStore(t, b.Store)
	ctx := context.Background()
	// MaxUses == 0 means single-use (1).
	tok := newIAT(b.Now(), "iat-cap", "hash-cap")
	tok.MaxUses = 0
	if err := s.Put(ctx, tok); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := s.IncrementUses(ctx, "iat-cap"); err != nil {
		t.Fatalf("first IncrementUses: %v", err)
	}
	_, err := s.IncrementUses(ctx, "iat-cap")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second IncrementUses: want ErrConflict, got %v", err)
	}
}

func iatDelete(t *testing.T, f Factory) {
	b := f(t)
	s := requireIATStore(t, b.Store)
	ctx := context.Background()
	tok := newIAT(b.Now(), "iat-del", "hash-del")
	if err := s.Put(ctx, tok); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, "iat-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.GetByHash(ctx, "hash-del"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetByHash after Delete: want ErrNotFound, got %v", err)
	}
}

func iatDeleteMissing(t *testing.T, f Factory) {
	b := f(t)
	s := requireIATStore(t, b.Store)
	err := s.Delete(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete missing: want ErrNotFound, got %v", err)
	}
}

// --- RegistrationAccessTokenStore -------------------------------------------

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var ratCases = []subtest{
	{"PutGet", ratPutGet},
	{"PutUpsert", ratPutUpsert},
	{"GetMissing", ratGetMissing},
	{"Delete", ratDelete},
	{"DeleteMissing", ratDeleteMissing},
}

func ratPutGet(t *testing.T, f Factory) {
	b := f(t)
	s := requireRATStore(t, b.Store)
	ctx := context.Background()
	tok := newRAT(b.Now(), "client-1", "hash-1")
	if err := s.Put(ctx, tok); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetByClientID(ctx, "client-1")
	if err != nil {
		t.Fatalf("GetByClientID: %v", err)
	}
	if got.ClientID != "client-1" || got.HashedValue != "hash-1" {
		t.Fatalf("unexpected RAT: %+v", got)
	}
	if !slices.Equal(got.AllowedScopes, tok.AllowedScopes) {
		t.Fatalf("AllowedScopes not round-tripped: %v want %v", got.AllowedScopes, tok.AllowedScopes)
	}
}

func ratPutUpsert(t *testing.T, f Factory) {
	b := f(t)
	s := requireRATStore(t, b.Store)
	ctx := context.Background()
	original := newRAT(b.Now(), "client-rotate", "hash-old")
	if err := s.Put(ctx, original); err != nil {
		t.Fatalf("Put original: %v", err)
	}
	rotated := newRAT(b.Now().Add(time.Minute), "client-rotate", "hash-new")
	if err := s.Put(ctx, rotated); err != nil {
		t.Fatalf("Put rotated: %v", err)
	}
	got, err := s.GetByClientID(ctx, "client-rotate")
	if err != nil {
		t.Fatalf("GetByClientID: %v", err)
	}
	if got.HashedValue != "hash-new" {
		t.Fatalf("Put did not upsert HashedValue: got %q", got.HashedValue)
	}
	if !got.CreatedAt.Equal(b.Now().Add(time.Minute)) {
		t.Fatalf("Put did not upsert CreatedAt: got %v", got.CreatedAt)
	}
}

func ratGetMissing(t *testing.T, f Factory) {
	b := f(t)
	s := requireRATStore(t, b.Store)
	_, err := s.GetByClientID(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetByClientID missing: want ErrNotFound, got %v", err)
	}
}

func ratDelete(t *testing.T, f Factory) {
	b := f(t)
	s := requireRATStore(t, b.Store)
	ctx := context.Background()
	tok := newRAT(b.Now(), "client-del", "hash-del")
	if err := s.Put(ctx, tok); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, "client-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.GetByClientID(ctx, "client-del"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetByClientID after Delete: want ErrNotFound, got %v", err)
	}
}

func ratDeleteMissing(t *testing.T, f Factory) {
	b := f(t)
	s := requireRATStore(t, b.Store)
	err := s.Delete(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete missing: want ErrNotFound, got %v", err)
	}
}

// --- helpers ----------------------------------------------------------------

// requireIATStore skips the current test when the backend does not expose an
// [store.InitialAccessTokenStore]. Backends that do not implement RFC 7591
// support are allowed to return nil from Store.InitialAccessTokens; the
// harness honours that opt-out the same way it honours
// [store.Transactional]'s.
func requireIATStore(t *testing.T, s store.Store) store.InitialAccessTokenStore {
	t.Helper()
	iats := s.InitialAccessTokens()
	if iats == nil {
		t.Skipf("backend %T does not expose InitialAccessTokenStore", s)
	}
	return iats
}

// requireRATStore is the [store.RegistrationAccessTokenStore] analogue of
// [requireIATStore].
func requireRATStore(t *testing.T, s store.Store) store.RegistrationAccessTokenStore {
	t.Helper()
	rats := s.RegistrationAccessTokens()
	if rats == nil {
		t.Skipf("backend %T does not expose RegistrationAccessTokenStore", s)
	}
	return rats
}

func newIAT(now time.Time, id, hash string) *store.InitialAccessToken {
	return &store.InitialAccessToken{
		ID:            id,
		HashedValue:   hash,
		MaxUses:       1,
		AllowedScopes: []string{"openid", "profile"},
		Tag:           "tenant-acme",
		ExpiresAt:     now.Add(24 * time.Hour),
		CreatedAt:     now,
	}
}

func newRAT(now time.Time, clientID, hash string) *store.RegistrationAccessToken {
	return &store.RegistrationAccessToken{
		ClientID:      clientID,
		HashedValue:   hash,
		AllowedScopes: []string{"openid", "profile"},
		CreatedAt:     now,
	}
}
