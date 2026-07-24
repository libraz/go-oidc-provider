package inmem_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func newPasskeyRecord(credentialID []byte, subject string) *store.PasskeyRecord {
	return &store.PasskeyRecord{
		CredentialID:    bytes.Clone(credentialID),
		Subject:         subject,
		PublicKey:       []byte{0xaa, 0xbb, 0xcc, 0xdd},
		AAGUID:          bytes.Repeat([]byte{0x01}, 16),
		SignCount:       1,
		AttestationType: "none",
		Transports:      []string{"usb", "internal"},
		UserPresent:     true,
		UserVerified:    true,
		BackupEligible:  true,
		BackupState:     false,
		CloneWarning:    false,
		Attachment:      "platform",
		CreatedAt:       time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	}
}

func TestPasskeyStoreContract(t *testing.T) {
	t.Parallel()
	contract.RunPasskeys(t, func(*testing.T) store.PasskeyStore {
		return inmem.New().Passkeys()
	})
}

func TestPasskeyStore_PutGetRoundTrip(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ps := s.Passkeys()
	ctx := context.Background()

	rec := newPasskeyRecord([]byte{0x01, 0x02, 0x03}, "user-alice")
	if err := ps.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := ps.Get(ctx, []byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.CredentialID, rec.CredentialID) {
		t.Errorf("CredentialID=%x want %x", got.CredentialID, rec.CredentialID)
	}
	if got.Subject != rec.Subject {
		t.Errorf("Subject=%q want %q", got.Subject, rec.Subject)
	}
	if !bytes.Equal(got.PublicKey, rec.PublicKey) {
		t.Errorf("PublicKey mismatch")
	}
	if got.SignCount != rec.SignCount {
		t.Errorf("SignCount=%d want %d", got.SignCount, rec.SignCount)
	}
}

func TestPasskeyStore_GetNotFound(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	if _, err := s.Passkeys().Get(context.Background(), []byte{0xff}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err=%v want ErrNotFound", err)
	}
}

func TestPasskeyStore_PutOverwrites(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ps := s.Passkeys()
	ctx := context.Background()

	first := newPasskeyRecord([]byte{0x01}, "user-alice")
	if err := ps.Put(ctx, first); err != nil {
		t.Fatalf("Put first: %v", err)
	}

	second := newPasskeyRecord([]byte{0x01}, "user-alice")
	second.SignCount = 99
	second.CloneWarning = true
	if err := ps.Put(ctx, second); err != nil {
		t.Fatalf("Put second: %v", err)
	}

	got, err := ps.Get(ctx, []byte{0x01})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SignCount != 99 {
		t.Errorf("SignCount=%d want 99 (overwrite did not stick)", got.SignCount)
	}
	if !got.CloneWarning {
		t.Errorf("CloneWarning=false want true")
	}
}

func TestPasskeyStore_ListBySubject(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ps := s.Passkeys()
	ctx := context.Background()

	if err := ps.Put(ctx, newPasskeyRecord([]byte{0x01}, "user-alice")); err != nil {
		t.Fatalf("Put alice-1: %v", err)
	}
	if err := ps.Put(ctx, newPasskeyRecord([]byte{0x02}, "user-alice")); err != nil {
		t.Fatalf("Put alice-2: %v", err)
	}
	if err := ps.Put(ctx, newPasskeyRecord([]byte{0x03}, "user-bob")); err != nil {
		t.Fatalf("Put bob: %v", err)
	}

	got, err := ps.ListBySubject(ctx, "user-alice")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len(got)=%d want 2", len(got))
	}
	for _, r := range got {
		if r.Subject != "user-alice" {
			t.Errorf("found Subject=%q want user-alice", r.Subject)
		}
	}
}

func TestPasskeyStore_ListBySubjectEmptyReturnsNonNilSlice(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	got, err := s.Passkeys().ListBySubject(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if got == nil {
		t.Error("got=nil want empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len(got)=%d want 0", len(got))
	}
}

func TestPasskeyStore_DeleteRemovesRecord(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ps := s.Passkeys()
	ctx := context.Background()

	rec := newPasskeyRecord([]byte{0x01}, "user-alice")
	if err := ps.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := ps.Delete(ctx, []byte{0x01}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := ps.Get(ctx, []byte{0x01}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get after Delete: err=%v want ErrNotFound", err)
	}
}

func TestPasskeyStore_DeleteMissingReturnsNotFound(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	if err := s.Passkeys().Delete(context.Background(), []byte{0xff}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err=%v want ErrNotFound", err)
	}
}

func TestPasskeyStore_PutNilRejected(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	if err := s.Passkeys().Put(context.Background(), nil); err == nil {
		t.Error("Put(nil) returned nil error")
	}
}

func TestPasskeyStore_PutEmptyCredentialIDRejected(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	rec := newPasskeyRecord(nil, "user-alice")
	rec.CredentialID = nil
	if err := s.Passkeys().Put(context.Background(), rec); err == nil {
		t.Error("Put with empty CredentialID returned nil error")
	}
}

func TestPasskeyStore_GetClonesRecord(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ps := s.Passkeys()
	ctx := context.Background()

	rec := newPasskeyRecord([]byte{0x01, 0x02}, "user-alice")
	if err := ps.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := ps.Get(ctx, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Mutating the returned record MUST NOT bleed into the store.
	got.PublicKey[0] ^= 0xff
	got.AAGUID[0] ^= 0xff
	got.Transports[0] = "ble"
	got.SignCount = 999

	again, err := ps.Get(ctx, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("Get again: %v", err)
	}
	if again.PublicKey[0] == got.PublicKey[0] {
		t.Errorf("PublicKey shared backing array between Get calls")
	}
	if again.AAGUID[0] == got.AAGUID[0] {
		t.Errorf("AAGUID shared backing array between Get calls")
	}
	if again.Transports[0] == got.Transports[0] {
		t.Errorf("Transports shared backing array between Get calls")
	}
	if again.SignCount == 999 {
		t.Errorf("SignCount mutation leaked into store")
	}
}

func TestPasskeyStore_PutClonesRecord(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ps := s.Passkeys()
	ctx := context.Background()

	rec := newPasskeyRecord([]byte{0x01}, "user-alice")
	if err := ps.Put(ctx, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Mutate the original after Put — the store MUST hold an
	// independent copy.
	rec.PublicKey[0] ^= 0xff
	rec.Transports[0] = "ble"

	got, err := ps.Get(ctx, []byte{0x01})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PublicKey[0] == rec.PublicKey[0] {
		t.Errorf("post-Put PublicKey mutation leaked into store")
	}
	if got.Transports[0] == rec.Transports[0] {
		t.Errorf("post-Put Transports mutation leaked into store")
	}
}

func TestPasskeyStore_ListBySubjectClonesRecords(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	ps := s.Passkeys()
	ctx := context.Background()

	if err := ps.Put(ctx, newPasskeyRecord([]byte{0x01}, "user-alice")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := ps.ListBySubject(ctx, "user-alice")
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got)=%d want 1", len(got))
	}
	got[0].PublicKey[0] ^= 0xff

	again, err := ps.ListBySubject(ctx, "user-alice")
	if err != nil {
		t.Fatalf("ListBySubject again: %v", err)
	}
	if again[0].PublicKey[0] == got[0].PublicKey[0] {
		t.Errorf("ListBySubject did not clone PublicKey")
	}
}
