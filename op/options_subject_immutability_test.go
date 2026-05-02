package op_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestSubjectModeGate_FreshStoreWritesPublicMarker confirms the gate
// records the default public mode on first construction so a later
// boot can detect a switch-to-pairwise that would orphan grants.
func TestSubjectModeGate_FreshStoreWritesPublicMarker(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	if _, err := op.New(validBaseOptsWithStore(t, st)...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
	got, err := st.Metadata().Get(context.Background(), store.SubjectModeKey)
	if err != nil {
		t.Fatalf("metadata Get: %v", err)
	}
	if got != store.SubjectModePublic {
		t.Errorf("marker=%q want %q", got, store.SubjectModePublic)
	}
}

// TestSubjectModeGate_FreshStoreWritesPairwiseMarker confirms the gate
// records the pairwise mode on first construction when the embedder
// supplies the pairwise option.
func TestSubjectModeGate_FreshStoreWritesPairwiseMarker(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	opts := append(validBaseOptsWithStore(t, st), op.WithPairwiseSubject(minSalt()))
	if _, err := op.New(opts...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
	got, err := st.Metadata().Get(context.Background(), store.SubjectModeKey)
	if err != nil {
		t.Fatalf("metadata Get: %v", err)
	}
	if got != store.SubjectModePairwise {
		t.Errorf("marker=%q want %q", got, store.SubjectModePairwise)
	}
}

// TestSubjectModeGate_RepeatBootSameModeAccepted confirms the gate is
// a no-op when the second construction reasserts the persisted mode.
func TestSubjectModeGate_RepeatBootSameModeAccepted(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	opts := validBaseOptsWithStore(t, st)
	if _, err := op.New(opts...); err != nil {
		t.Fatalf("first op.New: %v", err)
	}
	if _, err := op.New(opts...); err != nil {
		t.Fatalf("second op.New: %v", err)
	}
}

// TestSubjectModeGate_RejectsPublicToPairwiseWithMarker confirms the
// gate refuses a public→pairwise switch when the persisted marker is
// already public; the OP would otherwise reassign every issued sub.
func TestSubjectModeGate_RejectsPublicToPairwiseWithMarker(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	if _, err := op.New(validBaseOptsWithStore(t, st)...); err != nil {
		t.Fatalf("seed op.New: %v", err)
	}
	switchOpts := append(validBaseOptsWithStore(t, st), op.WithPairwiseSubject(minSalt()))
	_, err := op.New(switchOpts...)
	if !errors.Is(err, op.ErrSubjectModeMismatch) {
		t.Fatalf("op.New err=%v, want ErrSubjectModeMismatch", err)
	}
}

// TestSubjectModeGate_RejectsPairwiseToPublicWithMarker confirms the
// reverse direction (pairwise→public) is also blocked. Switching back
// would orphan every pairwise sub the OP previously issued.
func TestSubjectModeGate_RejectsPairwiseToPublicWithMarker(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	pwOpts := append(validBaseOptsWithStore(t, st), op.WithPairwiseSubject(minSalt()))
	if _, err := op.New(pwOpts...); err != nil {
		t.Fatalf("seed op.New: %v", err)
	}
	_, err := op.New(validBaseOptsWithStore(t, st)...)
	if !errors.Is(err, op.ErrSubjectModeMismatch) {
		t.Fatalf("op.New err=%v, want ErrSubjectModeMismatch", err)
	}
}

// TestSubjectModeGate_LegacyUpgradeRejectsNonPublic confirms the gate
// infers public mode when a populated grant store carries no marker
// (the v0.9.0 → v0.9.1 upgrade path) and refuses any non-public
// construction against it.
func TestSubjectModeGate_LegacyUpgradeRejectsNonPublic(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	now := time.Now().UTC()
	if err := st.Grants().Save(context.Background(), &store.Grant{
		ID:        "g-legacy-1",
		Subject:   "user-1",
		ClientID:  "client-1",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	pwOpts := append(validBaseOptsWithStore(t, st), op.WithPairwiseSubject(minSalt()))
	_, err := op.New(pwOpts...)
	if !errors.Is(err, op.ErrSubjectModeMismatch) {
		t.Fatalf("op.New err=%v, want ErrSubjectModeMismatch (legacy upgrade)", err)
	}
}

// TestSubjectModeGate_LegacyUpgradeAcceptsPublic confirms the legacy
// inference admits a public construction without further setup; the
// gate writes the marker on the way through so subsequent boots are
// strict.
func TestSubjectModeGate_LegacyUpgradeAcceptsPublic(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	now := time.Now().UTC()
	if err := st.Grants().Save(context.Background(), &store.Grant{
		ID:        "g-legacy-2",
		Subject:   "user-2",
		ClientID:  "client-2",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	if _, err := op.New(validBaseOptsWithStore(t, st)...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
	got, err := st.Metadata().Get(context.Background(), store.SubjectModeKey)
	if err != nil {
		t.Fatalf("metadata Get: %v", err)
	}
	if got != store.SubjectModePublic {
		t.Errorf("marker=%q want %q", got, store.SubjectModePublic)
	}
}
