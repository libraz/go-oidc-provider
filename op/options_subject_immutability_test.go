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

// TestSubjectModeGate_FreshStoreWritesOpInitMarker pins the sentinel
// the gate stamps alongside [store.SubjectModeKey] on every successful
// construction. The sentinel is the empty-store edge case defence: a
// later boot whose [store.SubjectModeKey] row was wiped (deliberately
// or by truncation) reads the sentinel back and refuses any non-public
// construction even when no grants remain.
func TestSubjectModeGate_FreshStoreWritesOpInitMarker(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	if _, err := op.New(validBaseOptsWithStore(t, st)...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
	got, err := st.Metadata().Get(context.Background(), store.OpInitKey)
	if err != nil {
		t.Fatalf("metadata Get OpInitKey: %v", err)
	}
	if got != store.OpInitMarker {
		t.Errorf("op-init marker=%q want %q", got, store.OpInitMarker)
	}
}

// TestSubjectModeGate_RejectsSwitchOnUsedStoreWithWipedMarker pins the
// empty-store edge case. A previously-used store whose subject_mode
// row was wiped (truncation, deliberate manipulation, or a tooling
// bug) but whose op-init sentinel survives MUST still reject a
// non-public construction. Without the sentinel probe the gate would
// fall through to the "fresh install" branch and silently re-key
// every future "sub". The test seeds the [store.OpInitKey] sentinel
// directly to simulate the post-wipe state because no public API
// exposes a metadata-only truncation.
func TestSubjectModeGate_RejectsSwitchOnUsedStoreWithWipedMarker(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	// Stamp the op-init sentinel as a previous OP boot would have,
	// but leave [store.SubjectModeKey] absent — this is the wiped /
	// truncated-but-not-empty shape the gate defends against.
	if err := st.Metadata().Set(context.Background(), store.OpInitKey, store.OpInitMarker); err != nil {
		t.Fatalf("seed op-init sentinel: %v", err)
	}
	pwOpts := append(validBaseOptsWithStore(t, st), op.WithPairwiseSubject(minSalt()))
	_, err := op.New(pwOpts...)
	if !errors.Is(err, op.ErrSubjectModeMismatch) {
		t.Fatalf("op.New err=%v, want ErrSubjectModeMismatch (wiped marker on used store)", err)
	}
}

// TestSubjectModeGate_RejectsCustomGenOnUsedStoreWithWipedMarker pins
// the same defence for the WithSubjectGenerator branch: a re-used
// store where [store.SubjectModeKey] was wiped but the op-init
// sentinel survives MUST refuse a custom-generator construction too,
// because the new generator could re-key every future "sub" against
// a different algorithm.
func TestSubjectModeGate_RejectsCustomGenOnUsedStoreWithWipedMarker(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	if err := st.Metadata().Set(context.Background(), store.OpInitKey, store.OpInitMarker); err != nil {
		t.Fatalf("seed op-init sentinel: %v", err)
	}
	customOpts := append(validBaseOptsWithStore(t, st), op.WithSubjectGenerator(passthroughGenerator{}))
	_, err := op.New(customOpts...)
	if !errors.Is(err, op.ErrSubjectModeMismatch) {
		t.Fatalf("op.New err=%v, want ErrSubjectModeMismatch (wiped marker on used store, custom gen)", err)
	}
}

// TestSubjectModeGate_AcceptsPublicOnUsedStoreWithWipedMarker pins
// the converse: the empty-store edge case admits a public
// construction even when the op-init sentinel is present and
// [store.SubjectModeKey] is absent. Public-on-public is the only
// transition that cannot reassign existing subs, so the gate writes
// the marker through and accepts.
func TestSubjectModeGate_AcceptsPublicOnUsedStoreWithWipedMarker(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	if err := st.Metadata().Set(context.Background(), store.OpInitKey, store.OpInitMarker); err != nil {
		t.Fatalf("seed op-init sentinel: %v", err)
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

// passthroughGenerator is a SubjectGenerator that returns the input
// InternalUserID verbatim. The test only needs it to exercise the
// WithSubjectGenerator path of the gate; the generator's behaviour
// is irrelevant because op.New rejects construction before issuance.
type passthroughGenerator struct{}

// Generate implements [op.SubjectGenerator].
func (passthroughGenerator) Generate(_ context.Context, in op.SubjectGeneratorInput) (op.Subject, error) {
	return op.Subject(in.InternalUserID), nil
}
