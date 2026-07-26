package recoverykit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/recoverykit"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestReplace covers the two properties in one pass, deliberately.
// Each batch costs ten argon2id hashings at 64 MiB, so a test file
// that mints a fresh batch per assertion is a measurable share of the
// suite's memory and wall-clock budget — the parameters are meant to
// be expensive.
//
//   - The persisted half must carry only hashes. A generator that
//     wrote the plaintext through to storage would satisfy "ten codes
//     came back" and hand every future database reader a working set
//     of credentials.
//   - Replacement is wholesale. Appending would leave the printout the
//     user asked to invalidate still working, which is the failure
//     mode "regenerate my codes" exists to prevent.
//
// That the codes verify at all is pinned where the verifier lives; the
// argon2id parameters and the code alphabet are fixed there and are
// not reachable from here.
func TestReplace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	st := inmem.New()
	first, err := recoverykit.Replace(ctx, st.RecoveryCodes(), "sub-1")
	if err != nil {
		t.Fatalf("first Replace: %v", err)
	}
	if len(first.Codes) == 0 {
		t.Fatal("Replace returned no plaintext codes")
	}
	if len(first.Batch.Codes) != len(first.Codes) {
		t.Fatalf("batch has %d slots but %d codes were returned", len(first.Batch.Codes), len(first.Codes))
	}

	stored, err := st.RecoveryCodes().Get(ctx, "sub-1")
	if err != nil {
		t.Fatalf("Get persisted batch: %v", err)
	}
	for i, slot := range stored.Codes {
		if slot.Hash == "" {
			t.Fatalf("slot %d persisted with an empty hash", i)
		}
		if slot.Hash == first.Codes[i] {
			t.Fatalf("slot %d persisted the plaintext code verbatim", i)
		}
		if !strings.HasPrefix(slot.Hash, "$argon2id$") {
			t.Fatalf("slot %d hash is not an argon2id encoding: %q", i, slot.Hash)
		}
		if !slot.ConsumedAt.IsZero() {
			t.Fatalf("slot %d arrived already consumed", i)
		}
	}

	second, err := recoverykit.Replace(ctx, st.RecoveryCodes(), "sub-1")
	if err != nil {
		t.Fatalf("second Replace: %v", err)
	}
	stored, err = st.RecoveryCodes().Get(ctx, "sub-1")
	if err != nil {
		t.Fatalf("Get after replacement: %v", err)
	}
	if len(stored.Codes) != len(second.Batch.Codes) {
		t.Fatalf("stored batch has %d slots; the second batch had %d — the batches were merged",
			len(stored.Codes), len(second.Batch.Codes))
	}
	firstHashes := make(map[string]struct{}, len(first.Batch.Codes))
	for _, slot := range first.Batch.Codes {
		firstHashes[slot.Hash] = struct{}{}
	}
	for i, slot := range stored.Codes {
		if _, ok := firstHashes[slot.Hash]; ok {
			t.Fatalf("slot %d still carries a hash from the invalidated batch", i)
		}
	}
}

// TestGenerate_DoesNotTouchStorage pins the difference between the two
// entry points: Generate hands the batch back for the caller to write,
// so a caller staging it in its own transaction is not racing a write
// this package already did.
func TestGenerate_DoesNotTouchStorage(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	st := inmem.New()
	if _, err := recoverykit.Generate(ctx, "sub-1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := st.RecoveryCodes().Get(ctx, "sub-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after Generate: err=%v, want store.ErrNotFound; Generate persisted the batch", err)
	}
}

func TestRejectsMissingArguments(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	st := inmem.New()
	if _, err := recoverykit.Generate(ctx, ""); err == nil {
		t.Error("Generate accepted an empty subject")
	}
	if _, err := recoverykit.Replace(ctx, st.RecoveryCodes(), ""); err == nil {
		t.Error("Replace accepted an empty subject")
	}
	if _, err := recoverykit.Replace(ctx, nil, "sub-1"); err == nil {
		t.Error("Replace accepted a nil store")
	}
}
