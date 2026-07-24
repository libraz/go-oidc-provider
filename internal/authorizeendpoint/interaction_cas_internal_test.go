package authorizeendpoint

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func TestPersistAuthnState_CannotOverwriteCompletionOrRecreateDeletedRow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	backing := inmem.New()
	interactions := backing.Interactions()
	initialState := authorize.RequestState{
		Library: authorize.RequestSnapshot{
			ClientID:     "client-1",
			ResponseType: "code",
			RedirectURI:  "https://rp.example.com/cb",
		},
	}
	initialRaw, err := authorize.MarshalState(initialState)
	if err != nil {
		t.Fatalf("MarshalState initial: %v", err)
	}
	stale := &store.Interaction{
		ID:        "interaction-cas",
		ClientID:  "client-1",
		Step:      "auth.password",
		RawState:  initialRaw,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := interactions.Save(context.Background(), stale); err != nil {
		t.Fatalf("Save: %v", err)
	}
	completionState := initialState
	completionState.Completion = &authorize.CompletionIntent{
		Version: 1,
		CodeID:  "stable-code",
		Subject: "user-1",
	}
	completionRaw, err := authorize.MarshalState(completionState)
	if err != nil {
		t.Fatalf("MarshalState completion: %v", err)
	}
	completed := *stale
	completed.RawState = completionRaw
	completed.UpdatedAt = now.Add(time.Second)
	cas := interactions.(store.InteractionStoreCAS)
	if err := cas.CompareAndSwap(context.Background(), stale, &completed); err != nil {
		t.Fatalf("claim completion: %v", err)
	}

	current, currentState, err := persistAuthnState(
		context.Background(),
		resolved{Deps: Deps{Interactions: interactions}},
		stale,
		initialState,
		authn.State{},
		"auth.totp",
		now.Add(2*time.Second),
	)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale persist error=%v want ErrConflict", err)
	}
	if current == nil || currentState.Completion == nil ||
		currentState.Completion.CodeID != "stable-code" {
		t.Fatalf("stale persist did not return immutable completion: rec=%+v state=%+v",
			current, currentState)
	}
	stored, err := interactions.Find(context.Background(), stale.ID)
	if err != nil {
		t.Fatalf("Find after stale persist: %v", err)
	}
	storedState, err := authorize.UnmarshalState(stored.RawState)
	if err != nil {
		t.Fatalf("UnmarshalState stored: %v", err)
	}
	if storedState.Completion == nil || storedState.Completion.CodeID != "stable-code" {
		t.Fatalf("stale persist overwrote completion: %+v", storedState.Completion)
	}

	if err := cas.DeleteIfUnchanged(context.Background(), stored); err != nil {
		t.Fatalf("DeleteIfUnchanged: %v", err)
	}
	if _, _, err := persistAuthnState(
		context.Background(),
		resolved{Deps: Deps{Interactions: interactions}},
		stale,
		initialState,
		authn.State{},
		"auth.totp",
		now.Add(3*time.Second),
	); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("persist after delete error=%v want ErrNotFound", err)
	}
	if _, err := interactions.Find(context.Background(), stale.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stale persist recreated deleted interaction: %v", err)
	}
}
