package subject_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/subject"
)

func TestUUIDv7_PassesInternalUserIDThrough(t *testing.T) {
	t.Parallel()
	g := subject.UUIDv7()
	out, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "user-42",
		Client:         &store.Client{ID: "client-a"},
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if out != "user-42" {
		t.Fatalf("Generate returned %q, want user-42", out)
	}
}

func TestUUIDv7_FederatedReturnsExternalID(t *testing.T) {
	t.Parallel()
	g := subject.UUIDv7()
	out, err := g.Generate(context.Background(), subject.GeneratorInput{
		Federated: subject.FederatedSubject{Provider: "google", ExternalID: "google-uid-123"},
		Client:    &store.Client{ID: "client-a"},
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if out != "google-uid-123" {
		t.Fatalf("Generate returned %q, want google-uid-123", out)
	}
}

func TestUUIDv7_EmptyInputReturnsError(t *testing.T) {
	t.Parallel()
	g := subject.UUIDv7()
	_, err := g.Generate(context.Background(), subject.GeneratorInput{
		Client: &store.Client{ID: "client-a"},
	})
	if !errors.Is(err, subject.ErrInputEmpty) {
		t.Fatalf("Generate err = %v, want %v", err, subject.ErrInputEmpty)
	}
}

func TestUUIDv7_BothSetReturnsError(t *testing.T) {
	t.Parallel()
	g := subject.UUIDv7()
	_, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: "user-1",
		Federated:      subject.FederatedSubject{Provider: "google", ExternalID: "google-1"},
		Client:         &store.Client{ID: "client-a"},
	})
	if !errors.Is(err, subject.ErrInputBothSet) {
		t.Fatalf("Generate err = %v, want %v", err, subject.ErrInputBothSet)
	}
}

func TestUUIDv7_DeterministicAcrossCalls(t *testing.T) {
	t.Parallel()
	g := subject.UUIDv7()
	const userID = "user-determinism-check"
	first, err := g.Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: userID,
		Client:         &store.Client{ID: "c"},
	})
	if err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	for i := range 100 {
		out, err := g.Generate(context.Background(), subject.GeneratorInput{
			InternalUserID: userID,
			Client:         &store.Client{ID: "c"},
		})
		if err != nil {
			t.Fatalf("iter %d Generate: %v", i, err)
		}
		if out != first {
			t.Fatalf("iter %d returned %q, want %q", i, out, first)
		}
	}
}
