package refreshchain_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/refreshchain"
	"github.com/libraz/go-oidc-provider/op/store"
)

func TestFindRootUsesStoredHandleResolverAfterPresentedCredential(t *testing.T) {
	t.Parallel()

	rootHandle := "stored-handle:root"
	midHandle := "stored-handle:mid"
	tokens := &recordingRefreshStore{
		byCredential: map[string]*store.RefreshToken{
			"presented-refresh-token": refresh("leaf", "client", ptr(midHandle)),
		},
		byHandle: map[string]*store.RefreshToken{
			midHandle:  refresh("mid", "client", ptr(rootHandle)),
			rootHandle: refresh("root", "client", nil),
		},
	}

	got, ok := refreshchain.FindRoot(context.Background(), tokens, "presented-refresh-token", 4)
	if !ok {
		t.Fatal("FindRoot reported no root for a valid chain")
	}
	if got != rootHandle {
		t.Fatalf("FindRoot root = %q, want %q", got, rootHandle)
	}
	if want := []string{"presented-refresh-token"}; !slices.Equal(tokens.findCalls, want) {
		t.Fatalf("Find calls = %v, want %v", tokens.findCalls, want)
	}
	if want := []string{midHandle, rootHandle}; !slices.Equal(tokens.handleCalls, want) {
		t.Fatalf("FindByStoredHandle calls = %v, want %v", tokens.handleCalls, want)
	}
}

func TestFindRootFallsBackToFindForRawParentPointerBackends(t *testing.T) {
	t.Parallel()

	rootID := "raw-root-token"
	tokens := &recordingRefreshStoreNoResolver{
		byCredential: map[string]*store.RefreshToken{
			"raw-leaf-token": refresh("leaf", "client", ptr(rootID)),
			rootID:           refresh("root", "client", nil),
		},
	}

	got, ok := refreshchain.FindRoot(context.Background(), tokens, "raw-leaf-token", 2)
	if !ok {
		t.Fatal("FindRoot reported no root for a valid raw-pointer chain")
	}
	if got != rootID {
		t.Fatalf("FindRoot root = %q, want %q", got, rootID)
	}
	if want := []string{"raw-leaf-token", rootID}; !slices.Equal(tokens.findCalls, want) {
		t.Fatalf("Find calls = %v, want %v", tokens.findCalls, want)
	}
}

func TestFindRootRejectsAmbiguousOrUnsafeChains(t *testing.T) {
	t.Parallel()

	t.Run("client changes across chain", func(t *testing.T) {
		t.Parallel()

		parent := "parent"
		tokens := &recordingRefreshStore{
			byCredential: map[string]*store.RefreshToken{
				"leaf": refresh("leaf", "client-a", ptr(parent)),
			},
			byHandle: map[string]*store.RefreshToken{
				parent: refresh("parent", "client-b", nil),
			},
		}

		if got, ok := refreshchain.FindRoot(context.Background(), tokens, "leaf", 2); ok || got != "" {
			t.Fatalf("FindRoot = (%q, %v), want empty/false for mixed-client chain", got, ok)
		}
	})

	t.Run("walk limit reached before root", func(t *testing.T) {
		t.Parallel()

		parent := "parent"
		root := "root"
		tokens := &recordingRefreshStore{
			byCredential: map[string]*store.RefreshToken{
				"leaf": refresh("leaf", "client", ptr(parent)),
			},
			byHandle: map[string]*store.RefreshToken{
				parent: refresh("parent", "client", ptr(root)),
				root:   refresh("root", "client", nil),
			},
		}

		if got, ok := refreshchain.FindRoot(context.Background(), tokens, "leaf", 2); ok || got != "" {
			t.Fatalf("FindRoot = (%q, %v), want empty/false when limit is exhausted", got, ok)
		}
	})

	t.Run("invalid inputs", func(t *testing.T) {
		t.Parallel()

		tokens := &recordingRefreshStore{}
		cases := []struct {
			name    string
			tokens  store.RefreshTokenStore
			startID string
			limit   int
		}{
			{name: "nil store", tokens: nil, startID: "leaf", limit: 1},
			{name: "empty start", tokens: tokens, startID: "", limit: 1},
			{name: "zero limit", tokens: tokens, startID: "leaf", limit: 0},
			{name: "negative limit", tokens: tokens, startID: "leaf", limit: -1},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				if got, ok := refreshchain.FindRoot(context.Background(), tc.tokens, tc.startID, tc.limit); ok || got != "" {
					t.Fatalf("FindRoot = (%q, %v), want empty/false", got, ok)
				}
			})
		}
	})
}

// A rotation chain loses its records oldest-first, whether to a
// scheduled sweep or to a backend that expires rows on their own TTL.
// The walk must stop at the boundary rather than abandon the cascade:
// every token still worth revoking hangs below it.
func TestFindRootStopsAtTheDeepestResolvableAncestor(t *testing.T) {
	t.Parallel()

	t.Run("reclaimed root", func(t *testing.T) {
		t.Parallel()

		parent, root := "parent", "root"
		tokens := &recordingRefreshStore{
			byCredential: map[string]*store.RefreshToken{
				"leaf": refresh("leaf", "client", ptr(parent)),
			},
			byHandle: map[string]*store.RefreshToken{
				// root is absent: the oldest record has been reclaimed.
				parent: refresh("parent", "client", ptr(root)),
			},
		}

		got, ok := refreshchain.FindRoot(context.Background(), tokens, "leaf", 8)
		if !ok {
			t.Fatal("FindRoot gave up because an ancestor was gone; the cascade would never run")
		}
		if got != parent {
			t.Fatalf("FindRoot = %q, want the deepest resolvable node %q", got, parent)
		}
	})

	t.Run("only the presented token survives", func(t *testing.T) {
		t.Parallel()

		parent := "parent"
		tokens := &recordingRefreshStore{
			byCredential: map[string]*store.RefreshToken{
				"leaf": refresh("leaf", "client", ptr(parent)),
			},
		}

		got, ok := refreshchain.FindRoot(context.Background(), tokens, "leaf", 8)
		if !ok || got != "leaf" {
			t.Fatalf("FindRoot = (%q, %v), want (\"leaf\", true)", got, ok)
		}
	})

	t.Run("presented token itself unresolvable", func(t *testing.T) {
		t.Parallel()

		// Nothing resolves, so there is no node to cascade from and the
		// walk must say so rather than invent one.
		tokens := &recordingRefreshStore{}

		if got, ok := refreshchain.FindRoot(context.Background(), tokens, "leaf", 8); ok || got != "" {
			t.Fatalf("FindRoot = (%q, %v), want empty/false", got, ok)
		}
	})

	t.Run("mixed client still fails past a reclaimed ancestor", func(t *testing.T) {
		t.Parallel()

		// A client mismatch is an untrustworthy pointer graph, not a
		// retention artefact, and following it could retire another
		// client's tokens. The fallback must not soften it.
		parent := "parent"
		tokens := &recordingRefreshStore{
			byCredential: map[string]*store.RefreshToken{
				"leaf": refresh("leaf", "client-a", ptr(parent)),
			},
			byHandle: map[string]*store.RefreshToken{
				parent: refresh("parent", "client-b", nil),
			},
		}

		if got, ok := refreshchain.FindRoot(context.Background(), tokens, "leaf", 8); ok || got != "" {
			t.Fatalf("FindRoot = (%q, %v), want empty/false for a mixed-client chain", got, ok)
		}
	})
}

func TestFindByHandleUsesStoredHandleResolver(t *testing.T) {
	t.Parallel()

	tokens := &recordingRefreshStore{
		byCredential: map[string]*store.RefreshToken{
			"leaked-digest": refresh("credential-path", "client", nil),
		},
		byHandle: map[string]*store.RefreshToken{
			"leaked-digest": refresh("handle-path", "client", nil),
		},
	}

	got, err := refreshchain.FindByHandle(context.Background(), tokens, "leaked-digest")
	if err != nil {
		t.Fatalf("FindByHandle returned error: %v", err)
	}
	if got.ID != "handle-path" {
		t.Fatalf("FindByHandle ID = %q, want handle-path", got.ID)
	}
	if len(tokens.findCalls) != 0 {
		t.Fatalf("FindByHandle called bearer Find with stored handle: %v", tokens.findCalls)
	}
	if want := []string{"leaked-digest"}; !slices.Equal(tokens.handleCalls, want) {
		t.Fatalf("FindByStoredHandle calls = %v, want %v", tokens.handleCalls, want)
	}
}

type recordingRefreshStore struct {
	byCredential map[string]*store.RefreshToken
	byHandle     map[string]*store.RefreshToken
	findCalls    []string
	handleCalls  []string
}

func (s *recordingRefreshStore) Save(context.Context, *store.RefreshToken) error {
	return errors.New("unexpected Save call")
}

func (s *recordingRefreshStore) Find(_ context.Context, id string) (*store.RefreshToken, error) {
	s.findCalls = append(s.findCalls, id)
	rec, ok := s.byCredential[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

func (s *recordingRefreshStore) Consume(context.Context, string) (*store.RefreshToken, error) {
	return nil, errors.New("unexpected Consume call")
}

func (s *recordingRefreshStore) RevokeChain(context.Context, string) error {
	return errors.New("unexpected RevokeChain call")
}

func (s *recordingRefreshStore) RevokeByGrant(context.Context, string) error {
	return errors.New("unexpected RevokeByGrant call")
}

func (s *recordingRefreshStore) FindByStoredHandle(_ context.Context, handle string) (*store.RefreshToken, error) {
	s.handleCalls = append(s.handleCalls, handle)
	rec, ok := s.byHandle[handle]
	if !ok {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

type recordingRefreshStoreNoResolver struct {
	byCredential map[string]*store.RefreshToken
	findCalls    []string
}

func (s *recordingRefreshStoreNoResolver) Save(context.Context, *store.RefreshToken) error {
	return errors.New("unexpected Save call")
}

func (s *recordingRefreshStoreNoResolver) Find(_ context.Context, id string) (*store.RefreshToken, error) {
	s.findCalls = append(s.findCalls, id)
	rec, ok := s.byCredential[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

func (s *recordingRefreshStoreNoResolver) Consume(context.Context, string) (*store.RefreshToken, error) {
	return nil, errors.New("unexpected Consume call")
}

func (s *recordingRefreshStoreNoResolver) RevokeChain(context.Context, string) error {
	return errors.New("unexpected RevokeChain call")
}

func (s *recordingRefreshStoreNoResolver) RevokeByGrant(context.Context, string) error {
	return errors.New("unexpected RevokeByGrant call")
}

func refresh(id, clientID string, parentID *string) *store.RefreshToken {
	return &store.RefreshToken{
		ID:       id,
		ClientID: clientID,
		ParentID: parentID,
	}
}

func ptr[T any](v T) *T {
	return &v
}
