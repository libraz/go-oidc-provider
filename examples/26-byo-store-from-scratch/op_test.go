//go:build example

// op_test.go — self-verification for the op.New wiring in op.go.

package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestBuildProviderDoesNotWarnAboutUserStoreMismatch reproduces
// buildProvider's exact option list with a capturing logger attached.
// op.New warns whenever the login step's store and WithStore(...).Users()
// compare unequal with ==, and this example wires both to the same
// scratchStore.Users() value on purpose (see op.go) — so the warning must
// never fire. scratchStore.Users caches its substore across calls
// precisely so this holds; a version that allocated a fresh one per call
// would fail this test.
func TestBuildProviderDoesNotWarnAboutUserStoreMismatch(t *testing.T) {
	t.Parallel()

	storage, _ := newTestStore(t)

	keys := devkeys.MustEphemeral("byo-store-from-scratch-test")
	users, ok := storage.Users().(store.UserPasswordStore)
	if !ok {
		t.Fatal("scratch users substore does not implement store.UserPasswordStore")
	}
	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: users},
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	if _, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(storage),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		op.WithAccessTokenRevocationStrategy(op.RevocationStrategyNone),
		op.WithLogger(logger),
	); err != nil {
		t.Fatalf("op.New: %v", err)
	}

	if strings.Contains(logs.String(), "different user store") {
		t.Errorf("op.New warned about a user-store mismatch on a store correctly wired to itself:\n%s", logs.String())
	}
}
