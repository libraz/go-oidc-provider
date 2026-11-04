package op_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// lockoutlessStore hides the AuthnLockouts accessor of the embedded store.
type lockoutlessStore struct {
	store.Store
	store.Transactional
}

// TestNew_RequiresAuthnLockoutStore pins that a password step with no
// resolvable lockout store fails construction, and that an explicit
// WithAuthnLockoutStore or a store implementing AuthnLockoutProvider
// satisfies it.
func TestNew_RequiresAuthnLockoutStore(t *testing.T) {
	t.Parallel()

	inner := inmem.New()
	flow := op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{Store: inner.UserPasswords()}})
	base := func(st store.Store) []op.Option {
		return []op.Option{op.WithDefaults(
			op.WithIssuer(validIssuer),
			op.WithStore(st),
			op.WithKeyset(validKeyset(t)),
			op.WithCookieKeys(newRandomCookieKey(t)),
		), flow}
	}

	if _, ok := store.Store(lockoutlessStore{Store: inner, Transactional: inner}).(store.AuthnLockoutProvider); ok {
		t.Fatal("lockoutlessStore must not implement AuthnLockoutProvider")
	}

	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		_, err := op.New(base(lockoutlessStore{Store: inner, Transactional: inner})...)
		if !errors.Is(err, op.ErrAuthnLockoutStoreRequired) {
			t.Fatalf("err = %v, want ErrAuthnLockoutStoreRequired", err)
		}
		if !op.IsServerError(err) {
			t.Fatalf("err = %v, want a configuration error", err)
		}
	})
	t.Run("explicit store", func(t *testing.T) {
		t.Parallel()
		opts := append(base(lockoutlessStore{Store: inner, Transactional: inner}), op.WithAuthnLockoutStore(inner.AuthnLockouts()))
		if _, err := op.New(opts...); err != nil {
			t.Fatalf("op.New: %v", err)
		}
	})
	t.Run("provider store", func(t *testing.T) {
		t.Parallel()
		if _, err := op.New(base(inner)...); err != nil {
			t.Fatalf("op.New: %v", err)
		}
	})
}

// TestNew_RequiresLoginFlow pins the sentinel behind the missing-LoginFlow
// construction error.
func TestNew_RequiresLoginFlow(t *testing.T) {
	t.Parallel()

	_, err := op.New(validBaseOptsNoAuthn(t)...)
	if !errors.Is(err, op.ErrLoginFlowRequired) {
		t.Fatalf("err = %v, want ErrLoginFlowRequired", err)
	}
}

// TestNew_WarnsOnDevAndNoopOptions pins the start-up warnings for
// WithFeature(feature.PKCE) and WithAllowLocalhostRedirectURIs.
func TestNew_WarnsOnDevAndNoopOptions(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		opt  op.Option
		msg  string
	}{
		{"pkce feature", op.WithFeature(feature.PKCE), "WithFeature(feature.PKCE) has no effect"},
		{"localhost redirect uris", op.WithAllowLocalhostRedirectURIs(), "WithAllowLocalhostRedirectURIs admits the textual"},
	} {
		for _, on := range []bool{true, false} {
			name := tc.name + " absent"
			if on {
				name = tc.name + " present"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				var buf bytes.Buffer
				opts := append(validBaseOptsWithInmem(t), op.WithLogger(slog.New(slog.NewJSONHandler(&buf, nil))))
				if on {
					opts = append(opts, tc.opt)
				}
				if _, err := op.New(opts...); err != nil {
					t.Fatalf("op.New: %v", err)
				}
				var found bool
				for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
					var rec map[string]any
					if json.Unmarshal(line, &rec) != nil {
						continue
					}
					if msg, _ := rec["msg"].(string); strings.Contains(msg, tc.msg) {
						found = true
						if rec["level"] != "WARN" {
							t.Fatalf("level = %v, want WARN", rec["level"])
						}
					}
				}
				if found != on {
					t.Fatalf("warning present = %v, want %v; log:\n%s", found, on, buf.String())
				}
			})
		}
	}
}
