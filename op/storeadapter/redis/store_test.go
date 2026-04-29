//nolint:testpackage // tests exercise unexported config and key helpers.
package oidcredis

import (
	"context"
	"strings"
	"testing"
)

func TestNew_RejectsMissingDSN(t *testing.T) {
	t.Parallel()
	_, err := New(context.Background())
	if err == nil || !strings.Contains(err.Error(), "WithDSN is required") {
		t.Fatalf("want WithDSN-required error, got %v", err)
	}
}

func TestNew_RejectsPlaintextDSN(t *testing.T) {
	t.Parallel()
	_, err := New(context.Background(),
		WithDSN("redis://localhost:6379/0"),
		WithRedisAuth("", "secret"),
	)
	if err == nil || !strings.Contains(err.Error(), "rediss://") {
		t.Fatalf("want TLS-required error, got %v", err)
	}
}

func TestNew_RejectsMissingAuth(t *testing.T) {
	t.Parallel()
	// rediss scheme without WithRedisAuth and without dev-mode is
	// rejected before any network I/O.
	_, err := New(context.Background(), WithDSN("rediss://localhost:6379/0"))
	if err == nil || !strings.Contains(err.Error(), "WithRedisAuth is required") {
		t.Fatalf("want WithRedisAuth-required error, got %v", err)
	}
}

func TestNew_RejectsUnknownScheme(t *testing.T) {
	t.Parallel()
	_, err := New(context.Background(),
		WithDSN("memcached://localhost:11211"),
		WithRedisAuth("", "secret"),
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported DSN scheme") {
		t.Fatalf("want unsupported-scheme error, got %v", err)
	}
}

func TestValidateScheme(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		scheme  string
		dev     bool
		wantErr string
	}{
		{"rediss accepted", "rediss", false, ""},
		{"rediss accepted in dev", "rediss", true, ""},
		{"plain rejected", "redis", false, "must be rediss"},
		{"plain accepted in dev", "redis", true, ""},
		{"unknown rejected", "ftp", false, "unsupported DSN scheme"},
		{"unknown rejected in dev", "ftp", true, "unsupported DSN scheme"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateScheme(tc.scheme, tc.dev)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want nil error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestStore_StubAccessorsPanic(t *testing.T) {
	t.Parallel()
	// We cannot invoke New successfully without a live redis, so we
	// exercise the panic path by constructing a Store value directly.
	// The panicking accessors do not touch s.client and so are
	// callable on a zero-initialised Store.
	s := &Store{prefix: DefaultKeyPrefix}

	cases := []struct {
		name string
		fn   func()
	}{
		{"Clients", func() { s.Clients() }},
		{"AuthorizationCodes", func() { s.AuthorizationCodes() }},
		{"RefreshTokens", func() { s.RefreshTokens() }},
		{"Grants", func() { s.Grants() }},
		{"PushedAuthRequests", func() { s.PushedAuthRequests() }},
		{"Users", func() { s.Users() }},
		{"AccessTokens", func() { s.AccessTokens() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("%s: want panic, got none", tc.name)
				}
				msg, ok := r.(string)
				if !ok || !strings.Contains(msg, tc.name) {
					t.Fatalf("%s: panic message missing kind name: %v", tc.name, r)
				}
			}()
			tc.fn()
		})
	}
}

func TestStore_NilStubsForRegistration(t *testing.T) {
	t.Parallel()
	s := &Store{prefix: DefaultKeyPrefix}
	if s.InitialAccessTokens() != nil {
		t.Fatalf("InitialAccessTokens: want nil, got non-nil")
	}
	if s.RegistrationAccessTokens() != nil {
		t.Fatalf("RegistrationAccessTokens: want nil, got non-nil")
	}
}

func TestJTIKey_DeterministicAndPrefixed(t *testing.T) {
	t.Parallel()
	s := &Store{prefix: DefaultKeyPrefix}
	j := newJTIStore(s)
	a := j.jtiKey("jti-foo")
	b := j.jtiKey("jti-foo")
	if a != b {
		t.Fatalf("key derivation not deterministic: %s vs %s", a, b)
	}
	if !strings.HasPrefix(a, DefaultKeyPrefix+"jti:") {
		t.Fatalf("key %q missing prefix %q", a, DefaultKeyPrefix+"jti:")
	}
	c := j.jtiKey("jti-bar")
	if a == c {
		t.Fatalf("distinct jtis hashed to identical keys")
	}
}

func TestInteractionKey_PrefixedWithPlainID(t *testing.T) {
	t.Parallel()
	s := &Store{prefix: "myprefix:"}
	i := newInteractionStore(s)
	got := i.interactionKey("inter-1")
	want := "myprefix:interaction:inter-1"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWithMaxValueBytes_ClampedToReasonableRange(t *testing.T) {
	t.Parallel()
	cfg := &config{maxValueBytes: MaxValueBytes}
	WithMaxValueBytes(512)(cfg) // below 1 KiB floor
	if cfg.maxValueBytes != MaxValueBytes {
		t.Fatalf("below-floor value accepted: %d", cfg.maxValueBytes)
	}
	WithMaxValueBytes(2 * 1024 * 1024)(cfg) // above 1 MiB ceiling
	if cfg.maxValueBytes != MaxValueBytes {
		t.Fatalf("above-ceiling value accepted: %d", cfg.maxValueBytes)
	}
	WithMaxValueBytes(8192)(cfg)
	if cfg.maxValueBytes != 8192 {
		t.Fatalf("in-range value rejected: %d", cfg.maxValueBytes)
	}
}
