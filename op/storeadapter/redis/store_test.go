//nolint:testpackage // tests exercise unexported config and key helpers.
package oidcredis

import (
	"context"
	"reflect"
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

// TestStore_OutOfScopeAccessorsReturnNil pins the rule that every
// out-of-scope substore accessor returns nil (not a typed-nil
// wrapper, not a panic). Returning nil lets op.New surface a
// fail-fast configuration error instead of crashing the process on
// the first request that touches the missing substore.
func TestStore_OutOfScopeAccessorsReturnNil(t *testing.T) {
	t.Parallel()
	s := &Store{prefix: DefaultKeyPrefix}

	cases := []struct {
		name string
		got  any
	}{
		{"Clients", s.Clients()},
		{"AuthorizationCodes", s.AuthorizationCodes()},
		{"RefreshTokens", s.RefreshTokens()},
		{"Grants", s.Grants()},
		{"DeviceCodes", s.DeviceCodes()},
		{"CIBARequests", s.CIBARequests()},
		{"PushedAuthRequests", s.PushedAuthRequests()},
		{"Users", s.Users()},
		{"AccessTokens", s.AccessTokens()},
		{"InitialAccessTokens", s.InitialAccessTokens()},
		{"RegistrationAccessTokens", s.RegistrationAccessTokens()},
		{"OpaqueAccessTokens", s.OpaqueAccessTokens()},
		{"GrantRevocations", s.GrantRevocations()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got == nil {
				return
			}
			rv := reflect.ValueOf(tc.got)
			switch rv.Kind() {
			case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
				if !rv.IsNil() {
					t.Fatalf("%s: want nil substore, got %T", tc.name, tc.got)
				}
			default:
				t.Fatalf("%s: want nil substore, got %T", tc.name, tc.got)
			}
		})
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

func TestWithMaxValueBytes_RejectsOutOfRange(t *testing.T) {
	t.Parallel()
	cfg := buildConfig(nil)
	WithMaxValueBytes(512)(cfg) // below 1 KiB floor
	if cfg.optionErr == nil || !strings.Contains(cfg.optionErr.Error(), "WithMaxValueBytes") {
		t.Fatalf("below-floor value error=%v, want validation error", cfg.optionErr)
	}
	cfg = buildConfig(nil)
	WithMaxValueBytes(2 * 1024 * 1024)(cfg) // above 1 MiB ceiling
	if cfg.optionErr == nil || !strings.Contains(cfg.optionErr.Error(), "WithMaxValueBytes") {
		t.Fatalf("above-ceiling value error=%v, want validation error", cfg.optionErr)
	}
	cfg = buildConfig(nil)
	WithMaxValueBytes(8192)(cfg)
	if cfg.optionErr != nil || cfg.maxValueBytes != 8192 {
		t.Fatalf("in-range value rejected: %d", cfg.maxValueBytes)
	}
}

func TestWithKeyPrefix_Validation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		prefix string
		valid  bool
	}{
		{prefix: "tenant:", valid: true},
		{prefix: "tenant-prod_1:", valid: true},
		{prefix: "", valid: false},
		{prefix: "tenant", valid: false},
		{prefix: "tenant space:", valid: false},
	} {
		cfg := buildConfig(nil)
		WithKeyPrefix(tc.prefix)(cfg)
		if (cfg.optionErr == nil) != tc.valid {
			t.Errorf("prefix %q optionErr=%v, valid=%v", tc.prefix, cfg.optionErr, tc.valid)
		}
	}
}

func TestNew_RejectsInvalidOptionBeforeNetwork(t *testing.T) {
	t.Parallel()
	_, err := New(context.Background(),
		WithDSN("rediss://localhost:6379/0"),
		WithRedisAuth("", "secret"),
		WithMaxValueBytes(1),
	)
	if err == nil || !strings.Contains(err.Error(), "WithMaxValueBytes") {
		t.Fatalf("New invalid option error=%v, want WithMaxValueBytes validation error", err)
	}
}
