//nolint:testpackage // tests exercise unexported config and key helpers.
package oidcredis

import (
	"context"
	"errors"
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

func TestNew_InvalidDSNDoesNotDiscloseCredentials(t *testing.T) {
	t.Parallel()
	const dsn = "rediss://sensitive-user:percent%ZZsecret@localhost:6379/0" //nolint:gosec // synthetic credential verifies redaction.
	_, err := New(context.Background(),
		WithDSN(dsn),
		WithRedisAuth("sensitive-user", "percent%ZZsecret"),
	)
	if err == nil {
		t.Fatal("want invalid-DSN error")
	}
	for _, secret := range []string{dsn, "sensitive-user", "percent%ZZsecret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error %q disclosed %q", err, secret)
		}
	}
	if got := err.Error(); got != "oidcredis: invalid DSN" {
		t.Fatalf("error=%q, want fixed invalid-DSN message", got)
	}
}

func TestNew_UnsupportedDSNOptionDoesNotDiscloseValue(t *testing.T) {
	t.Parallel()
	const dsn = "rediss://sensitive-user:percent%40secret@localhost:6379/0?password=query-secret" //nolint:gosec // synthetic credential verifies redaction.
	_, err := New(context.Background(),
		WithDSN(dsn),
		WithRedisAuth("sensitive-user", "percent@secret"),
	)
	if err == nil {
		t.Fatal("want invalid-DSN error")
	}
	for _, secret := range []string{dsn, "sensitive-user", "percent%40secret", "query-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error %q disclosed %q", err, secret)
		}
	}
}

func TestRedactedDSN(t *testing.T) {
	t.Parallel()
	const dsn = "rediss://sensitive-user:percent%40secret@redis.internal:6380/4?protocol=3#private" //nolint:gosec // synthetic credential verifies redaction.
	got := RedactedDSN(dsn)
	if want := "rediss://redis.internal:6380/4"; got != want {
		t.Fatalf("RedactedDSN()=%q, want %q", got, want)
	}
	for _, secret := range []string{"sensitive-user", "percent%40secret", "percent@secret", "protocol=3", "private"} {
		if strings.Contains(got, secret) {
			t.Fatalf("RedactedDSN()=%q disclosed %q", got, secret)
		}
	}
}

func TestRedactedDSN_InvalidInputFailsClosed(t *testing.T) {
	t.Parallel()
	for _, dsn := range []string{
		"rediss://sensitive-user:percent%ZZsecret@localhost:6379/0",
		"memcached://sensitive-user:secret@localhost:11211",
		"sensitive-user:secret",
	} {
		if got := RedactedDSN(dsn); got != invalidRedisDSNLabel {
			t.Errorf("RedactedDSN(%q)=%q, want fixed placeholder", dsn, got)
		}
	}
}

func TestRedisConnectionErrorDoesNotForwardDriverText(t *testing.T) {
	t.Parallel()
	cause := errors.New("WRONGPASS sensitive-user percent%40secret")
	err := &redisConnectionError{
		endpoint: "rediss://redis.internal:6380/4",
		cause:    cause,
	}
	for _, secret := range []string{"sensitive-user", "percent%40secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error %q disclosed %q", err, secret)
		}
	}
	if !errors.Is(err, cause) {
		t.Fatal("connection error no longer unwraps to its cause")
	}
}

func TestNew_ConnectionFailureUsesRedactedEndpoint(t *testing.T) {
	t.Parallel()
	const dsn = "rediss://sensitive-user:percent%40secret@redis.internal:6380/4" //nolint:gosec // synthetic credential verifies connection-error redaction.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New(ctx,
		WithDSN(dsn),
		WithRedisAuth("sensitive-user", "percent@secret"),
	)
	if err == nil {
		t.Fatal("want connection error")
	}
	for _, secret := range []string{dsn, "sensitive-user", "percent%40secret", "percent@secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("connection error %q disclosed %q", err, secret)
		}
	}
	if want := "rediss://redis.internal:6380/4"; !strings.Contains(err.Error(), want) {
		t.Fatalf("connection error %q omitted redacted endpoint %q", err, want)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("connection error %v no longer unwraps to context cancellation", err)
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
			case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
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
