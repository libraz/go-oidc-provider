package op_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func TestAccessTokenFormat_StringIsCanonical(t *testing.T) {
	t.Parallel()

	cases := []struct {
		f    op.AccessTokenFormat
		want string
	}{
		{op.AccessTokenFormatJWT, "jwt"},
		{op.AccessTokenFormatOpaque, "opaque"},
	}
	for _, tc := range cases {
		if got := tc.f.String(); got != tc.want {
			t.Errorf("AccessTokenFormat(%d).String() = %q, want %q", int(tc.f), got, tc.want)
		}
	}

	// Unknown values stringify with their numeric form so a
	// regression in the option-layer validator surfaces in audit /
	// log lines without crashing.
	bogus := op.AccessTokenFormat(99)
	if got := bogus.String(); !strings.Contains(got, "99") {
		t.Errorf("AccessTokenFormat(99).String() = %q, want it to mention 99", got)
	}
}

func TestAccessTokenFormat_IsValid(t *testing.T) {
	t.Parallel()

	if !op.AccessTokenFormatJWT.IsValid() {
		t.Error("AccessTokenFormatJWT must be valid")
	}
	if !op.AccessTokenFormatOpaque.IsValid() {
		t.Error("AccessTokenFormatOpaque must be valid")
	}
	if op.AccessTokenFormat(99).IsValid() {
		t.Error("AccessTokenFormat(99) must not be valid")
	}
}

func TestWithAccessTokenFormat_DefaultIsJWT(t *testing.T) {
	t.Parallel()

	// The library default — neither WithAccessTokenFormat nor
	// WithAccessTokenFormatPerAudience invoked — must resolve every
	// audience to JWT.
	got := op.FormatForAudienceForTest(t, validBaseOpts(t), "")
	if got != op.AccessTokenFormatJWT {
		t.Errorf("default formatForAudience(\"\") = %v, want jwt", got)
	}
	got = op.FormatForAudienceForTest(t, validBaseOpts(t), "https://api.example.com")
	if got != op.AccessTokenFormatJWT {
		t.Errorf("default formatForAudience(api) = %v, want jwt", got)
	}
}

func TestWithAccessTokenFormat_OpaqueRequiresSubstore(t *testing.T) {
	t.Parallel()

	// stubStore.OpaqueAccessTokens returns nil; the construction
	// validator must reject the configuration so the misconfiguration
	// surfaces at startup rather than the first /token request.
	_, err := op.New(append(validBaseOpts(t),
		op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
	)...)
	if err == nil {
		t.Fatal("expected error when opaque format is selected without OpaqueAccessTokens, got nil")
	}
	if !op.IsServerError(err) {
		t.Errorf("opaque-without-substore must be a server-side configuration error: %v", err)
	}
	if !strings.Contains(err.Error(), "OpaqueAccessTokens") {
		t.Errorf("err = %v, want it to mention OpaqueAccessTokens", err)
	}
}

func TestWithAccessTokenFormat_OpaqueWithInmemSucceeds(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
	)...)
	if err != nil {
		t.Fatalf("op.New(opaque + inmem): %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestWithAccessTokenFormat_RejectsUnknownValue(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithAccessTokenFormat(op.AccessTokenFormat(99)),
	)...)
	if err == nil {
		t.Fatal("expected error for unknown AccessTokenFormat, got nil")
	}
	if !strings.Contains(err.Error(), "unknown AccessTokenFormat") {
		t.Errorf("err = %v, want it to mention unknown AccessTokenFormat", err)
	}
}

func TestWithAccessTokenFormatPerAudience_OpaqueRequiresSubstore(t *testing.T) {
	t.Parallel()

	// A single opaque entry pointed at one resource is enough to
	// require the substore even when the global default stays JWT.
	_, err := op.New(append(validBaseOpts(t),
		op.WithAccessTokenFormatPerAudience(map[string]op.AccessTokenFormat{
			"https://api.example.com": op.AccessTokenFormatOpaque,
		}),
	)...)
	if err == nil {
		t.Fatal("expected error when per-audience opaque is selected without OpaqueAccessTokens, got nil")
	}
	if !strings.Contains(err.Error(), "OpaqueAccessTokens") {
		t.Errorf("err = %v, want it to mention OpaqueAccessTokens", err)
	}
}

func TestWithAccessTokenFormatPerAudience_OpaqueWithInmemSucceeds(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithAccessTokenFormatPerAudience(map[string]op.AccessTokenFormat{
			"https://api.example.com": op.AccessTokenFormatOpaque,
		}),
	)...)
	if err != nil {
		t.Fatalf("op.New(per-audience opaque + inmem): %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestWithAccessTokenFormatPerAudience_RejectsEmptyMap(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithAccessTokenFormatPerAudience(map[string]op.AccessTokenFormat{}),
	)...)
	if err == nil {
		t.Fatal("expected error for empty per-audience map, got nil")
	}
	if !strings.Contains(err.Error(), "at least one entry") {
		t.Errorf("err = %v, want it to require at least one entry", err)
	}
}

func TestWithAccessTokenFormatPerAudience_RejectsEmptyKey(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithAccessTokenFormatPerAudience(map[string]op.AccessTokenFormat{
			"": op.AccessTokenFormatOpaque,
		}),
	)...)
	if err == nil {
		t.Fatal("expected error for empty key, got nil")
	}
	if !strings.Contains(err.Error(), "empty key") {
		t.Errorf("err = %v, want it to mention empty key", err)
	}
}

func TestWithAccessTokenFormatPerAudience_RejectsNonCanonicalKeys(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		key  string
		want string
	}{
		{"uppercase scheme", "HTTPS://api.example.com", "lowercase"},
		{"uppercase host", "https://API.example.com", "lowercase"},
		{"fragment", "https://api.example.com#frag", "fragment"},
		{"relative", "/api", "absolute URI"},
		{"bare host", "api.example.com", "absolute URI"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOptsWithInmem(t),
				op.WithAccessTokenFormatPerAudience(map[string]op.AccessTokenFormat{
					tc.key: op.AccessTokenFormatOpaque,
				}),
			)...)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.key)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestWithAccessTokenFormatPerAudience_RejectsUnknownValue(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOptsWithInmem(t),
		op.WithAccessTokenFormatPerAudience(map[string]op.AccessTokenFormat{
			"https://api.example.com": op.AccessTokenFormat(99),
		}),
	)...)
	if err == nil {
		t.Fatal("expected error for unknown AccessTokenFormat value, got nil")
	}
	if !strings.Contains(err.Error(), "unknown AccessTokenFormat") {
		t.Errorf("err = %v, want it to mention unknown AccessTokenFormat", err)
	}
}

func TestFormatForAudience_PerAudienceWinsOverGlobal(t *testing.T) {
	t.Parallel()

	opts := append(validBaseOptsWithInmem(t),
		op.WithAccessTokenFormat(op.AccessTokenFormatJWT),
		op.WithAccessTokenFormatPerAudience(map[string]op.AccessTokenFormat{
			"https://api.example.com": op.AccessTokenFormatOpaque,
		}),
	)
	if got := op.FormatForAudienceForTest(t, opts, "https://api.example.com"); got != op.AccessTokenFormatOpaque {
		t.Errorf("formatForAudience(api) = %v, want opaque", got)
	}
	// Empty resource and unmapped resources fall back to the global
	// default (JWT in this configuration).
	if got := op.FormatForAudienceForTest(t, opts, ""); got != op.AccessTokenFormatJWT {
		t.Errorf("formatForAudience(\"\") = %v, want jwt", got)
	}
	if got := op.FormatForAudienceForTest(t, opts, "https://other.example.com"); got != op.AccessTokenFormatJWT {
		t.Errorf("formatForAudience(other) = %v, want jwt", got)
	}
}

func TestFormatForAudience_GlobalOpaqueAppliesToEmpty(t *testing.T) {
	t.Parallel()

	opts := append(validBaseOptsWithInmem(t),
		op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
	)
	// With only the global override, every audience (including the
	// empty default) resolves to opaque.
	if got := op.FormatForAudienceForTest(t, opts, ""); got != op.AccessTokenFormatOpaque {
		t.Errorf("formatForAudience(\"\") = %v, want opaque", got)
	}
	if got := op.FormatForAudienceForTest(t, opts, "https://api.example.com"); got != op.AccessTokenFormatOpaque {
		t.Errorf("formatForAudience(api) = %v, want opaque", got)
	}
}

// TestStoreOpaqueAccessTokens_NilByStub pins the contract the public
// API surface relies on for fail-fast testing: the legacy stubStore
// returns nil from OpaqueAccessTokens(), so a configuration that
// requests opaque tokens against it MUST be rejected.
func TestStoreOpaqueAccessTokens_NilByStub(t *testing.T) {
	t.Parallel()

	if got := (stubStore{}).OpaqueAccessTokens(); got != nil {
		t.Errorf("stubStore.OpaqueAccessTokens() = %v, want nil", got)
	}
	if got := inmem.New().OpaqueAccessTokens(); got == nil {
		t.Error("inmem.New().OpaqueAccessTokens() = nil, want non-nil")
	}

	// Sanity-check the public catalogue's IsServerError predicate
	// folds the construction error onto the configuration class.
	_, err := op.New(append(validBaseOpts(t),
		op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
	)...)
	if err == nil {
		t.Fatal("expected fail-fast error, got nil")
	}
	var typed *op.Error
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *op.Error", err)
	}
}
