package ciba_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/ciba"
)

func TestValidateBindingMessage(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{name: "empty is valid", in: "", want: "", wantErr: nil},
		{name: "whitespace-only collapses to empty", in: "   ", want: "", wantErr: nil},
		{name: "ascii passthrough", in: "Approve transfer", want: "Approve transfer", wantErr: nil},
		{
			name:    "html metacharacters pass through raw (not escaped)",
			in:      `pay <b>$5</b> & "quoted" 'val'`,
			want:    `pay <b>$5</b> & "quoted" 'val'`,
			wantErr: nil,
		},
		{name: "exactly 50 runes", in: strings.Repeat("a", 50), want: strings.Repeat("a", 50), wantErr: nil},
		{name: "51 ascii rejected", in: strings.Repeat("a", 51), want: "", wantErr: ciba.ErrBindingMessageTooLong},
		{
			name:    "50 multibyte runes accepted (rune-count not byte-count)",
			in:      strings.Repeat("あ", 50),
			want:    strings.Repeat("あ", 50),
			wantErr: nil,
		},
		{
			name:    "51 multibyte runes rejected",
			in:      strings.Repeat("あ", 51),
			want:    "",
			wantErr: ciba.ErrBindingMessageTooLong,
		},
		{
			name:    "embedded newline rejected as control character",
			in:      "line1\nline2",
			want:    "",
			wantErr: ciba.ErrBindingMessageInvalidChar,
		},
		{
			name:    "embedded NUL rejected as control character",
			in:      "amount\x00forged",
			want:    "",
			wantErr: ciba.ErrBindingMessageInvalidChar,
		},
		{
			name:    "embedded tab rejected as control character",
			in:      "pay\tnow",
			want:    "",
			wantErr: ciba.ErrBindingMessageInvalidChar,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ciba.ValidateBindingMessage(tc.in)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err: got %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("value: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateScope(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      string
		want    []string
		wantErr error
	}{
		{name: "empty rejected", in: "", wantErr: ciba.ErrMissingScope},
		{name: "whitespace-only rejected", in: "   \t", wantErr: ciba.ErrMissingScope},
		{name: "missing openid rejected", in: "profile email", wantErr: ciba.ErrScopeMissingOpenID},
		{name: "openid-only accepted", in: "openid", want: []string{"openid"}, wantErr: nil},
		{name: "openid plus extras accepted", in: "openid profile email", want: []string{"openid", "profile", "email"}, wantErr: nil},
		{name: "tab-separated accepted", in: "openid\tprofile", want: []string{"openid", "profile"}, wantErr: nil},
		{name: "duplicates preserved", in: "openid openid profile", want: []string{"openid", "openid", "profile"}, wantErr: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ciba.ValidateScope(tc.in)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err: got %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len: got %d (%v), want %d (%v)", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("scope[%d]: got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestClassifyHint(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		loginHint      string
		idTokenHint    string
		loginHintToken string
		wantKind       ciba.HintKind
		wantValue      string
		wantErr        error
	}{
		{
			name:    "none rejected",
			wantErr: ciba.ErrInvalidHintCombination,
		},
		{
			name:      "login_hint only",
			loginHint: "alice@example.test",
			wantKind:  ciba.HintLoginHint,
			wantValue: "alice@example.test",
		},
		{ //nolint:gosec // G101 false positive: struct-literal field names contain "Token" but the values are opaque test fixtures.
			name:        "id_token_hint only",
			idTokenHint: "opaque-id-tok-fixture",
			wantKind:    ciba.HintIDTokenHint,
			wantValue:   "opaque-id-tok-fixture",
		},
		{ //nolint:gosec // G101 false positive: struct-literal field names contain "Token" but the values are opaque test fixtures.
			name:           "login_hint_token only",
			loginHintToken: "opaque-login-hint-fixture",
			wantKind:       ciba.HintLoginHintToken,
			wantValue:      "opaque-login-hint-fixture",
		},
		{
			name:        "two of three rejected",
			loginHint:   "alice",
			idTokenHint: "tok",
			wantErr:     ciba.ErrInvalidHintCombination,
		},
		{
			name:           "all three rejected",
			loginHint:      "alice",
			idTokenHint:    "tok",
			loginHintToken: "ltok",
			wantErr:        ciba.ErrInvalidHintCombination,
		},
		{
			name:      "whitespace-only treated as empty",
			loginHint: "   ",
			wantErr:   ciba.ErrInvalidHintCombination,
		},
		{
			name:      "trimmed value returned",
			loginHint: "  alice  ",
			wantKind:  ciba.HintLoginHint,
			wantValue: "alice",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotKind, gotValue, err := ciba.ClassifyHint(tc.loginHint, tc.idTokenHint, tc.loginHintToken)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err: got %v, want %v", err, tc.wantErr)
			}
			if gotKind != tc.wantKind {
				t.Errorf("kind: got %v, want %v", gotKind, tc.wantKind)
			}
			if gotValue != tc.wantValue {
				t.Errorf("value: got %q, want %q", gotValue, tc.wantValue)
			}
		})
	}
}

func TestHintKind_String(t *testing.T) {
	t.Parallel()
	cases := map[ciba.HintKind]string{
		ciba.HintLoginHint:      "login_hint",
		ciba.HintIDTokenHint:    "id_token_hint",
		ciba.HintLoginHintToken: "login_hint_token",
		ciba.HintNone:           "none",
		ciba.HintKind(99):       "none",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("HintKind(%d).String() = %q, want %q", uint8(k), got, want)
		}
	}
}

func TestParseRequestedExpirySeconds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw     string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"  ", 0, false},
		{" 120 ", 120, false},
		{"9999999999", 9999999999, false},
		{"0", 0, true},
		{"-5", 0, true},
		{"abc", 0, true},
		{"1.5", 0, true},
	}
	for _, tc := range cases {
		got, err := ciba.ParseRequestedExpirySeconds(tc.raw)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseRequestedExpirySeconds(%q) = (%d, %v), want (%d, err=%v)", tc.raw, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestExpiryFromSeconds(t *testing.T) {
	t.Parallel()

	if got := ciba.ExpiryFromSeconds(0, time.Minute); got != 0 {
		t.Errorf("zero seconds = %v, want 0", got)
	}
	if got := ciba.ExpiryFromSeconds(30, time.Minute); got != 30*time.Second {
		t.Errorf("under upper = %v, want 30s", got)
	}
	if got := ciba.ExpiryFromSeconds(300, time.Minute); got != time.Minute {
		t.Errorf("over upper = %v, want clamp to 1m", got)
	}
	if got := ciba.ExpiryFromSeconds(300, 0); got != 300*time.Second {
		t.Errorf("no upper = %v, want 300s", got)
	}
}
