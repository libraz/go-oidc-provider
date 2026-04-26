package jarm_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jarm"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		in     string
		wantOK bool
		want   jarm.ResponseMode
	}{
		{name: "query.jwt", in: "query.jwt", wantOK: true, want: jarm.ResponseModeQueryJWT},
		{name: "fragment.jwt", in: "fragment.jwt", wantOK: true, want: jarm.ResponseModeFragmentJWT},
		{name: "form_post.jwt", in: "form_post.jwt", wantOK: true, want: jarm.ResponseModeFormPostJWT},
		{name: "jwt", in: "jwt", wantOK: true, want: jarm.ResponseModeJWT},
		{name: "query (non-JARM)", in: "query"},
		{name: "form_post (non-JARM)", in: "form_post"},
		{name: "fragment (non-JARM)", in: "fragment"},
		{name: "empty", in: ""},
		{name: "unknown", in: "weird.jwt"},
		{name: "case sensitive", in: "QUERY.JWT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := jarm.Parse(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v want %v", ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Errorf("got=%q want %q", got, tt.want)
			}
		})
	}
}

func TestIsJARM(t *testing.T) {
	t.Parallel()

	if !jarm.IsJARM("query.jwt") {
		t.Error("IsJARM(query.jwt) = false")
	}
	if jarm.IsJARM("query") {
		t.Error("IsJARM(query) = true")
	}
	if jarm.IsJARM("") {
		t.Error("IsJARM(empty) = true")
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		mode         jarm.ResponseMode
		responseType string
		want         jarm.ResponseMode
	}{
		{
			name:         "bare jwt with code resolves to query.jwt",
			mode:         jarm.ResponseModeJWT,
			responseType: "code",
			want:         jarm.ResponseModeQueryJWT,
		},
		{
			name:         "bare jwt with token resolves to fragment.jwt",
			mode:         jarm.ResponseModeJWT,
			responseType: "token",
			want:         jarm.ResponseModeFragmentJWT,
		},
		{
			name:         "bare jwt with id_token resolves to fragment.jwt",
			mode:         jarm.ResponseModeJWT,
			responseType: "id_token",
			want:         jarm.ResponseModeFragmentJWT,
		},
		{
			name:         "bare jwt with hybrid token id_token resolves to fragment.jwt",
			mode:         jarm.ResponseModeJWT,
			responseType: "code id_token",
			want:         jarm.ResponseModeFragmentJWT,
		},
		{
			name:         "explicit query.jwt is unchanged",
			mode:         jarm.ResponseModeQueryJWT,
			responseType: "code",
			want:         jarm.ResponseModeQueryJWT,
		},
		{
			name:         "explicit fragment.jwt is unchanged",
			mode:         jarm.ResponseModeFragmentJWT,
			responseType: "code",
			want:         jarm.ResponseModeFragmentJWT,
		},
		{
			name:         "explicit form_post.jwt is unchanged",
			mode:         jarm.ResponseModeFormPostJWT,
			responseType: "code",
			want:         jarm.ResponseModeFormPostJWT,
		},
		{
			name:         "non-JARM input returns empty",
			mode:         jarm.ResponseMode("query"),
			responseType: "code",
			want:         "",
		},
		{
			name:         "empty mode returns empty",
			mode:         "",
			responseType: "code",
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := jarm.Resolve(tt.mode, tt.responseType)
			if got != tt.want {
				t.Errorf("Resolve(%q, %q) = %q want %q", tt.mode, tt.responseType, got, tt.want)
			}
		})
	}
}
