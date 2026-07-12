package httpx_test

import (
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

func TestFirstDuplicateParameterRejectsRepeatedSingleValuedNames(t *testing.T) {
	t.Parallel()

	values := url.Values{
		"client_id": {"rp-1", "rp-1"},
		"resource":  {"https://api.example", "https://other.example"},
		"scope":     {"openid profile"},
	}
	got, ok := httpx.FirstDuplicateParameter(values, []string{"scope", "client_id"})
	if ok {
		t.Fatal("FirstDuplicateParameter reported ok for repeated client_id")
	}
	if got != "client_id" {
		t.Fatalf("duplicate name = %q, want client_id", got)
	}
}

func TestFirstDuplicateParameterPreservesCallerAllowlistOrder(t *testing.T) {
	t.Parallel()

	values := url.Values{
		"client_id": {"rp-1", "rp-2"},
		"scope":     {"openid", "profile"},
	}
	got, ok := httpx.FirstDuplicateParameter(values, []string{"scope", "client_id"})
	if ok {
		t.Fatal("FirstDuplicateParameter reported ok for repeated parameters")
	}
	if got != "scope" {
		t.Fatalf("duplicate name = %q, want first duplicate in caller order scope", got)
	}
}

func TestFirstDuplicateParameterIgnoresNamesNotDeclaredSingleValued(t *testing.T) {
	t.Parallel()

	values := url.Values{
		"resource": {"https://api.example", "https://other.example"},
		"scope":    {"openid profile"},
	}
	got, ok := httpx.FirstDuplicateParameter(values, []string{"scope", "client_id"})
	if !ok {
		t.Fatalf("FirstDuplicateParameter = (%q, false), want ok for undeclared multi-valued resource", got)
	}
	if got != "" {
		t.Fatalf("duplicate name = %q, want empty", got)
	}
}
