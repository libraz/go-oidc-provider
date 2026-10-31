//nolint:testpackage // exercises the unexported catalogues and lookup sets.
package redact

import (
	"slices"
	"strings"
	"testing"
)

// referenceIsSensitive is the straightforward linear-scan classifier the
// lookup sets must agree with.
func referenceIsSensitive(key string) bool {
	canon := strings.ReplaceAll(strings.ToLower(key), "-", "_")
	if canon == "" {
		return false
	}
	if slices.Contains(sensitiveKeys, canon) {
		return true
	}
	if slices.Contains(substringAllowlist, canon) {
		return false
	}
	for _, needle := range sensitiveSubstrings {
		if strings.Contains(canon, needle) {
			return true
		}
	}
	return false
}

func TestIsSensitive_MatchesReferenceForEveryCatalogueEntry(t *testing.T) {
	t.Parallel()
	var keys []string
	for _, list := range [][]string{sensitiveKeys, substringAllowlist, sensitiveSubstrings} {
		for _, k := range list {
			keys = append(keys,
				k, strings.ToUpper(k), strings.ReplaceAll(k, "_", "-"),
				"x_"+k, k+"_x", "Set-"+k)
		}
	}
	keys = append(keys, "", "user_id", "client_id", "sub", "Content-Type", "scope", "iss", "request_id", "path")
	for _, k := range keys {
		if got, want := IsSensitive(k), referenceIsSensitive(k); got != want {
			t.Errorf("IsSensitive(%q) = %v, want %v", k, got, want)
		}
	}
}

func TestIsSensitive_Classification(t *testing.T) {
	t.Parallel()
	for _, k := range sensitiveKeys {
		if !IsSensitive(k) {
			t.Errorf("exact entry %q not sensitive", k)
		}
	}
	for _, k := range substringAllowlist {
		if slices.Contains(sensitiveKeys, k) {
			continue
		}
		if IsSensitive(k) {
			t.Errorf("allowlisted entry %q reported sensitive", k)
		}
	}
	for _, k := range []string{"user_id", "client_id", "sub", "scope", "request_id"} {
		if IsSensitive(k) {
			t.Errorf("benign key %q reported sensitive", k)
		}
	}
}

func TestIsSensitive_CanonicalKeysDoNotAllocate(t *testing.T) {
	for _, key := range []string{"access_token", "user_id", "token_type", "new_refresh_token"} {
		if n := testing.AllocsPerRun(100, func() { _ = IsSensitive(key) }); n != 0 {
			t.Errorf("IsSensitive(%q) allocs = %v, want 0", key, n)
		}
	}
}

func BenchmarkIsSensitive(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		_ = IsSensitive("user_id")
	}
}
