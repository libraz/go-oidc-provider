//nolint:testpackage // intentional white-box test for unexported helpers.
package rpjwks

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
)

// unsupportedMemberJWK is a JWK the JOSE layer cannot turn into a key: an OKP
// curve outside the Ed25519 it implements. RPs publish members of this shape
// for ECDH-ES key agreement alongside their signing keys.
const unsupportedMemberJWK = `{"kty":"OKP","crv":"X25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo","use":"enc","kid":"enc-1"}`

// ecMemberJWK is a P-256 signing key every build can represent.
const ecMemberJWK = `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"k1"}`

// jwksJSON is the canonical RP-side JWKS document used across the tests.
const jwksJSON = `{"keys":[` + ecMemberJWK + `]}`

func TestParseKeySet_HappyPath(t *testing.T) {
	t.Parallel()

	keys, err := ParseKeySet([]byte(jwksJSON))
	if err != nil {
		t.Fatalf("ParseKeySet: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "k1" {
		t.Fatalf("ParseKeySet returned kids %v, want [k1]", keyIDs(keys))
	}
}

func TestParseKeySet_EmptyBody(t *testing.T) {
	t.Parallel()

	if _, err := ParseKeySet(nil); err == nil {
		t.Fatal("ParseKeySet accepted an empty body")
	}
}

// TestParseKeySet_KeepsSupportedKeyBesideUnsupportedOne pins RFC 7517 §5: an RP
// publishing a key type this build cannot represent (an X25519 key for ECDH-ES,
// say) next to its signing key stays usable instead of failing the whole
// document.
func TestParseKeySet_KeepsSupportedKeyBesideUnsupportedOne(t *testing.T) {
	t.Parallel()

	keys, err := ParseKeySet([]byte(`{"keys":[` + unsupportedMemberJWK + `,` + ecMemberJWK + `]}`))
	if err != nil {
		t.Fatalf("ParseKeySet: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "k1" {
		t.Fatalf("ParseKeySet returned kids %v, want [k1]", keyIDs(keys))
	}
}

// TestParseKeySet_RejectsKeysetWithoutAnySupportedKey confirms the tolerant
// decode still fails when nothing usable is left, so the caller reports a
// failure rather than silently holding an empty keyset.
func TestParseKeySet_RejectsKeysetWithoutAnySupportedKey(t *testing.T) {
	t.Parallel()

	if _, err := ParseKeySet([]byte(`{"keys":[` + unsupportedMemberJWK + `]}`)); err == nil {
		t.Fatal("ParseKeySet accepted a keyset with no usable member")
	}
}

// TestParseKeySet_EmptyKeysArrayIsAccepted pins that a syntactically valid
// document declaring no members decodes without error; reporting the absence is
// the caller's job, in the caller's vocabulary.
func TestParseKeySet_EmptyKeysArrayIsAccepted(t *testing.T) {
	t.Parallel()

	keys, err := ParseKeySet([]byte(`{"keys":[]}`))
	if err != nil {
		t.Fatalf("ParseKeySet: %v", err)
	}
	if len(keys.Keys) != 0 {
		t.Fatalf("Keys=%d want 0", len(keys.Keys))
	}
}

// TestParseKeySet_RejectsExcessiveKeyCount confirms the member cap counts what
// the document declares rather than what survived decoding, so a hostile keyset
// of unrepresentable members is still rejected on cardinality.
func TestParseKeySet_RejectsExcessiveKeyCount(t *testing.T) {
	t.Parallel()

	body := `{"keys":[` + strings.Repeat(`{"kty":"EC"},`, MaxKeys) + `{"kty":"EC"}]}`
	if _, err := ParseKeySet([]byte(body)); err == nil {
		t.Fatal("ParseKeySet accepted an excessive key count")
	}
}

func TestIsJSONContentType(t *testing.T) {
	t.Parallel()

	for _, ct := range []string{
		"application/json",
		"application/json; charset=utf-8",
		"application/jwk-set+json",
	} {
		if !isJSONContentType(ct) {
			t.Errorf("rejected %q", ct)
		}
	}
	for _, ct := range []string{"text/plain", "text/html", ""} {
		if isJSONContentType(ct) {
			t.Errorf("accepted %q", ct)
		}
	}
}

func TestParseMaxAge_HappyPath(t *testing.T) {
	t.Parallel()

	got, ok := parseMaxAge("public, max-age=120")
	if !ok || got != 120*time.Second {
		t.Fatalf("got=%v ok=%v", got, ok)
	}
}

func TestParseMaxAge_Absent(t *testing.T) {
	t.Parallel()

	if _, ok := parseMaxAge("no-store"); ok {
		t.Fatal("ok should be false when max-age missing")
	}
}

// TestTTLFromResponse_AbsentLeavesConfiguredTTL pins that a response without a
// usable max-age yields zero, which is what leaves the cache's configured TTL
// in force rather than overriding it with a package constant.
func TestTTLFromResponse_AbsentLeavesConfiguredTTL(t *testing.T) {
	t.Parallel()

	for _, cc := range []string{"", "no-store", "max-age=0", "max-age=abc"} {
		resp := &http.Response{Header: http.Header{}}
		if cc != "" {
			resp.Header.Set("Cache-Control", cc)
		}
		if got := ttlFromResponse(resp, DefaultTTL); got != 0 {
			t.Errorf("Cache-Control=%q ttl=%v want 0", cc, got)
		}
	}
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Cache-Control", "max-age=90")
	if got := ttlFromResponse(resp, DefaultTTL); got != 90*time.Second {
		t.Errorf("ttl=%v want 90s", got)
	}
}

// TestTTLFromResponse_ClampsToCeiling pins the direction the freshness hint is
// allowed to move in. The header is written by the relying party, so a long
// max-age must not be able to pin its keyset in the OP's cache: a key the RP
// leaked or withdrew would otherwise keep verifying client assertions for the
// advertised span, with no operator-visible signal.
func TestTTLFromResponse_ClampsToCeiling(t *testing.T) {
	t.Parallel()

	const ceiling = 5 * time.Minute
	for _, tc := range []struct {
		cacheControl string
		want         time.Duration
	}{
		{"max-age=31536000", ceiling},    // a year: clamped to the OP's bound
		{"max-age=300", ceiling},         // exactly the bound: unchanged
		{"max-age=30", 30 * time.Second}, // below the bound: the RP may shorten
	} {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("Cache-Control", tc.cacheControl)
		if got := ttlFromResponse(resp, ceiling); got != tc.want {
			t.Errorf("Cache-Control=%q ttl=%v want %v", tc.cacheControl, got, tc.want)
		}
	}
}

func TestParseUnsignedSeconds_Rejects(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"", "-1", "12a", "99999999999"} {
		if _, err := parseUnsignedSeconds(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestErrFetch_IsTheFallbackSentinel(t *testing.T) {
	t.Parallel()

	f := New(Config{})
	_, err := f.ParseKeySet(nil)
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("err=%v want ErrFetch", err)
	}
}

func keyIDs(set *josev4.JSONWebKeySet) []string {
	out := make([]string, 0, len(set.Keys))
	for i := range set.Keys {
		out = append(out, set.Keys[i].KeyID)
	}
	return out
}
