package jar_test

import (
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jar"
)

// objectWithClaims returns a [jar.Object] populated with claims. Tests
// in this file never run [jar.Verifier.Verify] — they exercise the merge
// rules in isolation.
func objectWithClaims(claims map[string]any) *jar.Object {
	return &jar.Object{Claims: claims}
}

func TestMerge_NilObjectIsParseError(t *testing.T) {
	t.Parallel()
	if _, err := jar.Merge(url.Values{}, nil); !errors.Is(err, jar.ErrParse) {
		t.Fatalf("err=%v want ErrParse", err)
	}
}

func TestMerge_RejectsNestedRequest(t *testing.T) {
	t.Parallel()
	obj := objectWithClaims(map[string]any{"request": "x"})
	if _, err := jar.Merge(url.Values{}, obj); !errors.Is(err, jar.ErrNestedRequest) {
		t.Fatalf("err=%v want ErrNestedRequest", err)
	}
}

func TestMerge_RejectsNestedRequestURI(t *testing.T) {
	t.Parallel()
	obj := objectWithClaims(map[string]any{"request_uri": "x"})
	if _, err := jar.Merge(url.Values{}, obj); !errors.Is(err, jar.ErrNestedRequest) {
		t.Fatalf("err=%v want ErrNestedRequest", err)
	}
}

func TestMerge_AcceptsClientIDAgreement(t *testing.T) {
	t.Parallel()
	wire := url.Values{"client_id": {"abc"}, "scope": {"old"}}
	obj := objectWithClaims(map[string]any{
		"client_id": "abc",
		"scope":     "openid profile",
	})
	out, err := jar.Merge(wire, obj)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if got := out.Get("client_id"); got != "abc" {
		t.Errorf("client_id=%q want abc", got)
	}
	if got := out.Get("scope"); got != "openid profile" {
		t.Errorf("scope=%q want override from JWT", got)
	}
}

func TestMerge_RejectsClientIDDisagreement(t *testing.T) {
	t.Parallel()
	wire := url.Values{"client_id": {"abc"}}
	obj := objectWithClaims(map[string]any{"client_id": "different"})
	_, err := jar.Merge(wire, obj)
	if !errors.Is(err, jar.ErrClientIDMismatch) {
		t.Fatalf("err=%v want ErrClientIDMismatch", err)
	}
}

func TestMerge_OmittedClientIDInJWTOK(t *testing.T) {
	t.Parallel()
	wire := url.Values{"client_id": {"abc"}}
	obj := objectWithClaims(map[string]any{"scope": "openid"})
	out, err := jar.Merge(wire, obj)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if got := out.Get("client_id"); got != "abc" {
		t.Errorf("client_id=%q want abc", got)
	}
}

func TestMerge_StripsRequestParametersFromWire(t *testing.T) {
	t.Parallel()
	wire := url.Values{
		"client_id":   {"abc"},
		"request":     {"original-jwt"},
		"request_uri": {"https://rp/req"},
	}
	obj := objectWithClaims(map[string]any{"scope": "openid"})
	out, err := jar.Merge(wire, obj)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if out.Has("request") {
		t.Errorf("request leaked: %v", out)
	}
	if out.Has("request_uri") {
		t.Errorf("request_uri leaked: %v", out)
	}
}

func TestMerge_OverridesWireValues(t *testing.T) {
	t.Parallel()
	wire := url.Values{
		"client_id":     {"abc"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	obj := objectWithClaims(map[string]any{
		"scope": "openid profile email",
	})
	out, err := jar.Merge(wire, obj)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if got := out.Get("scope"); got != "openid profile email" {
		t.Errorf("scope=%q want JWT override", got)
	}
	if got := out.Get("response_type"); got != "code" {
		t.Errorf("response_type=%q want preserved wire value", got)
	}
}

func TestMerge_IgnoresJOSEClaims(t *testing.T) {
	t.Parallel()
	wire := url.Values{"client_id": {"abc"}}
	obj := objectWithClaims(map[string]any{
		"iss":   "abc",
		"aud":   "https://op",
		"exp":   1234567890,
		"iat":   1234567880,
		"jti":   "abc-123",
		"nbf":   1234567880,
		"scope": "openid",
	})
	out, err := jar.Merge(wire, obj)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	for _, k := range []string{"iss", "aud", "exp", "iat", "jti", "nbf"} {
		if out.Has(k) {
			t.Errorf("%s leaked into wire form", k)
		}
	}
	if got := out.Get("scope"); got != "openid" {
		t.Errorf("scope missing: %v", out)
	}
}

func TestMerge_RejectsUnsupportedClaimShape(t *testing.T) {
	t.Parallel()
	wire := url.Values{"client_id": {"abc"}}
	obj := objectWithClaims(map[string]any{
		"weird": map[string]any{"nested": "object"},
	})
	_, err := jar.Merge(wire, obj)
	if !errors.Is(err, jar.ErrParse) {
		t.Fatalf("err=%v want ErrParse", err)
	}
}

func TestMerge_LowersBoolAndNumber(t *testing.T) {
	t.Parallel()
	wire := url.Values{"client_id": {"abc"}}
	obj := objectWithClaims(map[string]any{
		"flag":    true,
		"max_age": float64(60),
	})
	out, err := jar.Merge(wire, obj)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if got := out.Get("flag"); got != "true" {
		t.Errorf("flag=%q want true", got)
	}
	if got := out.Get("max_age"); got != "60" {
		t.Errorf("max_age=%q want 60", got)
	}
}

func TestMerge_LowersStringArray(t *testing.T) {
	t.Parallel()
	wire := url.Values{"client_id": {"abc"}}
	obj := objectWithClaims(map[string]any{
		"acr_values": []any{"urn:1", "urn:2"},
	})
	out, err := jar.Merge(wire, obj)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if got := out.Get("acr_values"); got != "urn:1 urn:2" {
		t.Errorf("acr_values=%q want space-joined", got)
	}
}

// TestMerge_LowersClaimsObject covers the OIDC Core 1.0 §5.5 path:
// when a request object carries a "claims" parameter, the merge step
// must JSON-encode the structured value so the downstream form parser
// (ParseClaimsRequest) sees the canonical wire bytes.
func TestMerge_LowersClaimsObject(t *testing.T) {
	t.Parallel()
	wire := url.Values{"client_id": {"abc"}}
	obj := objectWithClaims(map[string]any{
		"claims": map[string]any{
			"id_token": map[string]any{
				"sub":  nil,
				"name": map[string]any{"essential": true},
			},
		},
	})
	out, err := jar.Merge(wire, obj)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	got := out.Get("claims")
	if got == "" {
		t.Fatalf("claims param missing from merged form")
	}
	var roundTrip map[string]any
	if err := json.Unmarshal([]byte(got), &roundTrip); err != nil {
		t.Fatalf("claims param is not valid JSON: %v (raw=%q)", err, got)
	}
	idTok, ok := roundTrip["id_token"].(map[string]any)
	if !ok {
		t.Fatalf("id_token not preserved: %v", roundTrip)
	}
	if _, ok := idTok["sub"]; !ok {
		t.Errorf("sub key missing after merge")
	}
}

// TestMerge_LowersAuthorizationDetailsArray covers the RFC 9396 path:
// "authorization_details" is a JSON array of objects, the only other
// authorization parameter where the canonical wire form is structured
// JSON.
func TestMerge_LowersAuthorizationDetailsArray(t *testing.T) {
	t.Parallel()
	wire := url.Values{"client_id": {"abc"}}
	obj := objectWithClaims(map[string]any{
		"authorization_details": []any{
			map[string]any{"type": "payment_initiation", "amount": "10.00"},
		},
	})
	out, err := jar.Merge(wire, obj)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	got := out.Get("authorization_details")
	var arr []any
	if err := json.Unmarshal([]byte(got), &arr); err != nil {
		t.Fatalf("authorization_details is not valid JSON: %v (raw=%q)", err, got)
	}
	if len(arr) != 1 {
		t.Fatalf("authorization_details len=%d want 1", len(arr))
	}
}
