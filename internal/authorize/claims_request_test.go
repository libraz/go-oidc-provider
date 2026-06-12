package authorize_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

func TestParseClaimsRequest_Empty(t *testing.T) {
	t.Parallel()
	got, err := authorize.ParseClaimsRequest("")
	if err != nil {
		t.Fatalf("err=%v want nil", err)
	}
	if got != nil {
		t.Fatalf("got=%+v want nil", got)
	}
}

func TestParseClaimsRequest_Whitespace(t *testing.T) {
	t.Parallel()
	got, err := authorize.ParseClaimsRequest("   \n\t ")
	if err != nil || got != nil {
		t.Fatalf("got=%+v err=%v want (nil,nil)", got, err)
	}
}

func TestParseClaimsRequest_RejectsOversizedInput(t *testing.T) {
	t.Parallel()

	raw := `{"userinfo":{"name":{"value":"` + strings.Repeat("x", 16*1024) + `"}}}`
	_, err := authorize.ParseClaimsRequest(raw)
	if !errors.Is(err, authorize.ErrClaimsRequestInvalid) {
		t.Fatalf("err=%v want ErrClaimsRequestInvalid", err)
	}
}

func TestParseClaimsRequest_OFCSEssential(t *testing.T) {
	t.Parallel()
	raw := `{"userinfo":{"name":{"essential":true}}}`
	got, err := authorize.ParseClaimsRequest(raw)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if got == nil {
		t.Fatal("got=nil")
	}
	spec, ok := got.UserInfoSpec("name")
	if !ok {
		t.Fatal("name not present in userinfo")
	}
	if !spec.Essential {
		t.Errorf("essential=false want true")
	}
	if got.HasIDToken("name") {
		t.Errorf("name unexpectedly present in id_token")
	}
}

func TestParseClaimsRequest_VoluntaryNull(t *testing.T) {
	t.Parallel()
	raw := `{"userinfo":{"email":null}}`
	got, err := authorize.ParseClaimsRequest(raw)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	spec, ok := got.UserInfoSpec("email")
	if !ok {
		t.Fatal("email missing")
	}
	if spec.Essential {
		t.Errorf("essential=true want false on null body")
	}
	if spec.Value != nil || spec.Values != nil {
		t.Errorf("zero spec expected, got %+v", spec)
	}
}

func TestParseClaimsRequest_ValueAndValues(t *testing.T) {
	t.Parallel()
	raw := `{"id_token":{"acr":{"essential":true,"values":["urn:mace:incommon:iap:silver","2"]},"sub":{"value":"alice"}}}`
	got, err := authorize.ParseClaimsRequest(raw)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	acr, ok := got.IDTokenSpec("acr")
	if !ok {
		t.Fatal("acr missing")
	}
	if !acr.Essential {
		t.Error("acr.Essential=false want true")
	}
	if len(acr.Values) != 2 {
		t.Fatalf("acr.Values len=%d want 2", len(acr.Values))
	}
	if acr.Values[0].(string) != "urn:mace:incommon:iap:silver" {
		t.Errorf("acr.Values[0]=%v", acr.Values[0])
	}
	sub, _ := got.IDTokenSpec("sub")
	if sub.Value.(string) != "alice" {
		t.Errorf("sub.Value=%v", sub.Value)
	}
}

func TestParseClaimsRequest_UnknownTopLevelIgnored(t *testing.T) {
	t.Parallel()
	raw := `{"userinfo":{"name":null},"vendor_extension":{"foo":"bar"}}`
	got, err := authorize.ParseClaimsRequest(raw)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if !got.HasUserInfo("name") {
		t.Error("name should be parsed")
	}
}

func TestParseClaimsRequest_Malformed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
	}{
		{"truncated", `{"userinfo":{`},
		{"trailing_garbage", `{"userinfo":{}}{}`},
		{"top_level_array", `[]`},
		{"top_level_string", `"oops"`},
		{"location_array", `{"userinfo":[]}`},
		{"entry_array", `{"userinfo":{"name":[]}}`},
		{"entry_string", `{"userinfo":{"name":"value"}}`},
		{"essential_string", `{"userinfo":{"name":{"essential":"true"}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := authorize.ParseClaimsRequest(tc.raw)
			if !errors.Is(err, authorize.ErrClaimsRequestInvalid) {
				t.Errorf("err=%v want ErrClaimsRequestInvalid", err)
			}
		})
	}
}

func TestParseClaimsRequest_LanguageTagPreserved(t *testing.T) {
	t.Parallel()
	raw := `{"userinfo":{"name#ja-JP":{"essential":true}}}`
	got, err := authorize.ParseClaimsRequest(raw)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if !got.HasUserInfo("name#ja-JP") {
		t.Errorf("language-tagged key not preserved verbatim")
	}
}

func TestClaimSpec_Allows(t *testing.T) {
	t.Parallel()
	specEmpty := authorize.ClaimSpec{}
	if !specEmpty.Allows("anything") {
		t.Error("empty spec must allow anything")
	}

	specValue := authorize.ClaimSpec{Value: "alice"}
	if !specValue.Allows("alice") {
		t.Error("value match should allow")
	}
	if specValue.Allows("bob") {
		t.Error("value mismatch should reject")
	}

	specValues := authorize.ClaimSpec{Values: []any{"a", "b"}}
	if !specValues.Allows("a") || !specValues.Allows("b") {
		t.Error("values list should allow listed entries")
	}
	if specValues.Allows("c") {
		t.Error("values list should reject unlisted")
	}
}

func TestClaimSpec_Allows_Number(t *testing.T) {
	t.Parallel()
	parsed, err := authorize.ParseClaimsRequest(`{"userinfo":{"max":{"value":42}}}`)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	spec, _ := parsed.UserInfoSpec("max")
	if !spec.Allows(json.Number("42")) {
		t.Error("number 42 should match value 42")
	}
	if spec.Allows(json.Number("43")) {
		t.Error("number 43 should not match value 42")
	}
}

func TestClaimsRequest_Roundtrip(t *testing.T) {
	t.Parallel()
	raw := `{"userinfo":{"name":{"essential":true}},"id_token":{"sub":{"value":"alice"}}}`
	parsed, err := authorize.ParseClaimsRequest(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	encoded, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back authorize.ClaimsRequest
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !back.HasUserInfo("name") || !back.HasIDToken("sub") {
		t.Errorf("round-trip lost members: %s", encoded)
	}
}

func TestCloneClaimsRequest(t *testing.T) {
	t.Parallel()
	parsed, err := authorize.ParseClaimsRequest(`{"userinfo":{"name":{"essential":true}}}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cloned := authorize.CloneClaimsRequest(parsed)
	if cloned == parsed {
		t.Fatal("clone returned same pointer")
	}
	parsed.UserInfo["name"] = authorize.ClaimSpec{Essential: false}
	if !cloned.UserInfo["name"].Essential {
		t.Error("clone aliased original map")
	}
	if authorize.CloneClaimsRequest(nil) != nil {
		t.Error("CloneClaimsRequest(nil) must return nil")
	}
}
