package userinfo_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/internal/userinfo"
	"github.com/libraz/go-oidc-provider/op/store"
)

var reservedSourceClaims = map[string]any{
	"iss":   "https://evil.example.com",
	"aud":   "victim-client",
	"exp":   1,
	"email": "alice@example.com",
}

// TestBuild_ReservedClaimsNeverReleased pins that neither a custom scope
// claim list nor a claims request can release JWT-reserved names from
// the claim source.
func TestBuild_ReservedClaimsNeverReleased(t *testing.T) {
	t.Parallel()

	spec := map[string]authorize.ClaimSpec{"iss": {}, "aud": {}, "exp": {}, "email": {}}
	out, err := userinfo.Build(userinfo.Input{
		Subject:           "user-1",
		Scopes:            []string{"openid", "custom"},
		CustomScopeClaims: map[string][]string{"custom": {"iss", "aud"}},
		Source:            reservedSourceClaims,
		Claims:            &authorize.ClaimsRequest{UserInfo: spec},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, name := range []string{"iss", "aud", "exp"} {
		if v, ok := out[name]; ok {
			t.Errorf("%s=%v released from the claim source", name, v)
		}
	}
	if out["email"] != "alice@example.com" {
		t.Errorf("email=%v want released via the claims request", out["email"])
	}
}

// TestHandler_ReservedClaimsDoNotReachUserInfo drives both shapes with a
// source holding iss / aud and a claims request naming them: the signed
// body carries the OP issuer and the client_id, the JSON body neither.
func TestHandler_ReservedClaimsDoNotReachUserInfo(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-1", reservedSourceClaims)
	f.putClient(t, &store.Client{ID: "client-reserved"})
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = "client-reserved"
		c.Scope = []string{"openid"}
		c.UserInfoClaims = authorize.EncodeClaimsToGrant(&authorize.ClaimsRequest{
			UserInfo: map[string]authorize.ClaimSpec{"iss": {}, "aud": {}},
		})
	})

	resp := f.doRequest(t, f.newJWTAcceptGet(t, token))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwt shape: status=%d want 200", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	parsed, err := jwt.ParseSigned(strings.TrimSpace(string(raw)), []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	claims := map[string]any{}
	if err := parsed.Claims(f.signer.Signer.Public(), &claims); err != nil {
		t.Fatalf("verify Claims: %v", err)
	}
	if claims["iss"] != f.prov.Issuer {
		t.Errorf("iss=%v want %q", claims["iss"], f.prov.Issuer)
	}
	if claims["aud"] != "client-reserved" {
		t.Errorf("aud=%v want client-reserved", claims["aud"])
	}

	jsonResp := f.doRequest(t, f.newGet(t, token))
	defer jsonResp.Body.Close()
	body := decodeBody(t, jsonResp)
	for _, name := range []string{"iss", "aud"} {
		if v, ok := body[name]; ok {
			t.Errorf("json shape released %s=%v", name, v)
		}
	}
}
