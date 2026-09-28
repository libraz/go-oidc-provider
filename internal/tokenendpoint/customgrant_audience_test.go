package tokenendpoint_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestCustomGrant_BoundAudienceMatchesRefreshedAudience pins that a
// handler stating only the response-level Audience gets that audience on
// the first bound access token, the same one every access token minted
// by refreshing the chain carries.
func TestCustomGrant_BoundAudienceMatchesRefreshedAudience(t *testing.T) {
	t.Parallel()

	const (
		grantURN = "urn:example:grant-type:bound-audience"
		resource = "https://api.example.com/orders"
	)
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			BoundAccessToken:  &op.BoundAccessToken{Subject: op.Subject("user-aud")},
			IssueRefreshToken: true,
			Subject:           op.Subject("user-aud"),
			Scope:             []string{"read"},
			Audience:          []string{resource},
		},
	}
	f, _ := customGrantAuditFixture(t, handler)
	client, secret := customGrantRefreshClient(t, f.prov, "client-cg-bound-aud", grantURN, []string{"read"}, []string{resource})

	resp := f.post(t, url.Values{"grant_type": []string{grantURN}}, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	first, _ := body["access_token"].(string)
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("refresh_token missing; body=%v", body)
	}

	refreshResp := f.post(t, url.Values{
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{rt},
	}, client.ID, secret)
	defer refreshResp.Body.Close()
	if refreshResp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d want 200 body=%v", refreshResp.StatusCode, decodeJSON(t, refreshResp))
	}
	refreshed, _ := decodeJSON(t, refreshResp)["access_token"].(string)

	firstAud := audienceOf(t, decodeJWTPayload(t, first)["aud"])
	refreshedAud := audienceOf(t, decodeJWTPayload(t, refreshed)["aud"])
	if len(firstAud) != 1 || firstAud[0] != resource {
		t.Errorf("first access token aud=%v want [%s]", firstAud, resource)
	}
	if len(refreshedAud) != 1 || refreshedAud[0] != firstAud[0] {
		t.Errorf("refreshed access token aud=%v, first aud=%v; the chain must keep one audience", refreshedAud, firstAud)
	}
}

// audienceOf normalises the RFC 7519 §4.1.3 string-or-array aud shape.
func audienceOf(t *testing.T, raw any) []string {
	t.Helper()
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, _ := e.(string)
			out = append(out, s)
		}
		return out
	default:
		t.Fatalf("aud=%v has unexpected shape", raw)
		return nil
	}
}
