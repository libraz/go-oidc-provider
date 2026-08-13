package tokenendpoint_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// RFC 8707 §2 makes the resource indicator the audience the issued
// token is restricted to, and CIBA is the one grant where that binding
// has no black-box coverage: approving a backchannel request is not
// reachable from the public surface, so a wire-level test cannot get
// past authorization_pending to look at the token. The assertion
// therefore sits here, at the endpoint where an approved record can be
// seated directly — the same seam the acr / amr row uses for the same
// reason.
//
// The binding is what stops a token minted for one API from being
// replayed against another: a resource server that trusts "aud" is
// trusting exactly this step to have happened.

// TestHandleCIBA_AccessTokenBoundToRequestedResource pins the resource
// binding across a CIBA redemption: the access token's audience is the
// resource the backchannel request registered, and the refresh token
// minted alongside it carries the same resource so a later exchange
// cannot widen the audience.
func TestHandleCIBA_AccessTokenBoundToRequestedResource(t *testing.T) {
	t.Parallel()

	const resource = "https://api.example.com/orders"
	f := newCIBAFixture(t)
	f.seedCIBARequest(t, &store.CIBARequest{
		ID:       "auth-req-resource",
		Scope:    []string{"openid", "profile"},
		Status:   store.CIBARequestStatusPending,
		Resource: []string{resource},
	})
	if err := f.store.CIBARequests().Approve(
		context.Background(), "auth-req-resource", "user-77", "", f.clock.now,
	); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", "auth-req-resource")
	rec := f.post(t, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.AccessToken == "" {
		t.Fatalf("access_token missing: %s", rec.Body.String())
	}

	// A single resource encodes as a bare string per RFC 7519 §4.1.3,
	// which is the shape the /bc-authorize endpoint's one-resource limit
	// guarantees here.
	claims := decodeIDTokenClaims(t, body.AccessToken)
	if got, _ := claims["aud"].(string); got != resource {
		t.Errorf("access token aud = %v, want %q; a token the resource server accepts for one API "+
			"can be replayed against another when the binding is lost", claims["aud"], resource)
	}

	if body.RefreshToken == "" {
		t.Fatalf("refresh_token missing, so the rotation half of the binding cannot be checked: %s",
			rec.Body.String())
	}
	stored, err := f.store.RefreshTokens().Find(context.Background(), body.RefreshToken)
	if err != nil {
		t.Fatalf("Find refresh token: %v", err)
	}
	if stored.Resource != resource {
		t.Errorf("refresh token resource = %q, want %q; an exchange of this token would mint an "+
			"access token for a wider audience than the backchannel request asked for",
			stored.Resource, resource)
	}
}
