package ssf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/op/store"
)

// mgmtInternalOrigin is the origin a request reaches the OP on behind a
// proxy that rewrites the host; the advertised URLs stay on testIssuer.
const mgmtInternalOrigin = "http://op-internal:8080"

// TestManagementDPoPHTUIsTheAdvertisedURL pins that every SSF endpoint
// compares a DPoP proof's htu with its advertised URL (issuer origin plus
// path, the stream id substituted at the poll endpoint), never with the
// scheme and host the request arrived on.
func TestManagementDPoPHTUIsTheAdvertisedURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, method string
		path, body   func(streamID string) string
		scope        []string
	}{
		{"configuration", http.MethodGet, func(id string) string { return mgmtStreamsPath + "?stream_id=" + id }, noBody, mgmtScopeRead},
		{"status", http.MethodGet, func(id string) string { return mgmtStatusPath + "?stream_id=" + id }, noBody, mgmtScopeRead},
		{"verification", http.MethodPost, func(string) string { return mgmtVerifyPath }, func(id string) string {
			return fmt.Sprintf(`{"stream_id":%q}`, id)
		}, mgmtScopeManage},
		{"poll", http.MethodPost, pollTarget, func(string) string { return "{}" }, mgmtScopeRead},
	} {
		for _, origin := range []string{testIssuer, mgmtInternalOrigin} {
			t.Run(tc.name+"/htu="+origin, func(t *testing.T) {
				t.Parallel()
				f := newMgmtFixture(t)
				s := seedStream(t, f.st, mgmtClientA, store.SSFStreamEnabled, store.SSFDeliveryPoll)
				target := tc.path(s.ID)
				htu := origin + strings.SplitN(target, "?", 2)[0]
				w := f.doWithHTU(t, tc.scope, tc.method, target, tc.body(s.ID), htu)
				if origin == testIssuer {
					if w.Code == http.StatusUnauthorized {
						t.Fatalf("proof naming the advertised URL refused: %d %s %s", w.Code, w.Header().Get("WWW-Authenticate"), w.Body)
					}
					return
				}
				if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), "DPoP proof rejected") {
					t.Fatalf("proof naming the request URL = %d %q, want 401 DPoP proof rejected", w.Code, w.Header().Get("WWW-Authenticate"))
				}
			})
		}
	}
}

func noBody(string) string { return "" }

// doWithHTU sends a DPoP-bound request to target on [mgmtInternalOrigin]
// whose proof names htu.
func (f *mgmtFixture) doWithHTU(t *testing.T, scope []string, method, target, body, htu string) *httptest.ResponseRecorder {
	t.Helper()
	raw := f.token(t, mgmtDPoP, mgmtClientA, scope, nil)
	r := httptest.NewRequestWithContext(context.Background(), method, mgmtInternalOrigin+target, strings.NewReader(body))
	r.Header.Set("Authorization", "DPoP "+raw)
	f.seq++
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: f.dpopKey},
		(&josev4.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", josev4.JSONWebKey{Key: &f.dpopKey.PublicKey}),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	proof, err := jwt.Signed(signer).Claims(map[string]any{
		"jti": fmt.Sprintf("proof-%d", f.seq), "htm": method, "htu": htu,
		"iat": testNow.Unix(), "ath": dpop.AccessTokenHash(raw),
	}).Serialize()
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	r.Header.Set("DPoP", proof)
	return f.serve(r)
}
