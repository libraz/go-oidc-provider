package scenarios_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// TestAuthorizationCode_FailedPresentationKeepsOwnerGrant pins that a /token
// presentation failing the client or PKCE binding does not spend the code: the
// owner still redeems it, and the refresh token from an earlier redemption on
// the same grant is not torn down as replay fallout (RFC 6749 §4.1.3, RFC 7636
// §1).
func TestAuthorizationCode_FailedPresentationKeepsOwnerGrant(t *testing.T) {
	t.Parallel()

	const (
		ownerClientID  = "rp-fp-owner"
		callerClientID = "rp-fp-caller"
		callback       = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const ownerSecret = "rp-fp-owner-secret"
	//nolint:gosec // test fixture: not a real credential.
	const callerSecret = "rp-fp-caller-secret"

	ownerHash, err := op.HashClientSecret(ownerSecret)
	if err != nil {
		t.Fatalf("HashClientSecret(owner): %v", err)
	}
	callerHash, err := op.HashClientSecret(callerSecret)
	if err != nil {
		t.Fatalf("HashClientSecret(caller): %v", err)
	}

	tk := testkit.NewProvider(t)
	owner := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      ownerClientID,
		SecretHash:              ownerHash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      callerClientID,
		SecretHash:              callerHash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})

	runFlow := func() (string, scenariokit.PKCEPair) {
		pkce := scenariokit.NewPKCEPair("")
		flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
			ClientID:    owner.ID,
			RedirectURI: callback,
			Scope:       "openid offline_access",
			PKCE:        pkce,
		})
		if flow.Code == "" {
			t.Fatalf("authorize callback missing code: %+v", flow)
		}
		return flow.Code, pkce
	}

	earlierCode, earlierPKCE := runFlow()
	earlier := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         earlierCode,
		RedirectURI:  callback,
		Verifier:     earlierPKCE.Verifier,
		ClientID:     owner.ID,
		ClientSecret: ownerSecret,
	})
	if earlier.StatusCode != http.StatusOK || earlier.RefreshToken == "" {
		t.Fatalf("earlier /token status=%d body=%v, want 200 with refresh_token", earlier.StatusCode, earlier.Raw)
	}

	code, pkce := runFlow()
	wrongVerifier := strings.Repeat("w", 64)
	for _, bad := range []scenariokit.ExchangeCodeRequest{
		{Code: code, RedirectURI: callback, Verifier: pkce.Verifier, ClientID: callerClientID, ClientSecret: callerSecret},
		{Code: code, RedirectURI: callback, Verifier: wrongVerifier, ClientID: owner.ID, ClientSecret: ownerSecret},
	} {
		res := scenariokit.ExchangeCode(t, tk, bad)
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("failed presentation by %s status=%d body=%v, want 400", bad.ClientID, res.StatusCode, res.Raw)
		}
	}

	redeemed := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     owner.ID,
		ClientSecret: ownerSecret,
	})
	if redeemed.StatusCode != http.StatusOK {
		t.Fatalf("owner /token after failed presentations status=%d body=%v, want 200", redeemed.StatusCode, redeemed.Raw)
	}
	refresh := postRefreshToken(t, tk, earlier.RefreshToken, owner.ID, ownerSecret)
	if refresh.StatusCode != http.StatusOK {
		t.Fatalf("earlier refresh_token status=%d body=%v, want 200 (grant must survive)", refresh.StatusCode, refresh.Raw)
	}
}
