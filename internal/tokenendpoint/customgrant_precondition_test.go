package tokenendpoint_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestCustomGrant_NoTokenEscapesAFailedPrecondition pins the ordering
// rule that makes custom grants safe to expose: every precondition the OP
// owns is settled before anything that could become a credential is
// produced, and a request that fails one leaves nothing behind.
//
// A custom grant is the one token-endpoint path where embedder code
// decides who gets a token, so the OP's own gate — is this client
// registered for this grant type at all? — is the only thing standing
// between a handler and a caller it was never meant to serve. Running the
// handler first and checking afterwards would be a different posture even
// when the wire response is identical: the handler may have minted a
// token against its own backend, recorded an authorisation, or charged a
// quota, none of which the OP can take back by returning 400.
//
// The two rows cover the gate on each side of the handler. A client not
// registered for the grant type never reaches the handler at all. A
// handler that runs but returns a response violating a registered limit
// has its whole response discarded rather than partially honoured.
//
// Tracks: CVE-2026-1486 (Keycloak) — the JWT authorization-grant path
// issued tokens without checking that the backing identity provider was
// enabled, skipping an authorisation gate on the issuance path itself.
func TestCustomGrant_NoTokenEscapesAFailedPrecondition(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:precondition"

	cases := []struct {
		name string
		// clientGrantTypes is what the client is actually registered
		// for; the request always asks for grantURN.
		clientGrantTypes []string
		clientScopes     []string
		responseScope    []string
		wantError        string
		wantHandlerRan   bool
	}{
		{
			name:             "client not registered for the grant type",
			clientGrantTypes: []string{"authorization_code"},
			clientScopes:     []string{"read"},
			responseScope:    []string{"read"},
			wantError:        "unauthorized_client",
			wantHandlerRan:   false,
		},
		{
			name:             "handler response exceeds the registered scope",
			clientGrantTypes: []string{grantURN, "refresh_token"},
			clientScopes:     []string{"read"},
			responseScope:    []string{"read", "write"},
			wantError:        "invalid_scope",
			wantHandlerRan:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := &recordingGrant{
				name: grantURN,
				response: op.CustomGrantResponse{
					AccessToken:       "handler-minted-access-token",
					IssueRefreshToken: true,
					Subject:           op.Subject("user-precondition"),
					Scope:             tc.responseScope,
				},
			}
			prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
			f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token"}

			const secret = "shh-its-a-secret"
			hasher := clientauth.Argon2id{}
			hash, err := hasher.Hash(secret)
			if err != nil {
				t.Fatalf("Argon2id.Hash: %v", err)
			}
			client := prov.RegisterClient(t, testkit.ClientFixture{
				ID:                      "client-cg-precondition",
				SecretHash:              hash,
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              tc.clientGrantTypes,
				Scopes:                  tc.clientScopes,
			})

			resp := f.post(t, url.Values{"grant_type": []string{grantURN}}, client.ID, secret)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status=%d want 400; body=%v", resp.StatusCode, decodeJSON(t, resp))
			}
			body := decodeJSON(t, resp)
			if got, _ := body["error"].(string); got != tc.wantError {
				t.Errorf("error=%q want %q; body=%v", got, tc.wantError, body)
			}
			// Nothing that a caller could present anywhere may survive a
			// rejected request, whichever gate rejected it.
			for _, field := range []string{"access_token", "refresh_token", "id_token"} {
				if got, ok := body[field]; ok {
					t.Errorf("rejected response carries %s=%v", field, got)
				}
			}
			if ran := handler.gotReq.Client != nil; ran != tc.wantHandlerRan {
				if ran {
					t.Errorf("handler ran despite a precondition the OP could settle first; " +
						"a handler that mints or records anything of its own cannot be rolled back by a 400")
				} else {
					t.Errorf("handler never ran; the fixture no longer exercises the gate it was written for")
				}
			}
		})
	}
}
