package tokenendpoint_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// clientCredsClientWithResources registers a confidential client with
// the supplied scopes and RFC 8707 resource allowlist. Mirrors
// [clientCredsClient] but threads the Resources slice through the
// fixture so resource-indicator tests can exercise the allowlist gate.
func clientCredsClientWithResources(
	tb testing.TB,
	prov *testkit.Provider,
	id string,
	scopes, resources []string,
) (*store.Client, string) {
	tb.Helper()
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      id,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  scopes,
		Resources:               resources,
	})
	return client, secret
}

// TestClientCredentials_Resource is a table-driven exercise of the RFC
// 8707 §3 plumbing on the client_credentials grant: the resource form
// parameter MUST be validated against the client's Resources allowlist
// and, on success, MUST surface as the access token's "aud" claim.
// Absent resource MUST fall back to the issuer audience (RFC 9068
// §3 default). The cases are independent enough to run in parallel
// subtests; each registers its own client to avoid cross-test bleed
// through the in-memory store.
func TestClientCredentials_Resource(t *testing.T) {
	t.Parallel()

	const allowed = "https://api.example.com"
	const allowedAlt = "https://other.example.com"
	const disallowed = "https://api.unknown.example"

	cases := []struct {
		name           string
		clientID       string
		clientResource []string
		formResources  []string
		wantStatus     int
		wantError      string
		wantErrorDesc  string
		wantAudience   string
	}{
		{
			name:           "no resource keeps issuer audience",
			clientID:       "client-cc-noresource",
			clientResource: []string{allowed},
			formResources:  nil,
			wantStatus:     http.StatusOK,
		},
		{
			name:           "allowed resource binds aud",
			clientID:       "client-cc-allowed",
			clientResource: []string{allowed, allowedAlt},
			formResources:  []string{allowed},
			wantStatus:     http.StatusOK,
			wantAudience:   allowed,
		},
		{
			name:           "disallowed resource rejected",
			clientID:       "client-cc-denied",
			clientResource: []string{allowed},
			formResources:  []string{disallowed},
			wantStatus:     http.StatusBadRequest,
			wantError:      "invalid_target",
			wantErrorDesc:  "resource indicator is missing, or unknown",
		},
		{
			name:           "client without registered resources",
			clientID:       "client-cc-no-allowlist",
			clientResource: nil,
			formResources:  []string{allowed},
			wantStatus:     http.StatusBadRequest,
			wantError:      "invalid_target",
			wantErrorDesc:  "resource indicator is missing, or unknown",
		},
		{
			name:           "duplicate identical values tolerated",
			clientID:       "client-cc-dup-same",
			clientResource: []string{allowed},
			formResources:  []string{allowed, allowed},
			wantStatus:     http.StatusOK,
			wantAudience:   allowed,
		},
		{
			name:           "multiple distinct values rejected",
			clientID:       "client-cc-dup-diff",
			clientResource: []string{allowed, allowedAlt},
			formResources:  []string{allowed, allowedAlt},
			wantStatus:     http.StatusBadRequest,
			wantError:      "invalid_target",
			wantErrorDesc:  "only a single resource indicator value is supported",
		},
		{
			name:           "allowed plus disallowed rejected",
			clientID:       "client-cc-mixed",
			clientResource: []string{allowed},
			formResources:  []string{allowed, disallowed},
			wantStatus:     http.StatusBadRequest,
			wantError:      "invalid_target",
			wantErrorDesc:  "only a single resource indicator value is supported",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			client, secret := clientCredsClientWithResources(
				t, f.prov, tc.clientID,
				[]string{"read"},
				tc.clientResource,
			)

			form := url.Values{}
			form.Set("grant_type", "client_credentials")
			form.Set("scope", "read")
			for _, r := range tc.formResources {
				form.Add("resource", r)
			}

			resp := f.post(t, form, client.ID, secret)
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status=%d want %d body=%v",
					resp.StatusCode, tc.wantStatus, decodeJSON(t, resp))
			}

			body := decodeJSON(t, resp)
			if tc.wantError != "" {
				if got, _ := body["error"].(string); got != tc.wantError {
					t.Errorf("error=%v want %q", body["error"], tc.wantError)
				}
				if tc.wantErrorDesc != "" {
					if got, _ := body["error_description"].(string); got != tc.wantErrorDesc {
						t.Errorf("error_description=%q want %q", got, tc.wantErrorDesc)
					}
				}
				return
			}

			at, _ := body["access_token"].(string)
			if at == "" {
				t.Fatal("access_token missing on success path")
			}
			if strings.Contains(at, ".") {
				// JWT-format access token: decode and inspect aud.
				verifier := &tokens.AccessTokenVerifier{
					Keys: mustKeySet(t, f.prov), Issuer: f.prov.Issuer, Clock: f.clock,
				}
				parsed, _, err := verifier.Verify(at)
				if err != nil {
					t.Fatalf("AccessTokenVerifier.Verify: %v", err)
				}
				wantAud := tc.wantAudience
				if wantAud == "" {
					// Absent resource: aud falls back to the issuer.
					wantAud = f.prov.Issuer
				}
				if len(parsed.Audience) != 1 || parsed.Audience[0] != wantAud {
					t.Errorf("aud=%v want [%q]", parsed.Audience, wantAud)
				}
			} else {
				t.Fatalf("expected JWT access token, got opaque: %q", at)
			}
		})
	}
}
