package registrationendpoint_test

import (
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestDCR_ClientMetadataIsTreatedAsAttackerInput pins that a
// registration request is validated as untrusted input rather than
// accepted as configuration.
//
// Dynamic registration inverts the usual trust direction. Everywhere
// else the OP compares a request against an allowlist an operator
// wrote; here the requester writes the entry. An initial access token
// is not an administrative credential — it is a ticket to ask for a
// client — so every member of the request has to earn its way into
// storage on its own contract. A member that is merely stored and
// replayed later becomes whatever the surface that replays it makes of
// it: an outbound fetch, a rendered page, or a capability the client
// was never granted.
//
// Tracks: CVE-2026-22752 (Spring Authorization Server) — the Dynamic
// Client Registration endpoints performed insufficient validation of
// client metadata, so a caller holding only a valid initial access
// token could register a client whose metadata produced stored XSS,
// privilege escalation, or SSRF (CVSS 9.6).
func TestDCR_ClientMetadataIsTreatedAsAttackerInput(t *testing.T) {
	t.Parallel()

	// uriMembers are the metadata fields the OP or an operator console
	// will later dereference. A scheme other than https turns each of
	// them into a request the registrant chose the destination of.
	uriMembers := []string{
		"jwks_uri",
		"sector_identifier_uri",
		"logo_uri",
		"client_uri",
		"policy_uri",
		"tos_uri",
		"initiate_login_uri",
		"backchannel_logout_uri",
	}
	hostileURIs := []struct {
		name string
		uri  string
	}{
		{"javascript scheme", "javascript:alert(1)"},
		{"data scheme", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="},
		{"file scheme reaching the OP's own disk", "file:///etc/passwd"},
		{"ftp scheme", "ftp://attacker.test.invalid/jwks.json"},
		{"plaintext http", "http://attacker.test.invalid/jwks.json"},
		{"scheme-relative reference", "//attacker.test.invalid/jwks.json"},
		{"relative reference", "/jwks.json"},
		{"credentials embedded in the authority", "https://user:pass@attacker.test.invalid/jwks.json"},
	}

	t.Run("URI members are refused unless they name an https resource", func(t *testing.T) {
		t.Parallel()

		for _, member := range uriMembers {
			for _, h := range hostileURIs {
				t.Run(member+"/"+h.name, func(t *testing.T) {
					t.Parallel()
					f := newFixture(t, op.RegistrationOption{})
					_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})
					body := map[string]any{
						"redirect_uris": []string{"https://rp.test.invalid/callback"},
						member:          h.uri,
					}
					// backchannel_logout_uri is only meaningful
					// alongside the session-supported flag; supply it
					// so the request fails on the URI rather than on
					// the coupling rule.
					if member == "backchannel_logout_uri" {
						body["backchannel_logout_session_required"] = false
					}
					resp := f.post(t, body, iat)
					t.Cleanup(func() { _ = resp.Body.Close() })
					if resp.StatusCode == http.StatusCreated {
						t.Fatalf("registration stored %s=%q; the OP or an operator console will dereference it",
							member, h.uri)
					}
					decoded := decodeBody(t, resp)
					if got, _ := decoded["error"].(string); got == "" {
						t.Errorf("rejection carries no error code; body=%v", decoded)
					}
				})
			}
		}
	})

	t.Run("a request cannot grant itself a capability the OP did not offer", func(t *testing.T) {
		t.Parallel()

		// Each row asks for authority beyond what the registration
		// policy or the initial access token permits. The refusal must
		// come from the OP's own policy, not from the request being
		// malformed — every value below is individually well-formed.
		cases := []struct {
			name  string
			patch map[string]any
			// iat narrows the initial access token where the row's
			// escalation is scoped to it rather than to global policy.
			iat op.InitialAccessTokenSpec
		}{
			{
				name:  "a grant type outside the OP's configured set",
				patch: map[string]any{"grant_types": []string{"authorization_code", "implicit"}},
			},
			{
				name:  "a response type outside the OP's configured set",
				patch: map[string]any{"response_types": []string{"token id_token"}},
			},
			{
				name:  "a scope the initial access token does not cover",
				patch: map[string]any{"scope": "openid admin"},
				iat:   op.InitialAccessTokenSpec{AllowedScopes: []string{"openid"}},
			},
			{
				name:  "an unregistered client authentication method",
				patch: map[string]any{"token_endpoint_auth_method": "client_secret_jwt_but_not_really"},
			},
			{
				name:  "a signing algorithm outside the OP's policy",
				patch: map[string]any{"id_token_signed_response_alg": "none"},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				f := newFixture(t, op.RegistrationOption{})
				_, iat := f.issueIAT(t, tc.iat)
				body := map[string]any{"redirect_uris": []string{"https://rp.test.invalid/callback"}}
				for k, v := range tc.patch {
					body[k] = v
				}
				resp := f.post(t, body, iat)
				t.Cleanup(func() { _ = resp.Body.Close() })
				if resp.StatusCode == http.StatusCreated {
					t.Fatalf("registration granted %v; a caller holding only an initial access token widened its own authority",
						tc.patch)
				}
			})
		}
	})

	t.Run("the response reports the authority the OP granted, not the one requested", func(t *testing.T) {
		t.Parallel()

		// A registrant that reads its own registration response must
		// see what the OP actually recorded. Echoing the request back
		// would let a client believe it holds capabilities the OP will
		// refuse at the token endpoint, and would hide the narrowing
		// from anyone auditing the response.
		f := newFixture(t, op.RegistrationOption{})
		_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})
		resp := f.post(t, map[string]any{
			"redirect_uris": []string{"https://rp.test.invalid/callback"},
			"grant_types":   []string{"authorization_code"},
			// Members the OP does not define. They must not survive
			// into the stored client or the response, whatever a
			// downstream consumer might make of them.
			"is_admin":                  true,
			"allowed_origins":           []string{"https://attacker.test.invalid"},
			"registration_access_token": "attacker-chosen-token",
		}, iat)
		t.Cleanup(func() { _ = resp.Body.Close() })
		if resp.StatusCode == http.StatusCreated {
			body := decodeBody(t, resp)
			for _, member := range []string{"is_admin", "allowed_origins"} {
				if got, ok := body[member]; ok {
					t.Errorf("response echoes undefined member %s=%v; the OP does not validate it and must not report it as accepted",
						member, got)
				}
			}
			// The registration access token is the OP's own credential
			// for the management endpoint. A registrant that could name
			// it would be choosing the secret that guards its record.
			if got, _ := body["registration_access_token"].(string); got == "attacker-chosen-token" {
				t.Error("the registrant chose its own registration_access_token; the credential guarding the client record must be OP-minted")
			}
			return
		}
		// Refusing the request outright is an equally sound answer to
		// undefined members, so long as it is not silently accepted.
		decoded := decodeBody(t, resp)
		if got, _ := decoded["error"].(string); got == "" {
			t.Errorf("registration neither succeeded nor reported an error; body=%v", decoded)
		}
	})
}
