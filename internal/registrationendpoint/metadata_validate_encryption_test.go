package registrationendpoint_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// jweFamily groups the five DCR encryption-pair metadata fields the
// validator gates on (OIDC Core 1.0 §6.1, §10.2, §5.3.2; FAPI 2.0
// Message Signing §5.5; RFC 9701 §4). Each family has an `_alg` and an
// `_enc` half; the helper drives the same matrix against every family
// so a regression on one surface (id_token, userinfo, request_object,
// authorization, introspection) cannot pass while the others fail.
type jweFamily struct {
	name    string
	algKey  string
	encKey  string
	algGood string
	encGood string
}

func jweFamilies() []jweFamily {
	return []jweFamily{
		{
			name:    "id_token",
			algKey:  "id_token_encrypted_response_alg",
			encKey:  "id_token_encrypted_response_enc",
			algGood: "RSA-OAEP-256",
			encGood: "A256GCM",
		},
		{
			name:    "userinfo",
			algKey:  "userinfo_encrypted_response_alg",
			encKey:  "userinfo_encrypted_response_enc",
			algGood: "RSA-OAEP-256",
			encGood: "A128GCM",
		},
		{
			name:    "request_object",
			algKey:  "request_object_encryption_alg",
			encKey:  "request_object_encryption_enc",
			algGood: "ECDH-ES",
			encGood: "A256GCM",
		},
		{
			name:    "authorization",
			algKey:  "authorization_encrypted_response_alg",
			encKey:  "authorization_encrypted_response_enc",
			algGood: "ECDH-ES+A128KW",
			encGood: "A128GCM",
		},
		{
			name:    "introspection",
			algKey:  "introspection_encrypted_response_alg",
			encKey:  "introspection_encrypted_response_enc",
			algGood: "ECDH-ES+A256KW",
			encGood: "A256GCM",
		},
	}
}

// TestRegister_JWEAlgEncPair_Matrix walks each of the five DCR
// encryption-pair families through the admit/reject matrix the M5+M6
// fix pins:
//
//   - both alg+enc set to a JOSE-allowed value -> 201
//   - alg only           -> 400 invalid_client_metadata (M6)
//   - enc only           -> 400 invalid_client_metadata (M6)
//   - both empty         -> 201 (signed-only path)
//   - alg=RSA1_5         -> 400 invalid_client_metadata (M5: jose.ParseJWEAlg gate)
//
// The RSA1_5 case in particular pins the M5 fix against future drift:
// the validator must reject any alg the internal/jose allow-list
// excludes, even one a stale hard-coded list might have admitted.
func TestRegister_JWEAlgEncPair_Matrix(t *testing.T) {
	t.Parallel()

	for _, fam := range jweFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			t.Parallel()

			cases := []struct {
				name       string
				mutate     func(map[string]any)
				wantStatus int
				wantError  string
			}{
				{
					name: "both_set_admitted",
					mutate: func(b map[string]any) {
						b[fam.algKey] = fam.algGood
						b[fam.encKey] = fam.encGood
					},
					wantStatus: http.StatusCreated,
				},
				{
					name: "alg_only_rejected",
					mutate: func(b map[string]any) {
						b[fam.algKey] = fam.algGood
					},
					wantStatus: http.StatusBadRequest,
					wantError:  "invalid_client_metadata",
				},
				{
					name: "enc_only_rejected",
					mutate: func(b map[string]any) {
						b[fam.encKey] = fam.encGood
					},
					wantStatus: http.StatusBadRequest,
					wantError:  "invalid_client_metadata",
				},
				{
					name:       "both_empty_admitted",
					mutate:     func(_ map[string]any) {},
					wantStatus: http.StatusCreated,
				},
				{
					name: "alg_rsa1_5_rejected",
					mutate: func(b map[string]any) {
						// RSA1_5 is intentionally NOT on the
						// jose.ParseJWEAlg allow-list. A stale
						// hard-coded local list could miss this; the
						// row pins the M5 fix.
						b[fam.algKey] = "RSA1_5"
						b[fam.encKey] = fam.encGood
					},
					wantStatus: http.StatusBadRequest,
					wantError:  "invalid_client_metadata",
				},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					f := newFixture(t, op.RegistrationOption{})
					_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})
					body := minimalMetadata()
					tc.mutate(body)
					resp := f.post(t, body, iat)
					defer resp.Body.Close()
					if resp.StatusCode != tc.wantStatus {
						raw, _ := io.ReadAll(resp.Body)
						t.Fatalf("status=%d want %d body=%s", resp.StatusCode, tc.wantStatus, raw)
					}
					if tc.wantError == "" {
						return
					}
					got := decodeBody(t, resp)
					if got["error"] != tc.wantError {
						t.Errorf("error=%v want %q", got["error"], tc.wantError)
					}
				})
			}
		})
	}
}

// TestRegister_JWEAlgEncPair_HalfPairErrorMessage confirms the
// half-pair rejection carries the operator-facing description shape the
// godoc on validateJWEAlgEncPair documents (RFC 7591 / OIDC Core §6.1
// citation, both field names listed). The message is wire-stable so
// embedders can pattern-match on it; pinning the substring here flags
// any drift.
func TestRegister_JWEAlgEncPair_HalfPairErrorMessage(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})
	body := minimalMetadata()
	body["id_token_encrypted_response_alg"] = "RSA-OAEP-256"
	resp := f.post(t, body, iat)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if got["error"] != "invalid_client_metadata" {
		t.Fatalf("error=%v want invalid_client_metadata", got["error"])
	}
	desc, _ := got["error_description"].(string)
	for _, want := range []string{
		"id_token_encrypted_response_alg",
		"id_token_encrypted_response_enc",
		"must be set together",
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("error_description=%q must contain %q", desc, want)
		}
	}
}
