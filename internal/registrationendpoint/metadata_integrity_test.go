package registrationendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestRegister_InternalClientAttributesNotWritable posts valid metadata
// laced with OP-internal store.Client attributes (under their snake_case,
// Go and JSON-tag-less spellings) and requires the stored record to carry
// none of the injected values: provenance, client-type, secret material,
// identity and the resource allow-list are assigned by the OP alone.
//
// Tracks: CVE-2026-105306 (Keycloak — dynamic client registration did not filter security-sensitive client attributes)
func TestRegister_InternalClientAttributesNotWritable(t *testing.T) {
	t.Parallel()

	const (
		injectedHash   = "$argon2id$injected-hash"
		injectedSecret = "attacker-chosen-secret"
		injectedID     = "attacker-chosen-id"
		injectedRes    = "https://internal.test.invalid/admin"
	)
	cases := map[string]struct {
		authMethod string
		publicWant bool
	}{
		"confidential": {authMethod: "client_secret_basic", publicWant: false},
		"public":       {authMethod: "none", publicWant: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, op.RegistrationOption{})
			_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})
			body := minimalMetadata()
			body["token_endpoint_auth_method"] = tc.authMethod
			for _, k := range []string{"resources", "Resources", "resource"} {
				body[k] = []string{injectedRes}
			}
			for _, k := range []string{"source", "Source"} {
				body[k] = string(store.ClientSourceStatic)
			}
			for _, k := range []string{"public_client", "PublicClient"} {
				body[k] = !tc.publicWant
			}
			for _, k := range []string{"secret_hash", "SecretHash"} {
				body[k] = injectedHash
			}
			body["client_secret"] = injectedSecret
			body["client_id"] = injectedID
			body["id"] = injectedID
			body["client_id_issued_at"] = 1

			resp := f.post(t, body, iat)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want 201 body=%s", resp.StatusCode, raw)
			}
			got := decodeBody(t, resp)
			clientID, _ := got["client_id"].(string)
			if clientID == "" || clientID == injectedID {
				t.Fatalf("client_id=%q, want an OP-minted identifier", clientID)
			}
			if _, err := f.prov.Store.GetClient(context.Background(), injectedID); err == nil {
				t.Errorf("a client was registered under the injected id %q", injectedID)
			}
			stored, err := f.prov.Store.GetClient(context.Background(), clientID)
			if err != nil {
				t.Fatalf("GetClient(%q): %v", clientID, err)
			}
			if len(stored.Resources) != 0 {
				t.Errorf("Resources=%v, want none from the wire", stored.Resources)
			}
			if stored.Source != store.ClientSourceDynamic {
				t.Errorf("Source=%q, want %q", stored.Source, store.ClientSourceDynamic)
			}
			if stored.PublicClient != tc.publicWant {
				t.Errorf("PublicClient=%v, want %v (derived from the auth method)", stored.PublicClient, tc.publicWant)
			}
			if stored.SecretHash == injectedHash {
				t.Error("SecretHash is the injected value")
			}
			if stored.ClientIDIssuedAt == 1 {
				t.Error("ClientIDIssuedAt is the injected value")
			}
			if tc.publicWant {
				if stored.SecretHash != "" {
					t.Errorf("public client stored a secret hash %q", stored.SecretHash)
				}
				return
			}
			issued, _ := got["client_secret"].(string)
			if issued == "" || issued == injectedSecret {
				t.Fatalf("client_secret=%q, want an OP-minted secret", issued)
			}
			verifier := &clientauth.Argon2id{}
			if err := verifier.Verify(issued, stored.SecretHash); err != nil {
				t.Errorf("issued secret does not verify against the stored hash: %v", err)
			}
			if err := verifier.Verify(injectedSecret, stored.SecretHash); err == nil {
				t.Error("the injected secret verifies against the stored hash")
			}
		})
	}
}

// roundTripMetadata extends the full standard set with the encrypted
// authorization and introspection response members, so every encryption
// pair the record persists is exercised.
func roundTripMetadata() map[string]any {
	body := fullStandardMetadata()
	body["authorization_encrypted_response_alg"] = "ECDH-ES"
	body["authorization_encrypted_response_enc"] = "A128GCM"
	body["introspection_encrypted_response_alg"] = "RSA-OAEP-256"
	body["introspection_encrypted_response_enc"] = "A256GCM"
	return body
}

// metadataWithInlineJWKS swaps the jwks_uri of the round-trip set for an
// inline jwks, the other (mutually exclusive) spelling of client keys. The
// set holds one signing key and one encryption key per key type the
// declared algorithms need.
func metadataWithInlineJWKS(tb testing.TB) map[string]any {
	tb.Helper()
	ecSig, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("GenerateKey EC sig: %v", err)
	}
	ecEnc, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("GenerateKey EC enc: %v", err)
	}
	rsaEnc, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("GenerateKey RSA: %v", err)
	}
	raw, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{
		{Key: &ecSig.PublicKey, KeyID: "ec-sig", Use: "sig", Algorithm: "ES256"},
		{Key: &ecEnc.PublicKey, KeyID: "ec-enc", Use: "enc"},
		{Key: &rsaEnc.PublicKey, KeyID: "rsa-enc", Use: "enc"},
	}})
	if err != nil {
		tb.Fatalf("Marshal JWKS: %v", err)
	}
	var jwks map[string]any
	if err := json.Unmarshal(raw, &jwks); err != nil {
		tb.Fatalf("Unmarshal JWKS: %v", err)
	}
	body := roundTripMetadata()
	delete(body, "jwks_uri")
	body["jwks"] = jwks
	return body
}

// TestManage_ReadModifyWriteIsLossless registers a client with every
// persisted metadata member set to a non-default value, then reads it,
// writes the read body back (reserved members stripped as RFC 7592 §2.2
// requires), and reads again. Responses and the stored record must be
// unchanged: a member omitted from the read response would be cleared by
// the write-back, silently disabling a setting.
//
// Tracks: CVE-2026-107623 (Keycloak — the registration response omitted a setting, so a read-modify-write silently disabled it)
func TestManage_ReadModifyWriteIsLossless(t *testing.T) {
	t.Parallel()

	variants := map[string]func(testing.TB) map[string]any{
		"jwks_uri":    func(testing.TB) map[string]any { return roundTripMetadata() },
		"inline_jwks": metadataWithInlineJWKS,
	}
	for name, build := range variants {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			f := newFixture(t, op.RegistrationOption{})
			created := f.register(t, build(t))
			stored0, err := f.prov.Store.GetClient(ctx, created.clientID)
			if err != nil {
				t.Fatalf("GetClient: %v", err)
			}

			read1 := f.manage(t, http.MethodGet, created.registrationClientURI, created.registrationAccessToken, nil)
			defer read1.Body.Close()
			if read1.StatusCode != http.StatusOK {
				raw, _ := io.ReadAll(read1.Body)
				t.Fatalf("GET status=%d body=%s", read1.StatusCode, raw)
			}
			get1 := decodeBody(t, read1)

			putBody := map[string]any{}
			for k, v := range get1 {
				switch k {
				case "registration_access_token", "registration_client_uri",
					"client_secret_expires_at", "client_id_issued_at", "client_secret":
					continue
				}
				putBody[k] = v
			}
			put := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, putBody)
			defer put.Body.Close()
			if put.StatusCode != http.StatusOK {
				raw, _ := io.ReadAll(put.Body)
				t.Fatalf("PUT status=%d body=%s", put.StatusCode, raw)
			}
			putResp := decodeBody(t, put)
			rotated, _ := putResp["registration_access_token"].(string)
			if rotated == "" {
				t.Fatalf("PUT response carries no rotated registration_access_token: %v", putResp)
			}

			read2 := f.manage(t, http.MethodGet, created.registrationClientURI, rotated, nil)
			defer read2.Body.Close()
			if read2.StatusCode != http.StatusOK {
				raw, _ := io.ReadAll(read2.Body)
				t.Fatalf("second GET status=%d body=%s", read2.StatusCode, raw)
			}
			get2 := decodeBody(t, read2)

			if !reflect.DeepEqual(get1, get2) {
				t.Errorf("metadata changed across read-modify-write:\nbefore=%v\nafter =%v", get1, get2)
			}
			delete(putResp, "registration_access_token")
			if !reflect.DeepEqual(putResp, get2) {
				t.Errorf("PUT response differs from the following GET:\nput=%v\nget=%v", putResp, get2)
			}
			stored1, err := f.prov.Store.GetClient(ctx, created.clientID)
			if err != nil {
				t.Fatalf("GetClient after PUT: %v", err)
			}
			if !reflect.DeepEqual(stored0, stored1) {
				t.Errorf("stored client changed across read-modify-write:\nbefore=%+v\nafter =%+v", stored0, stored1)
			}
			assertEveryMetadataFieldSet(t, stored0, name)
		})
	}
}

// assertEveryMetadataFieldSet fails when a store.Client field the
// registration surface persists is left at its zero value by the
// fixture, so a field added to the record without extending the
// round-trip fixture is caught here rather than passing vacuously.
func assertEveryMetadataFieldSet(t *testing.T, c *store.Client, variant string) {
	t.Helper()
	exempt := map[string]string{ //nolint:gosec // Field names and reasons, not credentials.
		"Resources":                        "operator-only allow-list, not registration metadata",
		"PublicClient":                     "false for a confidential auth method",
		"SectorIdentifierURI":              "needs a pairwise OP and a fetched sector document",
		"BackchannelLogoutSessionRequired": "true is refused by this OP",
		"PreviousSecretHash":               "set by secret rotation, not by registration",
		"PreviousSecretExpiresAt":          "set by secret rotation, not by registration",
	}
	if variant == "jwks_uri" {
		exempt["JWKs"] = "mutually exclusive with jwks_uri"
	} else {
		exempt["JWKsURI"] = "mutually exclusive with jwks"
	}
	v := reflect.ValueOf(c).Elem()
	for i := range v.NumField() {
		name := v.Type().Field(i).Name
		if _, ok := exempt[name]; ok {
			continue
		}
		if v.Field(i).IsZero() {
			t.Errorf("store.Client.%s is zero in the round-trip fixture; extend the fixture", name)
		}
	}
}
