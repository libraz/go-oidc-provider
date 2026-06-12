package tokenendpoint_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op/store"
)

// rsaPrivJWK builds a JWKS document carrying the public half of priv
// with use=enc / alg=RSA-OAEP-256 / kid=kid. The document is the
// shape an RP would publish in its [store.Client.JWKs] field.
func rsaPrivJWK(t *testing.T, priv *rsa.PrivateKey, kid string) json.RawMessage {
	t.Helper()
	set := josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     kid,
			Use:       "enc",
			Algorithm: "RSA-OAEP-256",
		}},
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return body
}

// rsaSigJWK builds a JWKS document advertising only a use=sig key, so
// the encryption resolver finds nothing usable. The fixture exercises
// the ErrNoMatchingKey branch end-to-end.
func rsaSigJWK(t *testing.T, priv *rsa.PrivateKey, kid string) json.RawMessage {
	t.Helper()
	set := josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     kid,
			Use:       "sig",
			Algorithm: "RS256",
		}},
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return body
}

// mustRSAKey2048 mints a fresh 2048-bit RSA keypair. The bit floor
// matches the OP allow-list so the encryption resolver accepts the
// produced key.
func mustRSAKey2048(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func mustWeakRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // intentional weak key for floor-rejection test
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

// TestAuthCode_IDTokenEncryption_Disabled pins the legacy path: a
// client without id_token_encrypted_response_alg / _enc receives a
// plain three-segment JWS id_token regardless of resolver wiring.
func TestAuthCode_IDTokenEncryption_Disabled(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, challenge := pkcePair()
	const codeID = "code-enc-disabled"
	const grantID = "grant-enc-disabled"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "email"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "email"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-enc-disabled",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatal("id_token missing")
	}
	if got := strings.Count(idt, "."); got != 2 {
		t.Fatalf("id_token has %d dots, want 2 (JWS) — encryption fired without metadata", got)
	}
}

// TestAuthCode_IDTokenEncryption_Wraps drives the canonical OIDC
// Core 1.0 §10.2 path: the client registers
// id_token_encrypted_response_alg / _enc, publishes a use=enc key
// inline, and the OP wraps the signed id_token in a JWE addressed to
// that key. The decoded inner JWS is exercised against the unverified
// payload helper so the round-trip stays observable end-to-end.
func TestAuthCode_IDTokenEncryption_Wraps(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	rpKey := mustRSAKey2048(t)
	client.JWKs = rsaPrivJWK(t, rpKey, "rp-enc-1")
	client.IDTokenEncryptedResponseAlg = "RSA-OAEP-256"
	client.IDTokenEncryptedResponseEnc = "A256GCM"
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	verifier, challenge := pkcePair()
	const codeID = "code-enc-wraps"
	const grantID = "grant-enc-wraps"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "email"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "email"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-enc-wraps",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatal("id_token missing")
	}
	if got := strings.Count(idt, "."); got != 4 {
		t.Fatalf("id_token has %d dots, want 4 (compact JWE) — encryption did not fire", got)
	}

	// Decrypt with the RP's private key. ParseEncrypted accepts only
	// the alg/enc the OP issued so the test pins the wire shape.
	jwe, err := josev4.ParseEncrypted(
		idt,
		[]josev4.KeyAlgorithm{josev4.RSA_OAEP_256},
		[]josev4.ContentEncryption{josev4.A256GCM},
	)
	if err != nil {
		t.Fatalf("ParseEncrypted: %v", err)
	}
	plaintext, err := jwe.Decrypt(rpKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	inner := string(plaintext)
	if got := strings.Count(inner, "."); got != 2 {
		t.Fatalf("inner JWT has %d dots, want 2 (JWS)", got)
	}
	innerClaims := decodeIDTokenClaims(t, inner)
	if innerClaims["sub"] != subject {
		t.Errorf("inner sub=%v want %q", innerClaims["sub"], subject)
	}
	if innerClaims["nonce"] != "nonce-enc-wraps" {
		t.Errorf("inner nonce=%v want nonce-enc-wraps", innerClaims["nonce"])
	}
}

// TestAuthCode_IDTokenEncryption_NoMatchingKey_FailsClosed pins the
// fail-closed branch: the client registered encryption metadata but
// publishes only a use=sig key. The OP MUST refuse to issue the
// id_token (server_error) rather than silently emit it in the signed
// form, which would be a downgrade-attack surface.
func TestAuthCode_IDTokenEncryption_NoMatchingKey_FailsClosed(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	rpKey := mustRSAKey2048(t)
	client.JWKs = rsaSigJWK(t, rpKey, "rp-sig-only")
	client.IDTokenEncryptedResponseAlg = "RSA-OAEP-256"
	client.IDTokenEncryptedResponseEnc = "A256GCM"
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	verifier, challenge := pkcePair()
	const codeID = "code-enc-fail"
	const grantID = "grant-enc-fail"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "email"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "email"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-enc-fail",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "server_error" {
		t.Errorf("error=%v want server_error", body["error"])
	}
}

func TestAuthCode_IDTokenEncryption_WeakKey_FailsClosed(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	rpKey := mustWeakRSAKey(t)
	client.JWKs = rsaPrivJWK(t, rpKey, "rp-weak")
	client.IDTokenEncryptedResponseAlg = "RSA-OAEP-256"
	client.IDTokenEncryptedResponseEnc = "A256GCM"
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	verifier, challenge := pkcePair()
	const codeID = "code-enc-weak"
	const grantID = "grant-enc-weak"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid", "email"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-1",
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "email"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-enc-weak",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "server_error" {
		t.Errorf("error=%v want server_error", body["error"])
	}
}
