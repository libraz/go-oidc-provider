package tokenendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestCustomGrant_IDTokenEncryptedWhenClientRegistered pins that the
// id_token the OP signs for a custom grant is wrapped in the JWE the
// client registered for (OIDC Core 1.0 §10.2), as it is for every
// built-in grant, while a handler-supplied id_token passes verbatim.
func TestCustomGrant_IDTokenEncryptedWhenClientRegistered(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:encrypted-id-token"
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken: "test-access-token",
			Subject:     op.Subject("user-enc"),
			AuthTime:    clock.now.Add(-time.Minute),
			Scope:       []string{"openid"},
		},
	}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithCustomGrant(handler)),
	)
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token", clock: clock}
	client, secret := customGrantClient(t, prov, grantURN, []string{"openid"}, nil)
	rpKey := mustRSAKey2048(t)
	client.JWKs = rsaPrivJWK(t, rpKey, "rp-enc-cg")
	client.IDTokenEncryptedResponseAlg = "RSA-OAEP-256"
	client.IDTokenEncryptedResponseEnc = "A256GCM"
	if err := prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	resp := f.post(t, url.Values{"grant_type": []string{grantURN}}, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	idt, _ := decodeJSON(t, resp)["id_token"].(string)
	if got := strings.Count(idt, "."); got != 4 {
		t.Fatalf("id_token has %d dots, want 4 (compact JWE); the plain JWS reached the wire", got)
	}
	jwe, err := josev4.ParseEncrypted(idt,
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
	if got := decodeIDTokenClaims(t, string(plaintext))["sub"]; got != "user-enc" {
		t.Errorf("inner sub=%v want user-enc", got)
	}

	// A handler that signed its own id_token keeps it verbatim.
	handler.response.IDToken = "handler.signed.idtoken"
	resp2 := f.post(t, url.Values{"grant_type": []string{grantURN}}, client.ID, secret)
	defer resp2.Body.Close()
	if got, _ := decodeJSON(t, resp2)["id_token"].(string); got != "handler.signed.idtoken" {
		t.Errorf("handler-supplied id_token=%q want it passed through verbatim", got)
	}
}
