//nolint:testpackage // wires package-local dependencies into the HTTP handler.
package registrationendpoint

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestMetadataRoundTripSectorAndInlineJWKS drives the RFC 7591/7592
// POST → GET → PUT → GET sequence through a real HTTP server. It pins the
// requirement that every registered metadata value returned by the OP can be
// submitted on update without losing the pairwise sector or inline client
// keys.
func TestMetadataRoundTripSectorAndInlineJWKS(t *testing.T) {
	t.Parallel()

	const redirectURI = "https://rp.example.com/cb"
	sectorServer := newTLSSectorServer(t, http.StatusOK, `["`+redirectURI+`"]`)
	st := inmem.New()
	handler := Handler(Deps{
		Issuer:                   "https://op.example.com",
		RegisterPath:             "/register",
		Clients:                  st,
		InitialAccessTokens:      st.InitialAccessTokens(),
		RegistrationAccessTokens: st.RegistrationAccessTokens(),
		Open:                     true,
		SectorResolver:           newSectorTestResolver(sectorServer),
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	jwks := newClientJWKS(t)
	//nolint:gosec // G101 false positive: private_key_jwt is an OAuth method name, not a credential.
	created := doMetadataRequest(t, server.Client(), http.MethodPost, server.URL+"/register", "", map[string]any{
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "private_key_jwt",
		"sector_identifier_uri":      sectorServer.URL,
		"jwks":                       jwks,
	}, http.StatusCreated)
	assertMetadataValue(t, "POST", created, "sector_identifier_uri", sectorServer.URL)
	assertMetadataValue(t, "POST", created, "jwks", jwks)

	clientID := requiredString(t, created, "client_id")
	rat := requiredString(t, created, "registration_access_token")
	managementURL := server.URL + "/register/" + clientID

	read := doMetadataRequest(t, server.Client(), http.MethodGet, managementURL, rat, nil, http.StatusOK)
	assertMetadataValue(t, "GET", read, "sector_identifier_uri", sectorServer.URL)
	assertMetadataValue(t, "GET", read, "jwks", jwks)

	//nolint:gosec // G101 false positive: private_key_jwt is an OAuth method name, not a credential.
	updated := doMetadataRequest(t, server.Client(), http.MethodPut, managementURL, rat, map[string]any{
		"client_id":                  clientID,
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "private_key_jwt",
		"sector_identifier_uri":      read["sector_identifier_uri"],
		"jwks":                       read["jwks"],
	}, http.StatusOK)
	assertMetadataValue(t, "PUT", updated, "sector_identifier_uri", sectorServer.URL)
	assertMetadataValue(t, "PUT", updated, "jwks", jwks)

	rotatedRAT := requiredString(t, updated, "registration_access_token")
	finalRead := doMetadataRequest(t, server.Client(), http.MethodGet, managementURL, rotatedRAT, nil, http.StatusOK)
	assertMetadataValue(t, "final GET", finalRead, "sector_identifier_uri", sectorServer.URL)
	assertMetadataValue(t, "final GET", finalRead, "jwks", jwks)

	// RFC 7592 §2.2 treats omitted, null, and empty optional metadata as a
	// delete request. Exercise the explicit-null spelling because jwks used
	// to reach the parser as the literal bytes "null" and fail validation.
	cleared := doMetadataRequest(t, server.Client(), http.MethodPut, managementURL, rotatedRAT, map[string]any{
		"client_id":                  clientID,
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "none",
		"sector_identifier_uri":      nil,
		"jwks":                       nil,
	}, http.StatusOK)
	if _, ok := cleared["sector_identifier_uri"]; ok {
		t.Error("explicit null sector_identifier_uri must delete the metadata")
	}
	if _, ok := cleared["jwks"]; ok {
		t.Error("explicit null jwks must delete the metadata")
	}
}

func newClientJWKS(tb testing.TB) map[string]any {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("GenerateKey: %v", err)
	}
	raw, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key:       &key.PublicKey,
		KeyID:     "client-signing-key",
		Algorithm: "ES256",
		Use:       "sig",
	}}})
	if err != nil {
		tb.Fatalf("Marshal JWKS: %v", err)
	}
	var jwks map[string]any
	if err := json.Unmarshal(raw, &jwks); err != nil {
		tb.Fatalf("Unmarshal JWKS: %v", err)
	}
	return jwks
}

func doMetadataRequest(
	tb testing.TB,
	client *http.Client,
	method, target, bearer string,
	body any,
	wantStatus int,
) map[string]any {
	tb.Helper()
	var reader io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			tb.Fatalf("Marshal request: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, target, reader)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("%s request: %v", method, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		raw, _ := io.ReadAll(resp.Body)
		tb.Fatalf("%s status=%d want %d body=%s", method, resp.StatusCode, wantStatus, raw)
	}
	var decoded map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		tb.Fatalf("%s decode response: %v", method, err)
	}
	return decoded
}

func requiredString(tb testing.TB, body map[string]any, field string) string {
	tb.Helper()
	value, _ := body[field].(string)
	if value == "" {
		tb.Fatalf("%s missing from response: %+v", field, body)
	}
	return value
}

func assertMetadataValue(tb testing.TB, label string, body map[string]any, field string, want any) {
	tb.Helper()
	got, ok := body[field]
	if !ok {
		tb.Fatalf("%s: %s missing from response", label, field)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		tb.Fatalf("%s: marshal %s: %v", label, field, err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		tb.Fatalf("%s: marshal wanted %s: %v", label, field, err)
	}
	if !bytes.Equal(gotJSON, wantJSON) {
		tb.Errorf("%s: %s=%s want %s", label, field, gotJSON, wantJSON)
	}
}
