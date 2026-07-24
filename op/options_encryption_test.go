package op_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/op"
)

// TestSupportedEncryptionAlgs_Snapshot pins the public discovery
// surface. The list shape is observable to RPs via the shipped
// op.SupportedEncryptionAlgs() helper, so a drift here is a wire
// change embedders depend on.
func TestSupportedEncryptionAlgs_Snapshot(t *testing.T) {
	t.Parallel()

	want := []string{"RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"}
	got := op.SupportedEncryptionAlgs()
	if !slices.Equal(got, want) {
		t.Fatalf("alg list drift: got %v want %v", got, want)
	}
}

// TestSupportedEncryptionEncs_Snapshot pins the enc list shape.
func TestSupportedEncryptionEncs_Snapshot(t *testing.T) {
	t.Parallel()

	want := []string{"A128GCM", "A256GCM"}
	got := op.SupportedEncryptionEncs()
	if !slices.Equal(got, want) {
		t.Fatalf("enc list drift: got %v want %v", got, want)
	}
}

// TestWithEncryptionKeyset_RejectsEmpty asserts the option-site empty
// guard. An empty keyset is a misconfiguration (the embedder meant to
// register at least one key), not a "JWE off" signal — that is
// achieved by omitting the option entirely.
func TestWithEncryptionKeyset_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithEncryptionKeyset(op.EncryptionKeyset{}))...)
	if err == nil {
		t.Fatalf("expected error for empty encryption keyset, got nil")
	}
	if !strings.Contains(err.Error(), "WithEncryptionKeyset") {
		t.Fatalf("error %v does not name the option", err)
	}
}

// TestWithEncryptionKeyset_RejectsNilPrivateKey guards the nil-key
// path — a configuration smell that would otherwise surface as a
// runtime nil deref on first decryption attempt.
func TestWithEncryptionKeyset_RejectsNilPrivateKey(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithEncryptionKeyset(op.EncryptionKeyset{
			{KeyID: "enc-1", PrivateKey: nil},
		}),
	)...)
	if err == nil {
		t.Fatalf("expected error for nil PrivateKey, got nil")
	}
}

func TestWithEncryptionKeyset_RejectsTypedNilPrivateKeyBeforeMetricsRegistration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		key  any
	}{
		{name: "rsa", key: (*rsa.PrivateKey)(nil)},
		{name: "ecdsa", key: (*ecdsa.PrivateKey)(nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			registry := prometheus.NewRegistry()
			_, err := op.New(append(validBaseOpts(t),
				op.WithPrometheus(registry),
				op.WithEncryptionKeyset(op.EncryptionKeyset{{
					KeyID:      "typed-nil-" + tc.name,
					PrivateKey: tc.key,
				}}),
			)...)
			if err == nil {
				t.Fatal("op.New accepted a typed-nil encryption PrivateKey")
			}
			if !op.IsServerError(err) {
				t.Fatalf("typed-nil PrivateKey error is not a configuration error: %v", err)
			}
			if !strings.Contains(err.Error(), "entry 0 PrivateKey") {
				t.Fatalf("error %q does not identify the typed-nil field", err)
			}

			// A second construction using the same registry succeeds only if
			// validation rejected the typed nil before registering collectors.
			if _, err := op.New(append(validBaseOpts(t), op.WithPrometheus(registry))...); err != nil {
				t.Fatalf("typed-nil validation left a metrics side effect: %v", err)
			}
		})
	}
}

// TestWithEncryptionKeyset_RejectsKidCollision enforces the RFC 7517
// §4.2 use=sig / use=enc separation: a kid that appears in both
// keysets is a configuration error even when the underlying material
// is disjoint, because the published JWKS would carry the same kid
// twice with conflicting use values.
func TestWithEncryptionKeyset_RejectsKidCollision(t *testing.T) {
	t.Parallel()

	signing := newTestKey(t, "shared-kid")
	rsaKey := mustRSA(t)

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(op.Keyset{signing}),
		op.WithCookieKeys(newRandomCookieKey(t)),
		op.WithEncryptionKeyset(op.EncryptionKeyset{
			{KeyID: "shared-kid", PrivateKey: rsaKey},
		}),
	)
	if err == nil {
		t.Fatalf("expected error for kid collision, got nil")
	}
	if !strings.Contains(err.Error(), "shared-kid") {
		t.Fatalf("error %v does not name the colliding kid", err)
	}
}

// TestWithEncryptionKeyset_RejectsBadAlg asserts that an alg outside
// the v0.9.1 closed allow-list (e.g. RSA1_5) is rejected at
// construction time, even when paired with a structurally valid RSA
// key.
func TestWithEncryptionKeyset_RejectsBadAlg(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSA(t)
	_, err := op.New(append(validBaseOpts(t),
		op.WithEncryptionKeyset(op.EncryptionKeyset{
			{KeyID: "enc-1", PrivateKey: rsaKey, Algorithm: "RSA1_5"},
		}),
	)...)
	if err == nil {
		t.Fatalf("expected error for RSA1_5 alg, got nil")
	}
}

// TestWithEncryptionKeyset_RejectsAlgKeyMismatch asserts that an alg
// from the wrong family for the supplied key shape (e.g. ECDH-ES on
// an RSA key) is rejected; the inferred-from-shape default lands the
// embedder on a sensible alg, so an explicit mismatch is intentional
// misuse.
func TestWithEncryptionKeyset_RejectsAlgKeyMismatch(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSA(t)
	_, err := op.New(append(validBaseOpts(t),
		op.WithEncryptionKeyset(op.EncryptionKeyset{
			{KeyID: "enc-1", PrivateKey: rsaKey, Algorithm: "ECDH-ES"},
		}),
	)...)
	if err == nil {
		t.Fatalf("expected error for alg/key mismatch, got nil")
	}
}

// TestWithEncryptionKeyset_AcceptsRSA covers the happy path: an RSA
// 2048-bit key with the inferred alg builds a Provider whose
// discovery document advertises the encryption fields.
func TestWithEncryptionKeyset_AcceptsRSA(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSA(t)
	provider, err := op.New(append(validBaseOpts(t),
		op.WithEncryptionKeyset(op.EncryptionKeyset{
			{KeyID: "enc-1", PrivateKey: rsaKey},
		}),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}

// TestWithEncryptionKeyset_AcceptsECDSA covers the EC happy path
// across all permitted curves; P-224 and unsupported curves are
// rejected by the internal validator.
func TestWithEncryptionKeyset_AcceptsECDSA(t *testing.T) {
	t.Parallel()

	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			t.Parallel()

			ecKey := mustECDSA(t, curve)
			_, err := op.New(append(validBaseOpts(t),
				op.WithEncryptionKeyset(op.EncryptionKeyset{
					{KeyID: "enc-1", PrivateKey: ecKey},
				}),
			)...)
			if err != nil {
				t.Fatalf("op.New with %s: %v", curve.Params().Name, err)
			}
		})
	}
}

// TestWithEncryptionKeyset_RejectsP224 asserts that the P-224 curve
// is rejected — the OP only supports P-256 / P-384 / P-521, matching
// the JWS keyset policy.
func TestWithEncryptionKeyset_RejectsP224(t *testing.T) {
	t.Parallel()

	ecKey := mustECDSA(t, elliptic.P224())
	_, err := op.New(append(validBaseOpts(t),
		op.WithEncryptionKeyset(op.EncryptionKeyset{
			{KeyID: "enc-1", PrivateKey: ecKey},
		}),
	)...)
	if err == nil {
		t.Fatalf("expected error for P-224 curve, got nil")
	}
}

// TestWithSupportedEncryptionAlgs_RejectsUnknownAlg asserts that the
// embedder cannot extend the closed allow-list — the option only
// narrows.
func TestWithSupportedEncryptionAlgs_RejectsUnknownAlg(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithSupportedEncryptionAlgs([]string{"RSA1_5"}, nil),
	)...)
	if err == nil {
		t.Fatalf("expected error for RSA1_5 in narrowing list, got nil")
	}
}

// TestWithSupportedEncryptionAlgs_RejectsUnknownEnc covers the enc
// side of the narrowing guard.
func TestWithSupportedEncryptionAlgs_RejectsUnknownEnc(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithSupportedEncryptionAlgs(nil, []string{"A128CBC-HS256"}),
	)...)
	if err == nil {
		t.Fatalf("expected error for A128CBC-HS256 in narrowing list, got nil")
	}
}

// TestDiscovery_AdvertisesEncryptionFields asserts that the
// id_token / userinfo encryption arrays land in the discovery
// document when an encryption keyset is registered. The
// request_object / authorization / introspection arrays are gated on
// their respective features and tested in their own integration
// surfaces.
func TestDiscovery_AdvertisesEncryptionFields(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSA(t)
	provider, err := op.New(append(validBaseOpts(t),
		op.WithEncryptionKeyset(op.EncryptionKeyset{
			{KeyID: "enc-1", PrivateKey: rsaKey},
		}),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}

	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)

	resp := getJSON(t, srv.URL+"/.well-known/openid-configuration")
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	wantPresent := []string{
		"id_token_encryption_alg_values_supported",
		"id_token_encryption_enc_values_supported",
		"userinfo_encryption_alg_values_supported",
		"userinfo_encryption_enc_values_supported",
	}
	for _, k := range wantPresent {
		if _, ok := doc[k]; !ok {
			t.Errorf("discovery missing key %q", k)
		}
	}
	algs, _ := doc["id_token_encryption_alg_values_supported"].([]any)
	if len(algs) == 0 || algs[0] != "RSA-OAEP-256" {
		t.Errorf("id_token alg list shape: got %v", algs)
	}
}

// TestDiscovery_OmitsEncryptionFields asserts that an OP without an
// encryption keyset keeps the *_encryption_*_values_supported fields
// absent from the wire (omitempty). Embedders who do not want JWE
// must not see the fields advertised even as empty arrays.
func TestDiscovery_OmitsEncryptionFields(t *testing.T) {
	t.Parallel()

	provider, err := op.New(validBaseOpts(t)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)

	resp := getJSON(t, srv.URL+"/.well-known/openid-configuration")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)

	for _, k := range []string{
		"id_token_encryption_alg_values_supported",
		"userinfo_encryption_alg_values_supported",
	} {
		if _, ok := doc[k]; ok {
			t.Errorf("discovery should omit %q when JWE is off", k)
		}
	}
}

// TestJWKS_PublishesEncryptionKeys asserts the JWKS endpoint includes
// the use=enc public halves alongside the use=sig signing keys, so
// RPs can fetch the encryption key by kid for outbound request_object
// encryption to the OP.
func TestJWKS_PublishesEncryptionKeys(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSA(t)
	provider, err := op.New(append(validBaseOpts(t),
		op.WithEncryptionKeyset(op.EncryptionKeyset{
			{KeyID: "enc-1", PrivateKey: rsaKey},
		}),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}

	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)

	resp := getJSON(t, srv.URL+"/oidc/jwks")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("unmarshal jwks: %v\nbody: %s", err, body)
	}

	var sawEnc, sawSig bool
	for _, k := range jwks.Keys {
		switch k["use"] {
		case "enc":
			if k["kid"] == "enc-1" {
				sawEnc = true
				if k["alg"] != "RSA-OAEP-256" {
					t.Errorf("enc-1 alg: got %v want RSA-OAEP-256", k["alg"])
				}
			}
		case "sig":
			sawSig = true
		}
	}
	if !sawSig {
		t.Errorf("jwks missing use=sig key")
	}
	if !sawEnc {
		t.Errorf("jwks missing use=enc key with kid enc-1")
	}
}

// --- helpers --------------------------------------------------------

// getJSON is the test-only HTTP GET helper that satisfies the noctx
// linter. The default httptest server scope keeps the request short-
// lived, so a context backed by [t.Context()] is sufficient.
func getJSON(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func mustECDSA(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return k
}
