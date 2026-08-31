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
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
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
		fixtureAuthenticator(),
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
// document. The request_object / authorization / introspection arrays
// are gated on their respective features and tested in their own
// integration surfaces.
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

// TestDiscovery_OutboundEncryptionAdvertisedWithoutKeyset pins the
// capability the advertisement is supposed to describe. An id_token /
// userinfo response is encrypted to a key from the recipient client's
// JWKS, so an OP with no encryption keyset of its own serves them
// exactly as well as one with a keyset — and must say so. Gating these
// fields on op.WithEncryptionKeyset made a working OP advertise that it
// could not encrypt, and left "register a throwaway keyset" as the only
// workaround.
func TestDiscovery_OutboundEncryptionAdvertisedWithoutKeyset(t *testing.T) {
	t.Parallel()

	doc := fetchDiscoveryDoc(t, validBaseOpts(t))

	for _, k := range []string{
		"id_token_encryption_alg_values_supported",
		"id_token_encryption_enc_values_supported",
		"userinfo_encryption_alg_values_supported",
		"userinfo_encryption_enc_values_supported",
	} {
		values, ok := doc[k].([]any)
		if !ok || len(values) == 0 {
			t.Errorf("discovery must advertise %q without an encryption keyset, got %v", k, doc[k])
		}
	}
}

// TestDiscovery_InboundEncryptionRequiresKeyset pins the other half of
// the split: a request object is encrypted TO the OP, so the OP claims
// to accept one only when it holds a key to decrypt it.
func TestDiscovery_InboundEncryptionRequiresKeyset(t *testing.T) {
	t.Parallel()

	inbound := []string{
		"request_object_encryption_alg_values_supported",
		"request_object_encryption_enc_values_supported",
	}

	without := fetchDiscoveryDoc(t, append(validBaseOpts(t), op.WithFeature(feature.JAR)))
	for _, k := range inbound {
		if _, ok := without[k]; ok {
			t.Errorf("discovery must omit %q without an encryption keyset", k)
		}
	}

	with := fetchDiscoveryDoc(t, append(validBaseOpts(t),
		op.WithFeature(feature.JAR),
		op.WithEncryptionKeyset(op.EncryptionKeyset{{KeyID: "enc-1", PrivateKey: mustRSA(t)}}),
	))
	for _, k := range inbound {
		values, ok := with[k].([]any)
		if !ok || len(values) == 0 {
			t.Errorf("discovery must advertise %q with an encryption keyset, got %v", k, with[k])
		}
	}
}

// TestDiscovery_InboundEncryptionAlgsFollowKeyFamilies pins the
// inbound array to the key families the OP actually holds. An encrypted
// request object is addressed to the OP's own key, so advertising an
// alg no configured key can serve sends the RP looking for a recipient
// the JWKS does not contain and the request object it builds anyway
// comes back as an undiagnosable invalid_request_object.
//
// The outbound arrays are checked alongside because they must NOT
// shrink: those negotiate against the relying party's key and are
// unaffected by what the OP holds.
func TestDiscovery_InboundEncryptionAlgsFollowKeyFamilies(t *testing.T) {
	t.Parallel()

	ecAlgs := []string{"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"}
	for name, tc := range map[string]struct {
		keyset op.EncryptionKeyset
		want   []string
	}{
		"RSA only": {
			keyset: op.EncryptionKeyset{{KeyID: "enc-rsa", PrivateKey: mustRSA(t)}},
			want:   []string{"RSA-OAEP-256"},
		},
		"EC only": {
			keyset: op.EncryptionKeyset{{KeyID: "enc-ec", PrivateKey: mustECDSA(t, elliptic.P256())}},
			want:   ecAlgs,
		},
		"both families": {
			keyset: op.EncryptionKeyset{
				{KeyID: "enc-rsa", PrivateKey: mustRSA(t)},
				{KeyID: "enc-ec", PrivateKey: mustECDSA(t, elliptic.P384())},
			},
			want: op.SupportedEncryptionAlgs(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			doc := fetchDiscoveryDoc(t, append(validBaseOpts(t),
				op.WithFeature(feature.JAR),
				op.WithEncryptionKeyset(tc.keyset),
			))

			got := toStrings(t, doc["request_object_encryption_alg_values_supported"])
			if !slices.Equal(got, tc.want) {
				t.Errorf("request_object_encryption_alg_values_supported=%v want %v", got, tc.want)
			}
			outbound := toStrings(t, doc["id_token_encryption_alg_values_supported"])
			if !slices.Equal(outbound, op.SupportedEncryptionAlgs()) {
				t.Errorf(
					"id_token_encryption_alg_values_supported=%v want the full list %v",
					outbound, op.SupportedEncryptionAlgs(),
				)
			}
		})
	}
}

// TestDiscovery_InboundEncryptionAlgsIntersectNarrowing pins that the
// family filter composes with op.WithSupportedEncryptionAlgs rather
// than replacing it: the inbound array is the intersection, so a value
// either side excluded stays off the wire.
func TestDiscovery_InboundEncryptionAlgsIntersectNarrowing(t *testing.T) {
	t.Parallel()

	doc := fetchDiscoveryDoc(t, append(validBaseOpts(t),
		op.WithFeature(feature.JAR),
		op.WithEncryptionKeyset(op.EncryptionKeyset{
			{KeyID: "enc-ec", PrivateKey: mustECDSA(t, elliptic.P256())},
		}),
		op.WithSupportedEncryptionAlgs([]string{"RSA-OAEP-256", "ECDH-ES+A256KW"}, nil),
	))

	got := toStrings(t, doc["request_object_encryption_alg_values_supported"])
	if !slices.Equal(got, []string{"ECDH-ES+A256KW"}) {
		t.Errorf("request_object_encryption_alg_values_supported=%v want [ECDH-ES+A256KW]", got)
	}
}

// TestDiscovery_NarrowedEncryptionAlgsShrinkEveryFamily pins that
// op.WithSupportedEncryptionAlgs reaches the wire on every family at
// once, inbound and outbound, so the advertisement cannot disagree with
// what the runtime will accept.
//
// The keyset is EC because the narrowing keeps only an EC alg: an OP
// configured to negotiate ECDH-ES alone has no use for an RSA
// decryption key and does not construct.
func TestDiscovery_NarrowedEncryptionAlgsShrinkEveryFamily(t *testing.T) {
	t.Parallel()

	doc := fetchDiscoveryDoc(t, append(validBaseOpts(t),
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.JARM),
		op.WithFeature(feature.Introspect),
		op.WithEncryptionKeyset(op.EncryptionKeyset{
			{KeyID: "enc-1", PrivateKey: mustECDSA(t, elliptic.P256())},
		}),
		op.WithSupportedEncryptionAlgs([]string{"ECDH-ES"}, []string{"A256GCM"}),
	))

	for _, k := range []string{
		"id_token_encryption_alg_values_supported",
		"userinfo_encryption_alg_values_supported",
		"request_object_encryption_alg_values_supported",
		"authorization_encryption_alg_values_supported",
		"introspection_encryption_alg_values_supported",
	} {
		if got := doc[k]; !slices.Equal(toStrings(t, got), []string{"ECDH-ES"}) {
			t.Errorf("%s=%v want [ECDH-ES]", k, got)
		}
	}
	for _, k := range []string{
		"id_token_encryption_enc_values_supported",
		"userinfo_encryption_enc_values_supported",
		"request_object_encryption_enc_values_supported",
		"authorization_encryption_enc_values_supported",
		"introspection_encryption_enc_values_supported",
	} {
		if got := doc[k]; !slices.Equal(toStrings(t, got), []string{"A256GCM"}) {
			t.Errorf("%s=%v want [A256GCM]", k, got)
		}
	}
}

// TestWithEncryptionKeyset_WarnsAboveKidlessTrialCap covers the
// misconfiguration the kid-less trial cap makes possible: a deployment
// staging a long rotation with more keys of one family than the cap
// admits has every kid-less encrypted request object refused, with
// nothing in the response or the option surface naming the cause.
// Construction still succeeds, because relying parties that send kid —
// which is all of them, once they have read the OP's JWKS — are
// unaffected.
func TestWithEncryptionKeyset_WarnsAboveKidlessTrialCap(t *testing.T) {
	t.Parallel()

	ks := make(op.EncryptionKeyset, 0, op.MaxKidlessEncryptionTrialKeys+1)
	for i := range cap(ks) {
		ks = append(ks, op.EncryptionKey{
			KeyID:      "enc-" + strconv.Itoa(i),
			PrivateKey: mustECDSA(t, elliptic.P256()),
		})
	}

	logged := warnings(t, append(validBaseOpts(t), op.WithEncryptionKeyset(ks))...)
	if !strings.Contains(logged, "kid-less trial cap") {
		t.Errorf("logger output = %q, want a warning naming the kid-less trial cap", logged)
	}
}

// TestWithEncryptionKeyset_SilentAtKidlessTrialCap pins the boundary
// from the other side: a keyset exactly at the cap still decrypts every
// kid-less ciphertext, so warning there would train the operator to
// ignore the line. The count is per key family, so a set that is over
// the cap only in aggregate stays silent too.
func TestWithEncryptionKeyset_SilentAtKidlessTrialCap(t *testing.T) {
	t.Parallel()

	ks := make(op.EncryptionKeyset, 0, op.MaxKidlessEncryptionTrialKeys+1)
	for i := range op.MaxKidlessEncryptionTrialKeys {
		ks = append(ks, op.EncryptionKey{
			KeyID:      "enc-ec-" + strconv.Itoa(i),
			PrivateKey: mustECDSA(t, elliptic.P256()),
		})
	}
	ks = append(ks, op.EncryptionKey{KeyID: "enc-rsa", PrivateKey: mustRSA(t)})

	logged := warnings(t, append(validBaseOpts(t), op.WithEncryptionKeyset(ks))...)
	if strings.Contains(logged, "kid-less trial cap") {
		t.Errorf("logger output = %q, want no kid-less trial cap warning at the boundary", logged)
	}
}

// TestWithEncryptionKeyset_RejectsFamilyExcludedByNarrowing pins that
// op.WithSupportedEncryptionAlgs reaches the published JWK metadata too.
// A key whose whole family the narrowing removed can never decrypt
// anything, and publishing it would hand an RP that trusts the JWKS
// document over the discovery one a recipient the OP always refuses.
func TestWithEncryptionKeyset_RejectsFamilyExcludedByNarrowing(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithEncryptionKeyset(op.EncryptionKeyset{{KeyID: "enc-1", PrivateKey: mustRSA(t)}}),
		op.WithSupportedEncryptionAlgs([]string{"ECDH-ES"}, nil),
	)...)
	if err == nil {
		t.Fatal("New accepted an RSA encryption key under an EC-only alg narrowing")
	}
	if !strings.Contains(err.Error(), "narrowing") {
		t.Fatalf("err = %v, want it to name the alg narrowing as the cause", err)
	}
}

// TestJWKS_EncryptionKeyAlgsStayWithinNarrowing is the wire-level
// counterpart: whatever alg the OP stamps on a published use=enc JWK
// has to be one it would actually accept on an inbound ciphertext.
func TestJWKS_EncryptionKeyAlgsStayWithinNarrowing(t *testing.T) {
	t.Parallel()

	// ECDH-ES is the label an EC key carries by default, so narrowing it
	// away is what forces the advertisement onto a surviving member.
	allowed := []string{"ECDH-ES+A128KW"}
	provider, err := op.New(append(validBaseOpts(t),
		op.WithEncryptionKeyset(op.EncryptionKeyset{
			{KeyID: "enc-ec", PrivateKey: mustECDSA(t, elliptic.P256())},
		}),
		op.WithSupportedEncryptionAlgs(allowed, nil),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}

	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)
	resp := getJSON(t, srv.URL+"/oidc/jwks")
	defer resp.Body.Close()

	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	seen := false
	for _, k := range doc.Keys {
		if k.Use != "enc" {
			continue
		}
		seen = true
		if !slices.Contains(allowed, k.Alg) {
			t.Errorf("published enc key %q advertises alg %q outside the narrowing %v", k.Kid, k.Alg, allowed)
		}
	}
	if !seen {
		t.Fatal("jwks published no use=enc key")
	}
}

// TestDiscovery_EmptyEncryptionNarrowingOmitsEveryFamily pins the
// deliberate "publish keys, negotiate nothing" posture: narrowing to
// the empty set drops the whole family from the wire.
func TestDiscovery_EmptyEncryptionNarrowingOmitsEveryFamily(t *testing.T) {
	t.Parallel()

	doc := fetchDiscoveryDoc(t, append(validBaseOpts(t),
		op.WithFeature(feature.JAR),
		op.WithEncryptionKeyset(op.EncryptionKeyset{{KeyID: "enc-1", PrivateKey: mustRSA(t)}}),
		op.WithSupportedEncryptionAlgs([]string{}, nil),
	))

	for _, k := range []string{
		"id_token_encryption_alg_values_supported",
		"id_token_encryption_enc_values_supported",
		"userinfo_encryption_alg_values_supported",
		"request_object_encryption_alg_values_supported",
	} {
		if _, ok := doc[k]; ok {
			t.Errorf("discovery must omit %q when the inventory is narrowed to nothing", k)
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

// fetchDiscoveryDoc boots a Provider from opts, fetches its discovery
// document and returns it decoded.
func fetchDiscoveryDoc(t *testing.T, opts []op.Option) map[string]any {
	t.Helper()

	provider, err := op.New(opts...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)

	resp := getJSON(t, srv.URL+"/.well-known/openid-configuration")
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read discovery body: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal discovery: %v", err)
	}
	return doc
}

// toStrings converts a decoded JSON array into a []string so slice
// comparisons read directly.
func toStrings(t *testing.T, raw any) []string {
	t.Helper()

	values, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("discovery array member %v is not a string", v)
		}
		out = append(out, s)
	}
	return out
}

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
