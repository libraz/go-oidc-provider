package scenariokit

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
)

// rpJWKEntry mirrors the JSON shape RFC 7517 §4 mandates for an RSA
// public key advertised with use=enc. The struct is package-private —
// tests use [RPEncryptionKey.JWKS] which already carries the marshalled
// representation.
type rpJWKEntry struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type rpJWKSet struct {
	Keys []rpJWKEntry `json:"keys"`
}

// NewOPEncryptionKey returns a fresh 2048-bit RSA private key wrapped
// in [op.EncryptionKey] with the supplied kid. The result is intended
// to drop straight into an [op.EncryptionKeyset] passed to
// [op.WithEncryptionKeyset]; the algorithm is left empty so the OP
// infers RSA-OAEP-256 (RFC 7518 §4.3) at construction time.
//
// Each call produces fresh key material so parallel scenarios do not
// share secrets.
func NewOPEncryptionKey(tb testing.TB, kid string) op.EncryptionKey {
	tb.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("scenariokit: rsa.GenerateKey: %v", err)
	}
	return op.EncryptionKey{KeyID: kid, PrivateKey: priv}
}

// RPEncryptionKey bundles the private RSA key kept on the relying-party
// side with the JWKS document the same key advertises (RFC 7517 §4.2,
// use=enc). Tests register [JWKS] on the testkit client fixture and
// keep [Private] for [DecryptJWE] use after the OP wraps a token.
type RPEncryptionKey struct {
	// KID is the "kid" header stamped on the published JWK and
	// echoed back on the OP's outbound JWE protected header.
	KID string

	// Private is the RSA private key the test uses to decrypt JWE
	// tokens addressed to [KID]. The key MUST stay test-local; it
	// is never sent over the wire.
	Private *rsa.PrivateKey

	// JWKS is the marshalled `{"keys":[...]}` document the testkit
	// installs on [op.testkit.ClientFixture.JWKs]. The single key
	// inside carries kty=RSA, use=enc, alg=RSA-OAEP-256 plus the
	// public n / e in base64url (RFC 7518 §6.3.1).
	JWKS json.RawMessage
}

// NewRPEncryptionKey generates a fresh 2048-bit RSA keypair and returns
// the relying-party-side bundle. The serialised JWKS carries exactly
// one key with kty=RSA, use=enc, alg=RSA-OAEP-256, and the supplied
// kid so the OP's clientencjwks resolver picks it as the encryption
// recipient.
func NewRPEncryptionKey(tb testing.TB, kid string) RPEncryptionKey {
	tb.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("scenariokit: rsa.GenerateKey: %v", err)
	}
	pub := &priv.PublicKey
	entry := rpJWKEntry{
		Kty: "RSA",
		Use: "enc",
		Alg: "RSA-OAEP-256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigIntBytesE(pub.E)),
	}
	doc, err := json.Marshal(rpJWKSet{Keys: []rpJWKEntry{entry}})
	if err != nil {
		tb.Fatalf("scenariokit: marshal jwks: %v", err)
	}
	return RPEncryptionKey{KID: kid, Private: priv, JWKS: doc}
}

// bigIntBytesE marshals an RSA public exponent into the minimum-length
// big-endian byte slice the JWK "e" parameter expects (RFC 7518 §6.3.1
// Base64urlUInt encoding). The exponent is canonical (typically 65537,
// 0x010001) so a tight three-byte slice is sufficient.
func bigIntBytesE(e int) []byte {
	if e <= 0 {
		return []byte{0}
	}
	var buf [8]byte
	for i := 7; i >= 0; i-- {
		buf[i] = byte(e & 0xff)
		e >>= 8
		if e == 0 {
			return buf[i:]
		}
	}
	return buf[:]
}

// DecryptJWE parses jwe as a JWE compact serialisation (RFC 7516 §3),
// decrypts it with priv, and returns the inner JWS compact string the
// JWE wrapped. The function asserts the JWE protected header carries
// cty=JWT (RFC 7519 §5.2) so callers exercising the nested-JWT shape
// do not need to re-decode the header.
func DecryptJWE(tb testing.TB, jwe string, priv *rsa.PrivateKey) string {
	tb.Helper()
	parsed, err := josev4.ParseEncrypted(jwe,
		[]josev4.KeyAlgorithm{josev4.RSA_OAEP_256},
		[]josev4.ContentEncryption{josev4.A128GCM, josev4.A256GCM})
	if err != nil {
		tb.Fatalf("scenariokit: parse JWE: %v", err)
	}
	if cty, _ := parsed.Header.ExtraHeaders[josev4.HeaderContentType].(string); cty != "JWT" {
		tb.Fatalf("scenariokit: JWE cty=%q want JWT", cty)
	}
	plain, err := parsed.Decrypt(priv)
	if err != nil {
		tb.Fatalf("scenariokit: decrypt JWE: %v", err)
	}
	return string(plain)
}

// DecodeJWSClaims base64url-decodes the payload segment of a JWS
// compact serialisation (RFC 7515 §7.1) and json.Unmarshals it. The
// helper does NOT verify the signature — callers that need verification
// pull the signing key separately and use the existing test-suite
// helpers.
func DecodeJWSClaims(tb testing.TB, jws string) map[string]any {
	tb.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		tb.Fatalf("scenariokit: JWS has %d parts, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		tb.Fatalf("scenariokit: decode JWS payload: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		tb.Fatalf("scenariokit: unmarshal JWS payload: %v", err)
	}
	return out
}

// JWEParts splits a JWE compact serialisation on "." and returns the
// raw segments. A well-formed JWE has exactly five parts (RFC 7516
// §7.1: header.cek.iv.ct.tag); tests use len(JWEParts(s)) == 5 as the
// shape gate.
func JWEParts(jwe string) []string {
	return strings.Split(jwe, ".")
}

// EncryptJWE wraps the supplied compact-serialised inner JWS in a JWE
// addressed to opPub using alg / enc. The protected header carries
// cty=JWT (RFC 7519 §5.2 nested JWT) and the supplied kid so the OP's
// kid-routing resolver can pick the matching private key. Callers
// drive the unsupported-alg / unsupported-enc rejection paths by
// tampering the resulting compact-serialised header via [TamperJWEAlg]
// or [TamperJWEEnc]; go-jose v4 itself will refuse to mint a JWE with
// a header outside its constants.
//
// alg defaults to "RSA-OAEP-256" and enc defaults to "A256GCM" when
// the caller passes the empty string.
func EncryptJWE(tb testing.TB, innerJWS string, opPub *rsa.PublicKey, kid, alg, enc string) string {
	tb.Helper()
	if alg == "" {
		alg = "RSA-OAEP-256"
	}
	if enc == "" {
		enc = "A256GCM"
	}
	rcpt := josev4.Recipient{
		Algorithm: josev4.KeyAlgorithm(alg),
		Key:       opPub,
		KeyID:     kid,
	}
	opts := (&josev4.EncrypterOptions{}).
		WithType("JWT").
		WithContentType("JWT")
	encrypter, err := josev4.NewEncrypter(josev4.ContentEncryption(enc), rcpt, opts)
	if err != nil {
		tb.Fatalf("scenariokit: NewEncrypter(%s/%s): %v", alg, enc, err)
	}
	obj, err := encrypter.Encrypt([]byte(innerJWS))
	if err != nil {
		tb.Fatalf("scenariokit: Encrypt: %v", err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		tb.Fatalf("scenariokit: CompactSerialize: %v", err)
	}
	return out
}

// TamperJWEHeader rewrites a single string field in the protected
// header of a compact-serialised JWE and returns the re-serialised
// form. It exists because go-jose v4 refuses to mint a JWE whose
// `alg` or `enc` lives outside its allow-list; tests that need to
// exercise the OP's pre-crypto allow-list gate construct the hostile
// fixture by post-hoc header rewrite.
//
// The match is a literal substring replacement on the JSON header
// (`"<field>":"<from>"`); callers MUST supply the exact value that
// appeared in the original header so the replacement targets the
// intended JSON key.
func TamperJWEHeader(tb testing.TB, jwe, field, from, to string) string {
	tb.Helper()
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		tb.Fatalf("scenariokit: not a compact JWE: %d parts", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		tb.Fatalf("scenariokit: decode protected header: %v", err)
	}
	needle := `"` + field + `":"` + from + `"`
	repl := `"` + field + `":"` + to + `"`
	tampered := strings.Replace(string(header), needle, repl, 1)
	if tampered == string(header) {
		tb.Fatalf("scenariokit: tamper target %q not found in header %s", needle, header)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(tampered))
	return strings.Join(parts, ".")
}
