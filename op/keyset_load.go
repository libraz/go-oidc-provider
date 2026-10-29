package op

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
)

const (
	p256CoordLen    = 32
	symmetricKeyLen = 32
)

// LoadSigningKey reads one ECDSA P-256 private key from path and returns
// it as a [SigningKey] ready for [WithKeyset].
//
// The format is detected from the content:
//
//   - PKCS#8 PEM ("PRIVATE KEY")
//   - SEC1 PEM ("EC PRIVATE KEY")
//   - a private JWK (JSON object with kty "EC", crv "P-256", x, y, d)
//
// Encrypted PEM ("ENCRYPTED PRIVATE KEY" or a "Proc-Type: 4,ENCRYPTED"
// header) is rejected: decrypt the key before handing it over. RSA keys
// and other curves are rejected because the OP signs with ES256 only.
//
// KeyID is the JWK "kid" member when it is non-empty, otherwise the RFC
// 7638 SHA-256 thumbprint of the public key (base64url, no padding), so
// the same key yields the same kid on every replica regardless of the
// file name. NotAfter is left zero; set it on the returned value to pin
// a retirement deadline.
//
// Failures are [*Error] values with the "configuration_error" code. The
// message names path and the reason and never carries key material.
//
// Stable since v1.5.
func LoadSigningKey(path string) (SigningKey, error) {
	raw, err := readKeyFile("LoadSigningKey", path)
	if err != nil {
		return SigningKey{}, err
	}
	priv, kid, reason := parseSigningKey(raw)
	if reason != "" {
		return SigningKey{}, newConfigurationError("LoadSigningKey: "+path+": "+reason, nil)
	}
	if kid == "" {
		kid = p256Thumbprint(priv)
	}
	return SigningKey{KeyID: kid, Signer: priv}, nil
}

// LoadKeyset reads one signing key per path and returns them as a
// [Keyset]. paths[0] is the active signing key and the rest are
// retiring keys that stay in JWKS for verification, the same order
// [WithKeyset] uses. At least one path is required, and a kid that
// appears twice (including the same key loaded from two files) is
// rejected. Each file is read as described on [LoadSigningKey].
//
// Stable since v1.5.
func LoadKeyset(paths ...string) (Keyset, error) {
	if len(paths) == 0 {
		return nil, newConfigurationError("LoadKeyset requires at least one path", nil)
	}
	ks := make(Keyset, 0, len(paths))
	seen := make(map[string]string, len(paths))
	seenKey := make(map[string]string, len(paths))
	for _, p := range paths {
		k, err := LoadSigningKey(p)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[k.KeyID]; dup {
			return nil, newConfigurationError(
				"LoadKeyset: "+p+" has the same kid as "+prev+" (kid "+k.KeyID+")", nil,
			)
		}
		thumb := p256Thumbprint(k.Signer.(*ecdsa.PrivateKey))
		if prev, dup := seenKey[thumb]; dup {
			return nil, newConfigurationError("LoadKeyset: "+p+" holds the same key as "+prev, nil)
		}
		seen[k.KeyID] = p
		seenKey[thumb] = p
		ks = append(ks, k)
	}
	return ks, nil
}

// LoadSymmetricKeys reads one 32-byte symmetric key per path, for
// [WithCookieKeys] and [WithMFAEncryptionKeys]. The first key is the
// active one and later keys are retired keys kept for decryption.
//
// Each file holds either exactly 32 raw bytes (at least one of them
// neither printable ASCII nor whitespace), or text of the form below, with surrounding
// whitespace ignored:
//
//   - 64 hex characters
//   - base64 of 32 bytes (standard or URL alphabet, padded or not)
//
// Any other length is rejected. A 32-byte file of printable ASCII only,
// such as the output of "openssl rand -hex 16", is rejected as well
// because it carries 128 bits of entropy in a 256-bit slot. Generate
// keys with "openssl rand -hex 32" or "openssl rand 32".
//
// Failures are [*Error] values with the "configuration_error" code. The
// message names path and never carries key material.
//
// Stable since v1.5.
func LoadSymmetricKeys(paths ...string) ([][]byte, error) {
	if len(paths) == 0 {
		return nil, newConfigurationError("LoadSymmetricKeys requires at least one path", nil)
	}
	keys := make([][]byte, 0, len(paths))
	for _, p := range paths {
		raw, err := readKeyFile("LoadSymmetricKeys", p)
		if err != nil {
			return nil, err
		}
		key, reason := decodeSymmetricKey(raw)
		if reason != "" {
			return nil, newConfigurationError("LoadSymmetricKeys: "+p+": "+reason, nil)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// readKeyFile reads path and rejects an empty file.
func readKeyFile(fn, path string) ([]byte, error) {
	//nolint:gosec // G304: path is operator-supplied at construction time.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, newConfigurationError(fn+": read "+path, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, newConfigurationError(fn+": "+path+" is empty", nil)
	}
	return raw, nil
}

// parseSigningKey returns the key and the JWK kid (empty for PEM or an
// absent kid). A non-empty reason describes the failure.
func parseSigningKey(raw []byte) (priv *ecdsa.PrivateKey, kid, reason string) {
	trimmed := bytes.TrimSpace(raw)
	if trimmed[0] == '{' {
		return parsePrivateJWK(trimmed)
	}
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, "", "not a PEM block or a JWK"
	}
	block, reason := privateKeyBlock(trimmed)
	if block == nil {
		return nil, "", reason
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" ||
		strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, "", "encrypted PEM is not supported; decrypt the key before loading it"
	}
	var parsed any
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", "malformed PKCS#8 key"
		}
		parsed = k
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", "malformed SEC1 key"
		}
		parsed = k
	default:
		return nil, "", "unsupported PEM type " + block.Type
	}
	ec, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, "", "key is not ECDSA; only ECDSA P-256 is supported"
	}
	if ec.Curve != elliptic.P256() {
		return nil, "", "key curve is " + ec.Curve.Params().Name + "; only P-256 is supported"
	}
	return ec, "", ""
}

// privateKeyBlock returns the one private-key block in a PEM file. Non-key
// blocks such as EC PARAMETERS may precede the key; a nil block comes with
// the reason.
func privateKeyBlock(pemBytes []byte) (*pem.Block, string) {
	var block *pem.Block
	for rest := pemBytes; ; {
		b, next := pem.Decode(rest)
		if b == nil {
			break
		}
		rest = next
		if b.Type == "EC PARAMETERS" {
			continue
		}
		if block != nil {
			return nil, "more than one private key block"
		}
		block = b
	}
	if block == nil {
		return nil, "malformed PEM block"
	}
	return block, ""
}

// parsePrivateJWK reads a private EC P-256 JWK without a JOSE library.
func parsePrivateJWK(raw []byte) (priv *ecdsa.PrivateKey, kid, reason string) {
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		D   string `json:"d"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, "", "malformed JWK JSON"
	}
	if jwk.Kty != "EC" {
		return nil, "", "JWK kty must be EC"
	}
	if jwk.Crv != "P-256" {
		return nil, "", "JWK crv must be P-256"
	}
	if jwk.D == "" {
		return nil, "", "JWK has no private component (d); a public key cannot sign"
	}
	d, errD := base64.RawURLEncoding.DecodeString(jwk.D)
	x, errX := base64.RawURLEncoding.DecodeString(jwk.X)
	y, errY := base64.RawURLEncoding.DecodeString(jwk.Y)
	if errD != nil || errX != nil || errY != nil {
		return nil, "", "JWK d, x or y is not base64url"
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return nil, "", "JWK d is not a valid P-256 scalar"
	}
	gx, gy, ok := p256Coords(&key.PublicKey)
	if !ok || !bytes.Equal(gx, x) || !bytes.Equal(gy, y) {
		return nil, "", "JWK x and y do not match d"
	}
	return key, jwk.Kid, ""
}

// p256Coords splits the uncompressed SEC 1 encoding of a P-256 public
// key into its 32-byte x and y coordinates.
func p256Coords(pub *ecdsa.PublicKey) (x, y []byte, ok bool) {
	raw, err := pub.Bytes()
	if err != nil || len(raw) != 1+2*p256CoordLen {
		return nil, nil, false
	}
	return raw[1 : 1+p256CoordLen], raw[1+p256CoordLen:], true
}

// p256Thumbprint returns the RFC 7638 SHA-256 thumbprint of the public
// key, built from the required members in lexicographic order.
func p256Thumbprint(priv *ecdsa.PrivateKey) string {
	x, y, _ := p256Coords(&priv.PublicKey)
	enc := base64.RawURLEncoding
	canonical := `{"crv":"P-256","kty":"EC","x":"` + enc.EncodeToString(x) +
		`","y":"` + enc.EncodeToString(y) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return enc.EncodeToString(sum[:])
}

// decodeSymmetricKey returns the 32-byte key held by raw, or a reason.
func decodeSymmetricKey(raw []byte) ([]byte, string) {
	if len(raw) == symmetricKeyLen && hasNonPrintable(raw) {
		return append([]byte(nil), raw...), ""
	}
	text := strings.TrimSpace(string(raw))
	if len(text) == 2*symmetricKeyLen {
		if b, err := hex.DecodeString(text); err == nil {
			return b, ""
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(text); err == nil && len(b) == symmetricKeyLen {
			return b, ""
		}
	}
	return nil, "key must be 32 raw bytes, 64 hex characters or base64 of 32 bytes"
}

// hasNonPrintable reports whether b holds a byte that is neither
// printable ASCII nor text whitespace, so 31 characters and a newline
// still read as text.
func hasNonPrintable(b []byte) bool {
	for _, c := range b {
		if (c < 0x20 || c > 0x7e) && c != '\t' && c != '\n' && c != '\r' {
			return true
		}
	}
	return false
}
