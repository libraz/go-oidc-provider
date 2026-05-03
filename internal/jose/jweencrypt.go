package jose

import (
	"errors"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"
)

// ErrJWEUnsupportedKey indicates [Encrypt] was given a recipient
// public key whose Go type is not compatible with the requested
// [JWEAlg]. Examples: an `*rsa.PublicKey` paired with `ECDH-ES`, or
// a non-P-curve `*ecdsa.PublicKey` paired with the ECDH-ES family.
//
// The wrapped detail is safe to log for diagnosis but never exposed
// to clients.
var ErrJWEUnsupportedKey = errors.New("jose: JWE recipient key not supported by alg")

// EncryptionRecipient is a single (kid, alg, public-key) triple
// [Encrypt] uses to mint a compact-serialised JWE. The kid is
// stamped into the protected header so the recipient can route to
// the right private key during decryption.
//
// Key MUST be one of:
//   - `*rsa.PublicKey` for [JWEAlgRSAOAEP256]
//   - `*ecdsa.PublicKey` for any of the ECDH-ES family
//
// Any other type is rejected with [ErrJWEUnsupportedKey] before
// any cryptographic operation runs.
type EncryptionRecipient struct {
	Alg   JWEAlg
	Enc   JWEEnc
	KeyID string
	Key   any
}

// Encrypt serialises plaintext as a compact JWE addressed to
// recipient. The output is a five-segment dot-separated string the
// recipient can decrypt with the private half of recipient.Key.
//
// The function enforces the same alg / enc allow-list as [Decrypt]
// (no `RSA1_5`, no symmetric `A*KW` / `dir`, no AES-CBC-HS) so the
// OP cannot accidentally produce JWE that its own [Decrypt] would
// reject.
//
// The protected header carries `alg`, `enc`, and `kid` (when
// recipient.KeyID is non-empty). No `crit`, `cty`, or `zip` is
// emitted by default — callers that need a nested JWE-of-JWS shape
// build the inner JWS first via [Sign] and then wrap it through
// [Encrypt] with `cty=JWT` (currently configured by the caller via
// the returned compact form, since this layer only emits the
// minimum protected header).
func Encrypt(plaintext []byte, recipient EncryptionRecipient) (string, error) {
	if !recipient.Alg.IsAllowed() {
		return "", fmt.Errorf("%w: %q", ErrJWEAlgNotAllowed, recipient.Alg)
	}
	if !recipient.Enc.IsAllowed() {
		return "", fmt.Errorf("%w: %q", ErrJWEEncNotAllowed, recipient.Enc)
	}
	if recipient.Key == nil {
		return "", fmt.Errorf("%w: nil recipient key", ErrJWEUnsupportedKey)
	}

	rcpt := josev4.Recipient{
		Algorithm: josev4.KeyAlgorithm(recipient.Alg),
		Key:       recipient.Key,
		KeyID:     recipient.KeyID,
	}
	opts := (&josev4.EncrypterOptions{}).
		WithType("JWT")
	encrypter, err := josev4.NewEncrypter(josev4.ContentEncryption(recipient.Enc), rcpt, opts)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWEUnsupportedKey, err)
	}

	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWEUnsupportedKey, err)
	}
	out, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWEMalformed, err)
	}
	return out, nil
}

// EncryptNestedJWT wraps a JWS (already-signed compact JWT) in a JWE
// addressed to recipient. The protected header carries `cty=JWT` per
// RFC 7519 §5.2 so the recipient knows to verify a JWS after
// decrypting.
//
// This is the canonical shape for encrypted-and-signed id_tokens,
// userinfo responses, JARM, and introspection responses: the OP
// signs the claim set with its own signing keyset, then encrypts the
// resulting JWS to the RP's `use=enc` public key. The recipient
// decrypts, sees `cty=JWT`, and verifies the inner JWS with the OP's
// signing keys.
//
// The inner jws value MUST already be a compact-serialised JWS (e.g.
// the output of [Sign]). The function does not validate the JWS
// shape beyond non-emptiness; callers are responsible for ensuring
// the input is a JWS the recipient will accept.
func EncryptNestedJWT(jws string, recipient EncryptionRecipient) (string, error) {
	if jws == "" {
		return "", fmt.Errorf("%w: empty inner JWS", ErrJWEMalformed)
	}
	if !recipient.Alg.IsAllowed() {
		return "", fmt.Errorf("%w: %q", ErrJWEAlgNotAllowed, recipient.Alg)
	}
	if !recipient.Enc.IsAllowed() {
		return "", fmt.Errorf("%w: %q", ErrJWEEncNotAllowed, recipient.Enc)
	}
	if recipient.Key == nil {
		return "", fmt.Errorf("%w: nil recipient key", ErrJWEUnsupportedKey)
	}

	rcpt := josev4.Recipient{
		Algorithm: josev4.KeyAlgorithm(recipient.Alg),
		Key:       recipient.Key,
		KeyID:     recipient.KeyID,
	}
	opts := (&josev4.EncrypterOptions{}).
		WithType("JWT").
		WithContentType("JWT")
	encrypter, err := josev4.NewEncrypter(josev4.ContentEncryption(recipient.Enc), rcpt, opts)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWEUnsupportedKey, err)
	}

	jwe, err := encrypter.Encrypt([]byte(jws))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWEUnsupportedKey, err)
	}
	out, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWEMalformed, err)
	}
	return out, nil
}
