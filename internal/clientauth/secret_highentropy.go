package clientauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// The high-entropy encoding and the sizes it is built from.
//
// The identifier deliberately names the construction rather than
// borrowing a PHC algorithm id: a reader auditing a database dump
// should be able to tell at a glance that this is a keyed hash over a
// machine-generated credential, not a password KDF someone weakened.
const (
	// highEntropyID is the algorithm segment of the encoding.
	highEntropyID = "hmac-sha256"

	// highEntropySaltBytes is the per-record salt length. The salt is
	// not load-bearing against brute force — nothing is, at the
	// entropy this format requires — but it keeps two clients that
	// were provisioned with the same secret from presenting the same
	// stored value, which a dump would otherwise show.
	highEntropySaltBytes = 16

	// highEntropyMinSecretChars is the floor [HashHighEntropySecret]
	// enforces on the plaintext.
	//
	// The number is a length, not an entropy measurement, because a
	// string carries no way to measure the latter: "aaaa…" and 32
	// bytes of crypto/rand are indistinguishable to any check this
	// code could run. The floor is therefore a filter against the
	// obvious mistake (a hand-written secret), and the real guarantee
	// comes from the caller's assertion that the value is machine
	// generated — which [NewHighEntropySecret] makes true by
	// construction. The library's own minted secret is 32 random
	// bytes, 43 characters in base64url, so it clears this with room
	// to spare.
	highEntropyMinSecretChars = 32

	// highEntropyMaxEncodingChars caps the stored value before
	// parsing, mirroring the bound the argon2id parser applies. A real
	// encoding is under 100 bytes.
	highEntropyMaxEncodingChars = 256
)

// ErrSecretTooShort reports that a plaintext offered to
// [HashHighEntropySecret] is below [highEntropyMinSecretChars]. It is
// a provisioning-time error — never a verification outcome — so it
// never reaches the wire and callers surface it verbatim to the
// operator who wrote the configuration.
var ErrSecretTooShort = errors.New("authn: client secret too short for high-entropy hashing")

// HighEntropy is the [SecretVerifier] for an OP whose client secrets
// are all machine generated.
//
// # Why a fast hash is the right primitive here
//
// Argon2id's cost buys one thing: it multiplies the work an attacker
// holding a stolen database must do per guess. That is decisive for a
// human-chosen password, where the guess space is small enough that a
// constant factor decides the outcome. It buys nothing against a
// credential drawn from 256 bits of crypto/rand — 2^256 is out of
// reach whether each guess costs 90 ms or 200 ns, and the OP pays the
// 90 ms on every legitimate request to defend a search nobody can run.
//
// The precondition is doing all the work, so it is enforced rather
// than assumed: [NewHighEntropySecret] mints the secret itself, and
// [HashHighEntropySecret] refuses a plaintext short enough to have
// been typed by a person.
//
// # Why the verifier still reads argon2id
//
// An OP that adopts this format still has clients whose stored hash
// predates it, and the OP cannot re-hash them: it holds no plaintext.
// Verification therefore dispatches on the stored encoding, and a
// legacy record keeps working untouched. What that costs is spelled
// out on [HighEntropy.VerifyDummy].
type HighEntropy struct{}

// Verify implements [SecretVerifier]. It dispatches on the stored
// encoding so a store holding either format authenticates, and
// collapses every failure — unparseable, wrong algorithm, mismatched
// — onto [ErrCredentialsInvalid], because the distinctions are
// integrity faults the caller must not be able to read off the wire.
func (HighEntropy) Verify(presented, stored string) error {
	return verifyStoredSecret(presented, stored)
}

// VerifyDummy implements [DummyVerifier] with the same work factor
// [Verify] spends on a high-entropy record.
//
// The pairing is the point. The timing shim exists so a rejection
// tells the caller nothing about whether the client_id resolved, and
// it can only do that if it costs what the real check costs. A shim
// left at the argon2id work factor would make every high-entropy
// client answer in microseconds while an unknown id took 90 ms, which
// is the client-existence oracle again with the sign flipped.
//
// The residual is a store that still holds argon2id records: those
// clients answer at the old cost and are therefore distinguishable
// from an unknown id. That is the migration hazard this format
// carries, and the reason adopting it is a deliberate OP-wide
// decision rather than something the library infers per client. An OP
// that has not re-provisioned its clients should not be using it.
func (HighEntropy) VerifyDummy(presented string) {
	salt := make([]byte, highEntropySaltBytes)
	_ = highEntropyMAC(presented, salt)
}

// HashHighEntropySecret renders the stored encoding for a plaintext
// the caller asserts is machine generated, refusing anything shorter
// than [highEntropyMinSecretChars] with [ErrSecretTooShort].
//
// Callers that can mint the credential themselves should use
// [NewHighEntropySecret] instead: it removes the assertion entirely
// rather than checking a proxy for it.
func HashHighEntropySecret(secret string) (string, error) {
	if len(secret) < highEntropyMinSecretChars {
		return "", fmt.Errorf("%w: %d characters, minimum %d",
			ErrSecretTooShort, len(secret), highEntropyMinSecretChars)
	}
	salt := make([]byte, highEntropySaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("authn: read client secret salt: %w", err)
	}
	return encodeHighEntropy(salt, highEntropyMAC(secret, salt)), nil
}

// NewHighEntropySecret mints a client_secret and its stored encoding
// together. The plaintext carries 256 bits from crypto/rand, which is
// the entropy the format's security argument rests on, so a caller
// using this function is not asserting anything — the property holds
// by construction.
//
// The plaintext is returned for delivery to the client and is never
// persisted by the library.
func NewHighEntropySecret() (secret, stored string, err error) {
	raw := make([]byte, highEntropySecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("authn: read client secret: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	stored, err = HashHighEntropySecret(secret)
	if err != nil {
		return "", "", err
	}
	return secret, stored, nil
}

// highEntropySecretBytes is the entropy [NewHighEntropySecret] mints.
// 256 bits matches the refresh-token and registration-access-token
// lengths used elsewhere, and RFC 6819 §5.1.4.2's recommendation.
const highEntropySecretBytes = 32

// IsHighEntropyEncoding reports whether stored is in the encoding this
// file defines. Provisioning code uses it to tell a record that
// already carries a hash from one that still needs hashing; it makes
// no claim about the record being valid.
func IsHighEntropyEncoding(stored string) bool {
	return strings.HasPrefix(stored, "$"+highEntropyID+"$")
}

// verifyStoredSecret checks presented against whichever encoding
// stored is in. It is the single dispatch point both verifiers share,
// so neither can drift into accepting a format the other rejects — a
// divergence that would strand clients on whichever endpoint happened
// to install the other verifier.
func verifyStoredSecret(presented, stored string) error {
	if !IsHighEntropyEncoding(stored) {
		return (&Argon2id{}).verifyArgon2id(presented, stored)
	}
	salt, want, err := decodeHighEntropy(stored)
	if err != nil {
		return ErrCredentialsInvalid
	}
	if !hmac.Equal(highEntropyMAC(presented, salt), want) {
		return ErrCredentialsInvalid
	}
	return nil
}

// highEntropyMAC derives the stored tag. The salt keys the HMAC rather
// than being concatenated with the secret: both are sound at a fixed
// salt length, but a keyed construction leaves nothing to argue about
// if the salt length is ever made variable.
func highEntropyMAC(secret string, salt []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(secret))
	return mac.Sum(nil)
}

// encodeHighEntropy renders the stored form.
func encodeHighEntropy(salt, tag []byte) string {
	return "$" + highEntropyID + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(tag)
}

// decodeHighEntropy parses the stored form back into its salt and tag.
// The parser is strict — exact segment count, exact algorithm id,
// exact decoded lengths — because every rejection here collapses onto
// the same wire answer as a wrong secret, so a lenient parser would
// only widen what a corrupted store can feed into the comparison.
func decodeHighEntropy(stored string) (salt, tag []byte, err error) {
	if len(stored) > highEntropyMaxEncodingChars {
		return nil, nil, errors.New("authn: stored secret encoding too long")
	}
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "" || parts[1] != highEntropyID {
		return nil, nil, errors.New("authn: stored secret envelope invalid")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) != highEntropySaltBytes {
		return nil, nil, errors.New("authn: stored secret salt invalid")
	}
	tag, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(tag) != sha256.Size {
		return nil, nil, errors.New("authn: stored secret tag invalid")
	}
	return salt, tag, nil
}

// ensure compile-time interface satisfaction for both roles.
var (
	_ SecretVerifier = HighEntropy{}
	_ DummyVerifier  = HighEntropy{}
)
