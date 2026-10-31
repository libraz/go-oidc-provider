package registrationendpoint

import (
	"crypto/sha256"
	"encoding/hex"
)

// Token / identifier byte lengths the handler uses. The values mirror
// the public op.IssueInitialAccessToken posture so DCR-issued
// credentials carry the same entropy as IAT-issued ones.
const (
	// clientIDBytes is the entropy of the opaque client_id minted on
	// successful registration. 16 bytes (128 bits) is sufficient for a
	// public identifier (collision-resistant within any realistic
	// deployment) and short enough to stay readable in operator logs.
	// Mirrors op.iatIDBytes.
	clientIDBytes = 16

	// clientSecretBytes is the entropy of the issued client_secret for
	// confidential clients. 256 bits matches the OAuth refresh token
	// entropy used elsewhere in the library and the RFC 6819 §5.1.4.2
	// recommendation. Mirrors op.iatSecretBytes.
	clientSecretBytes = 32

	// ratBytes is the entropy of the registration_access_token (RFC
	// 7591 §3.2.1). 256 bits matches the IAT secret length and the
	// PAR request_uri entropy.
	ratBytes = 32
)

// hashSecret returns the lowercase hex SHA-256 digest of the bearer
// secret. The format matches the contract documented on
// store.InitialAccessToken.HashedValue and
// store.RegistrationAccessToken.HashedValue; backends compare digests
// in constant time.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
