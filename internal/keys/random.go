package keys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"math/big"
)

// RandomUint63Except returns a non-zero token in the signed 63-bit range that
// differs from excluded. It is suitable for equality-only optimistic-concurrency
// tokens stored in a signed BIGINT column. The upper bound is exclusive, so
// math.MaxInt64 is deliberately never issued: callers can retain that value as
// an invalid/sentinel snapshot.
//
// The token is drawn from crypto/rand and no ordering is implied. A read
// failure is returned to the caller so a state transition fails closed rather
// than reusing a predictable or prior token.
func RandomUint63Except(excluded uint64) (uint64, error) {
	// A conversion of excluded >= 2^63 is negative and can never equal a
	// token in [1, MaxInt64), so no value needs special exclusion.
	v, err := RandomInt63Except(int64(excluded)) //nolint:gosec // wraps outside the token range, see above.
	return uint64(v), err                        //nolint:gosec // v is in [1, MaxInt64) on success.
}

// RandomInt63Except is the signed counterpart to [RandomUint63Except]. It
// returns a non-zero token below math.MaxInt64, suitable for passing directly
// to SQL BIGINT parameters without an unsigned-to-signed conversion.
//
// excluded is an already-valid signed token. Values outside the usable range
// are not produced, so they need not be specially excluded.
func RandomInt63Except(excluded int64) (int64, error) {
	upper := big.NewInt(math.MaxInt64)
	for {
		value, err := rand.Int(rand.Reader, upper)
		if err != nil {
			return 0, err
		}
		result := value.Int64()
		if result != 0 && result != excluded {
			return result, nil
		}
	}
}

// IdentifierBytes is the entropy, 128 bits, of the opaque identifiers the OP
// mints through [RandomBase64URL]: jtis, grant ids and interaction uids.
const IdentifierBytes = 16

// RandomBase64URL returns n bytes drawn from crypto/rand, encoded as
// unpadded base64url. It is the single recipe behind the opaque
// identifiers the OP mints (session ids, codes, jtis, opaque tokens). A
// read failure is returned so the caller fails closed rather than
// issuing a predictable identifier.
func RandomBase64URL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("keys: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
