package keys

import (
	"crypto/rand"
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
	upper := big.NewInt(math.MaxInt64)
	for {
		value, err := rand.Int(rand.Reader, upper)
		if err != nil {
			return 0, err
		}
		result := value.Uint64()
		if result != 0 && result != excluded {
			return result, nil
		}
	}
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
