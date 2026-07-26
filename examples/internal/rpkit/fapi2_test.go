//go:build example

package rpkit_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
)

// p256CoordLen is the octet length RFC 7518 §6.2.1.2 requires of a P-256
// coordinate: the full size of a coordinate for the curve, zero-padded on
// the left rather than trimmed to its minimal representation.
const p256CoordLen = 32

// TestPublicJWKSetJSONCoordinatesAreFixedWidth pins that rule.
//
// The natural implementation — base64url of big.Int.Bytes — is correct for
// most keys and wrong for the roughly one coordinate in 256 that starts
// with a zero byte, which encodes to 31 octets and yields a JWK a
// conforming parser rejects as malformed. Because every caller generates
// an ephemeral key at boot, that defect shows up as an occasional startup
// failure rather than a reproducible one, so the test supplies the small
// coordinates where the difference is deterministic instead of generating
// a key and hoping. PublicJWKSetJSON only encodes the coordinates it is
// handed, so a point that is not on the curve exercises it faithfully.
func TestPublicJWKSetJSONCoordinatesAreFixedWidth(t *testing.T) {
	t.Parallel()

	full := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	cases := map[string]struct{ x, y *big.Int }{
		"leading zero bytes": {x: big.NewInt(1), y: big.NewInt(0xff)},
		"one byte short":     {x: new(big.Int).Rsh(full, 8), y: new(big.Int).Rsh(full, 8)},
		"full width":         {x: full, y: full},
	}

	for name, tc := range cases {
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: tc.x, Y: tc.y}
		raw, err := rpkit.PublicJWKSetJSON(pub, "kid-1")
		if err != nil {
			t.Fatalf("%s: PublicJWKSetJSON: %v", name, err)
		}

		var set struct {
			Keys []struct {
				X string `json:"x"`
				Y string `json:"y"`
			} `json:"keys"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			t.Fatalf("%s: unmarshal JWK set: %v", name, err)
		}
		if len(set.Keys) != 1 {
			t.Fatalf("%s: got %d keys, want 1", name, len(set.Keys))
		}

		for label, coord := range map[string]struct {
			encoded string
			want    *big.Int
		}{
			"x": {set.Keys[0].X, tc.x},
			"y": {set.Keys[0].Y, tc.y},
		} {
			decoded, err := base64.RawURLEncoding.DecodeString(coord.encoded)
			if err != nil {
				t.Fatalf("%s/%s: decode: %v", name, label, err)
			}
			if len(decoded) != p256CoordLen {
				t.Errorf("%s/%s: encoded to %d octets, want %d",
					name, label, len(decoded), p256CoordLen)
			}
			if got := new(big.Int).SetBytes(decoded); got.Cmp(coord.want) != 0 {
				t.Errorf("%s/%s: round-tripped to %s, want %s",
					name, label, got, coord.want)
			}
		}
	}
}
