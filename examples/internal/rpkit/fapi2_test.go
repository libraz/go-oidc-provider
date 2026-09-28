//go:build example

package rpkit_test

import (
	"bytes"
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
// Base64url of a coordinate's minimal big-endian form is correct for most
// keys and wrong for the roughly one coordinate in 256 that starts with a
// zero byte. Callers generate an ephemeral key at boot, so the defect would
// surface as an occasional startup failure; the test instead uses fixed
// scalars whose public points have a leading zero byte in X (d=379) and
// in Y (d=43), which makes the difference deterministic.
func TestPublicJWKSetJSONCoordinatesAreFixedWidth(t *testing.T) {
	t.Parallel()

	for name, d := range map[string]int64{"x leading zero": 379, "y leading zero": 43} {
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), big.NewInt(d).FillBytes(make([]byte, p256CoordLen)))
		if err != nil {
			t.Fatalf("%s: ParseRawPrivateKey: %v", name, err)
		}
		point, err := priv.PublicKey.Bytes()
		if err != nil {
			t.Fatalf("%s: PublicKey.Bytes: %v", name, err)
		}
		wantX, wantY := point[1:1+p256CoordLen], point[1+p256CoordLen:]
		if wantX[0] != 0 && wantY[0] != 0 {
			t.Fatalf("%s: fixture no longer has a leading zero coordinate byte", name)
		}

		raw, err := rpkit.PublicJWKSetJSON(&priv.PublicKey, "kid-1")
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
			want    []byte
		}{
			"x": {set.Keys[0].X, wantX},
			"y": {set.Keys[0].Y, wantY},
		} {
			decoded, err := base64.RawURLEncoding.DecodeString(coord.encoded)
			if err != nil {
				t.Fatalf("%s/%s: decode: %v", name, label, err)
			}
			if !bytes.Equal(decoded, coord.want) {
				t.Errorf("%s/%s: encoded to %x (%d octets), want %x (%d octets)",
					name, label, decoded, len(decoded), coord.want, len(coord.want))
			}
		}
	}
}
