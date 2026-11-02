package op

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"strconv"
	"time"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/op/grant"
)

// validateCookieKeys runs the same shape checks as [cookie.NewCodec] but
// without instantiating the codec — startup validation must surface every
// wrong-length key with a stable [*Error] code regardless of order.
func validateCookieKeys(keys [][]byte) error {
	for i, k := range keys {
		if len(k) != cookieKeyLen {
			return newConfigurationError("WithCookieKeys: entry "+strconv.Itoa(i)+" is not 32 bytes", nil)
		}
	}
	return nil
}

// cookieKeyLen mirrors the AES-256-GCM key length expected by the cookie
// codec. The value is duplicated here so option-level validation can return
// a stable [*Error] without instantiating the codec.
const cookieKeyLen = 32

// validateCookieKeysRequired enforces the rule that any grant which depends
// on the authorize endpoint setting encrypted cookies (interaction binding,
// session resumption) MUST be paired with at least one cookie key. The
// authorization_code grant is the only one that imposes the
// requirement; the rule is centralised here so another grant can opt in by
// adding itself to the switch.
func validateCookieKeysRequired(grants []grant.Type, keys [][]byte) error {
	if len(keys) > 0 {
		return nil
	}
	for _, g := range grants {
		if g == grant.AuthorizationCode {
			return ErrCookieKeysRequired
		}
	}
	return nil
}

// validateKeyset enforces the issuing-algorithm policy: the active entry
// (ks[0]) is a key of alg, every other entry is a key of ES256 or RS256,
// and an entry of the other algorithm sets NotAfter so a mixed keyset is
// only ever a transition. It also rejects empty and duplicate key IDs and
// nil signers.
func validateKeyset(ks Keyset, alg SigningAlgorithm) error {
	seen := make(map[string]struct{}, len(ks))
	for i, k := range ks {
		if k.KeyID == "" {
			return newConfigurationError("keyset entry "+strconv.Itoa(i)+" is missing KeyID", nil)
		}
		if _, dup := seen[k.KeyID]; dup {
			return newConfigurationError("duplicate KeyID "+k.KeyID, nil)
		}
		seen[k.KeyID] = struct{}{}
		if nilcheck.IsNil(k.Signer) {
			return newConfigurationError("keyset entry "+k.KeyID+" has nil Signer", nil)
		}
		shape, keyAlg := signingKeyShape(k.Signer.Public())
		switch {
		case i == 0 && keyAlg != alg:
			return newConfigurationError("keyset entry "+k.KeyID+" is "+shape+"; the OP signs with "+string(alg)+
				", which requires "+signingKeyRequirement(alg)+" for the active key", nil)
		case keyAlg == "":
			return newConfigurationError("keyset entry "+k.KeyID+" is "+shape+
				"; only ECDSA P-256 and RSA of 2048 bits or more are accepted", nil)
		case keyAlg != alg && k.NotAfter.IsZero():
			return newConfigurationError("keyset entry "+k.KeyID+" is "+shape+" but the OP signs with "+string(alg)+
				"; a key of the other type must set NotAfter", nil)
		}
	}
	return nil
}

// signingKeyShape describes pub for the keyset errors and returns the
// issuing algorithm it serves, or "" when it serves none.
func signingKeyShape(pub crypto.PublicKey) (string, SigningAlgorithm) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil {
			break
		}
		if k.Curve == elliptic.P256() {
			return "ECDSA P-256", AlgES256
		}
		return "ECDSA " + k.Curve.Params().Name, ""
	case *rsa.PublicKey:
		if k == nil || k.N == nil {
			break
		}
		bits := k.N.BitLen()
		shape := "RSA " + strconv.Itoa(bits) + " bits"
		if bits < jose.MinRSAKeyBits {
			return shape, ""
		}
		return shape, AlgRS256
	case ed25519.PublicKey:
		return "Ed25519", ""
	}
	return "an unsupported key type", ""
}

// signingKeyRequirement names the key type the active entry needs for alg.
func signingKeyRequirement(alg SigningAlgorithm) string {
	if alg == AlgRS256 {
		return "RSA of 2048 bits or more"
	}
	return "ECDSA P-256"
}

// validateActiveSigningKeyLive rejects a keyset whose active entry
// (ks[0], the signer every newly-issued JWS is stamped with) has
// already reached its [SigningKey.NotAfter] deadline at the configured
// clock reading.
//
// The retirement gate runs on verification only ([keys.Set.Find]), so
// such a Provider would sign happily and then refuse its own tokens at
// every entry point that verifies them — /userinfo, /introspect,
// /revoke, token exchange, /end_session — for the whole lifetime of
// each token, with no runtime signal naming the cause. Because the OP
// verifies what it just issued, an active entry whose deadline has
// passed is not a rotation posture the deployment can be in: the only
// correct move is to promote a live key, and a construction error is
// what says so before the first token is minted.
//
// The comparison mirrors [keys.Set.Find]: a deadline of exactly "now"
// already rejects there, so it must reject here too. Retiring entries
// behind the active slot are untouched — holding a past-deadline key in
// the tail is exactly how a completed rotation looks.
func validateActiveSigningKeyLive(ks Keyset, now time.Time) error {
	if len(ks) == 0 {
		return nil
	}
	active := ks[0]
	if active.NotAfter.IsZero() || now.Before(active.NotAfter) {
		return nil
	}
	return newConfigurationError("active keyset entry "+active.KeyID+
		" has already reached its NotAfter deadline, so every token it signs "+
		"would fail the OP's own verification; promote a live key to the first slot", nil)
}
