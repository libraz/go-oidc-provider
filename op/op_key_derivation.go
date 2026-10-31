package op

import (
	"crypto/hmac"
	"crypto/sha256"
)

// csrfDerivationLabel is the HMAC label used to derive the CSRF signing
// key from the active cookie key. Including a domain-separation label
// prevents a key reuse attack across cookie / CSRF surfaces if either
// derivation function is ever changed independently.
const csrfDerivationLabel = "oidc-csrf-v1"

// stateRefDerivationLabel is the HMAC label used to derive the
// orchestrator's [authn.StateRefSigner] key from the cookie key. The
// derivation is namespaced from the CSRF key so a hypothetical key-
// disclosure on one signer cannot forge tokens on the other.
const stateRefDerivationLabel = "oidc-stateref-v1"

// completionDerivationLabel namespaces stable authorization-completion IDs
// from cookies, CSRF tokens, and orchestrator state references.
const completionDerivationLabel = "oidc-authorization-completion-key-v1"

// deriveCSRFKey returns a 32-byte HMAC-SHA256 derivation of cookieKey
// labelled with [csrfDerivationLabel]. SHA-256 emits exactly 32 bytes
// which matches the [csrf.NewSigner] requirement, so no truncation is
// needed.
func deriveCSRFKey(cookieKey []byte) []byte {
	h := hmac.New(sha256.New, cookieKey)
	_, _ = h.Write([]byte(csrfDerivationLabel))
	return h.Sum(nil)
}

// deriveCSRFSigningKeys applies the CSRF domain separation to the active
// cookie key and every configured decryption-overlap key. The resulting ring
// lets a newly deployed instance verify an interaction form issued by a
// still-draining previous instance, while issuance remains pinned to current.
func deriveCSRFSigningKeys(cookieKeys [][]byte) ([]byte, [][]byte) {
	if len(cookieKeys) == 0 {
		return nil, nil
	}
	current := deriveCSRFKey(cookieKeys[0])
	previous := make([][]byte, 0, len(cookieKeys)-1)
	for _, key := range cookieKeys[1:] {
		previous = append(previous, deriveCSRFKey(key))
	}
	return current, previous
}

// deriveStateRefKey returns a 32-byte HMAC-SHA256 derivation of
// cookieKey labelled with [stateRefDerivationLabel] for use as the
// orchestrator's [authn.StateRefSigner] key.
func deriveStateRefKey(cookieKey []byte) []byte {
	h := hmac.New(sha256.New, cookieKey)
	_, _ = h.Write([]byte(stateRefDerivationLabel))
	return h.Sum(nil)
}

// deriveStateRefSigningKeys is the StateRef counterpart of
// [deriveCSRFSigningKeys]. Keeping the derivation label distinct ensures that
// accepting a previous cookie key for both short-lived form tokens does not
// make either token type forgeable as the other.
func deriveStateRefSigningKeys(cookieKeys [][]byte) ([]byte, [][]byte) {
	if len(cookieKeys) == 0 {
		return nil, nil
	}
	current := deriveStateRefKey(cookieKeys[0])
	previous := make([][]byte, 0, len(cookieKeys)-1)
	for _, key := range cookieKeys[1:] {
		previous = append(previous, deriveStateRefKey(key))
	}
	return current, previous
}

func deriveCompletionKey(cookieKey []byte) []byte {
	h := hmac.New(sha256.New, cookieKey)
	_, _ = h.Write([]byte(completionDerivationLabel))
	return h.Sum(nil)
}
