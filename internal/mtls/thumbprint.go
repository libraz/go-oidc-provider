package mtls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// Thumbprint returns the RFC 8705 §3.1 SHA-256 thumbprint of cert,
// encoded as base64url without padding. The hash is taken over the
// DER-encoded leaf certificate ([x509.Certificate.Raw]); RFC 8705
// pins SHA-256 (no negotiation) and points at the IETF "x5t#S256"
// confirmation method (RFC 8705 §3.1, RFC 7800 §3.5).
//
// The function returns "" when cert is nil or its Raw bytes are
// empty so the caller can guard the [AccessTokenClaims.Confirmation]
// assignment with a simple non-empty check; passing an empty value
// would produce a hash that no possible cert reproduces, which is
// worse than refusing to bind.
func Thumbprint(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
