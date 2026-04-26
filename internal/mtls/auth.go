package mtls

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	josev4 "github.com/go-jose/go-jose/v4"
)

// ClientMatcher is the projection of a registered client's
// tls_client_auth metadata the package needs to decide whether a
// presented certificate authenticates that client (RFC 8705 §2.1.2).
//
// All fields are optional; the matcher succeeds when AT LEAST ONE
// non-empty field matches a value present on the cert. An entirely
// empty matcher fails closed with [ErrNoMatcherConfigured]: silently
// admitting any cert would defeat the §2.1 contract.
type ClientMatcher struct {
	// SubjectDN is the RFC 4514 string form of the cert subject DN.
	// The match is byte-for-byte after canonicalisation through the
	// standard library's [pkix.Name.String]; embedders that store a
	// non-canonical encoding are expected to normalise at
	// registration time.
	SubjectDN string

	// SANDNS is the DNS name expected in [x509.Certificate.DNSNames].
	// Comparison is case-insensitive per RFC 5280 §7.2.
	SANDNS string

	// SANURI is the URI expected in [x509.Certificate.URIs]. The
	// match is byte-for-byte; query / fragment differences are NOT
	// normalised away because the spec leaves it to the embedder.
	SANURI string

	// SANIP is the IP literal expected in [x509.Certificate.IPAddresses].
	// Comparison is by [net.IP.Equal] so v4-in-v6 mappings round-trip.
	SANIP string

	// SANEmail is the rfc822Name expected in
	// [x509.Certificate.EmailAddresses]. Comparison is case-
	// insensitive on the local-part (matching the standard library's
	// [mail.ParseAddress] behaviour) and the domain (DNS).
	SANEmail string
}

// hasAny reports whether the matcher has at least one non-empty field.
// The check exists so [VerifyTLSClientAuth] can fail closed when the
// client has no matcher configured at all rather than silently
// accepting any cert.
func (m ClientMatcher) hasAny() bool {
	return m.SubjectDN != "" ||
		m.SANDNS != "" ||
		m.SANURI != "" ||
		m.SANIP != "" ||
		m.SANEmail != ""
}

// VerifyTLSClientAuth checks the cert against the client's registered
// matcher per RFC 8705 §2.1.2. It returns nil on a successful match
// and a typed sentinel on failure; chain validation against the OP's
// trust anchors is the EMBEDDER's responsibility (and the reverse-
// proxy / [tls.Config.ClientCAs] are the canonical places to wire it).
//
// The function does not consult the cert's NotBefore / NotAfter
// either — the TLS layer (or the proxy that terminated TLS) has
// already done that. Re-checking would create a clock dependency the
// package deliberately avoids.
func VerifyTLSClientAuth(cert *x509.Certificate, expected ClientMatcher) error {
	if cert == nil {
		return fmt.Errorf("%w: nil certificate", ErrNoClientCert)
	}
	if !expected.hasAny() {
		return ErrNoMatcherConfigured
	}
	if expected.SubjectDN != "" {
		if cert.Subject.String() == expected.SubjectDN {
			return nil
		}
		// Subject was configured but did not match. Fall through to
		// the SAN checks: RFC 8705 §2.1.2 lets either the DN OR a
		// SAN satisfy the requirement, so a configured-but-mismatched
		// DN must not short-circuit the SAN attempts.
	}
	if matchSAN(cert, expected) {
		return nil
	}
	if expected.SubjectDN != "" {
		return ErrSubjectMismatch
	}
	return ErrSANMismatch
}

// matchSAN reports whether any configured SAN matcher matches a value
// on the cert. Each comparison is shaped to the SAN type's RFC 5280
// canonicalisation rules.
func matchSAN(cert *x509.Certificate, m ClientMatcher) bool {
	if m.SANDNS != "" && containsFold(cert.DNSNames, m.SANDNS) {
		return true
	}
	if m.SANURI != "" && containsURI(cert.URIs, m.SANURI) {
		return true
	}
	if m.SANIP != "" && containsIP(cert.IPAddresses, m.SANIP) {
		return true
	}
	if m.SANEmail != "" && containsFold(cert.EmailAddresses, m.SANEmail) {
		return true
	}
	return false
}

// containsFold reports whether haystack contains needle under ASCII
// case folding. DNS names and email addresses are case-insensitive
// per RFC 5280 §7.2 / §3.4.4.
func containsFold(haystack []string, needle string) bool {
	for _, v := range haystack {
		if strings.EqualFold(v, needle) {
			return true
		}
	}
	return false
}

// containsURI reports whether haystack contains the URI needle. The
// match is byte-for-byte after re-serialisation; we deliberately do
// not normalise scheme / host case because the spec leaves the
// comparison policy to the embedder.
func containsURI(haystack []*url.URL, needle string) bool {
	for _, u := range haystack {
		if u == nil {
			continue
		}
		if u.String() == needle {
			return true
		}
	}
	return false
}

// containsIP reports whether haystack contains an IP literal equal to
// needle under [net.IP.Equal]. The wrapping function exists to keep
// the malformed-needle case (a string the parser cannot decode)
// localised: a malformed needle is treated as "no match" rather than
// propagating an error, because validation of the registered client
// metadata happens at registration time.
func containsIP(haystack []net.IP, needle string) bool {
	target := net.ParseIP(needle)
	if target == nil {
		return false
	}
	for _, ip := range haystack {
		if ip.Equal(target) {
			return true
		}
	}
	return false
}

// VerifySelfSignedTLSClientAuth checks that the cert's public-key JWK
// thumbprint appears in jwks (RFC 8705 §2.2.2). It returns nil on a
// match and a typed sentinel otherwise. Chain validation is NOT
// performed: the spec deliberately allows self-signed certs because
// the trust anchor is the registered JWK, not a CA.
//
// jwks is the raw JSON Web Key Set bytes — typically the value of the
// client's "jwks" metadata field. A nil / empty input returns
// [ErrJWKSMalformed] so the caller can distinguish "client has no
// JWKS" from "JWKS does not contain this key".
func VerifySelfSignedTLSClientAuth(cert *x509.Certificate, jwks []byte) error {
	if cert == nil {
		return fmt.Errorf("%w: nil certificate", ErrNoClientCert)
	}
	if len(jwks) == 0 {
		return ErrJWKSMalformed
	}
	var set josev4.JSONWebKeySet
	if err := json.Unmarshal(jwks, &set); err != nil {
		return fmt.Errorf("%w: %w", ErrJWKSMalformed, err)
	}

	certThumbprint, err := jwkThumbprint(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: derive cert JWK thumbprint: %w", ErrCertMalformed, err)
	}
	for _, key := range set.Keys {
		if key.Key == nil {
			continue
		}
		got, err := key.Thumbprint(crypto.SHA256)
		if err != nil {
			continue
		}
		if equalBytes(got, certThumbprint) {
			return nil
		}
	}
	return ErrNoMatchingJWK
}

// jwkThumbprint returns the RFC 7638 SHA-256 JWK thumbprint of pub.
// The function delegates to go-jose so the canonical encoding matches
// the rest of the JOSE ecosystem.
func jwkThumbprint(pub any) ([]byte, error) {
	jwk := josev4.JSONWebKey{Key: pub}
	return jwk.Thumbprint(crypto.SHA256)
}

// equalBytes is a small constant-time helper. The values being
// compared are public-key digests so timing leakage is not a real
// risk, but the function exists so the comparison is auditable.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
