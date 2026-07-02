package mtls

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
	// The match runs in two passes (see [VerifyTLSClientAuth]): a
	// DER round-trip through [pkix.Name] (so RFC 4514 attribute-
	// ordering differences disappear) and, on parse failure, a
	// fallback byte-for-byte compare against [pkix.Name.String] of
	// [x509.Certificate.Subject]. Embedders supplying a value the
	// DER round-trip cannot canonicalise (multi-valued RDNs,
	// extension OIDs outside the closed catalogue) MUST normalise
	// to the standard library's string form at registration time so
	// the verbatim string fallback succeeds.
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
	// insensitive across the entire address (both local-part and
	// domain) via [strings.EqualFold].
	//
	// RFC 5280 §3.4.4 and RFC 5321 §2.4 make only the domain part
	// canonically case-insensitive; the local-part is implementation-
	// defined and RFC 5321 deprecates relying on its case. The
	// matcher takes the conservative "fold everything" stance so a
	// mailbox registered with one casing still authenticates the
	// owner when the cert encodes a different casing — at the cost
	// of admitting two operationally distinct local-parts on a
	// hypothetical mail system that genuinely treats them as
	// distinct (none in modern deployments). The looser-than-RFC
	// stance is intentional and documented here so a future audit
	// finds the rationale next to the implementation.
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

// MethodTLSClientAuth is the RFC 8705 §2.1 token_endpoint_auth_method
// value naming the PKI-authenticated cert path: the cert is issued
// by a CA the OP trusts AND its subject DN (or one of the SAN
// matchers) matches the value the client metadata registered.
const MethodTLSClientAuth = "tls_client_auth"

// MethodSelfSignedTLSClientAuth is the RFC 8705 §2.2
// token_endpoint_auth_method value naming the JWK-thumbprint
// authenticated cert path: the cert is typically self-signed AND its
// public-key thumbprint appears in the client's registered JWKS.
const MethodSelfSignedTLSClientAuth = "self_signed_tls_client_auth"

// VerifyClientAuth dispatches the inbound cert onto the per-method
// verifier RFC 8705 §2 prescribes. The function is the single entry
// point handler code calls; callers pass the client's stored
// token_endpoint_auth_method verbatim and the function returns the
// per-method sentinel on failure.
//
//   - tls_client_auth (§2.1) routes to [VerifyTLSClientAuth]; the
//     supplied [ClientMatcher] is used to decide whether the cert's
//     subject DN or one of its SANs satisfies the registered value.
//     Chain validation against the OP's trust anchors is the
//     EMBEDDER's responsibility (see [VerifyTLSClientAuth]).
//
//   - self_signed_tls_client_auth (§2.2) routes to
//     [VerifySelfSignedTLSClientAuth]; the supplied jwks bytes are
//     compared against the cert's public-key thumbprint. The matcher
//     argument is unused on this path because §2.2 binds the cert to
//     the client by thumbprint, not by DN.
//
// Any other method value returns [ErrUnsupportedMethod] so the caller
// surfaces invalid_client at the wire boundary; the comparison is
// case-sensitive because RFC 8705 spells the method names exactly.
// A nil cert returns [ErrNoClientCert] so the caller can distinguish
// "no cert at all" from "cert presented but does not satisfy the
// registered method".
func VerifyClientAuth(method string, cert *x509.Certificate, expected ClientMatcher, jwks []byte) error {
	switch method {
	case MethodTLSClientAuth:
		return VerifyTLSClientAuth(cert, expected)
	case MethodSelfSignedTLSClientAuth:
		return VerifySelfSignedTLSClientAuth(cert, jwks)
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedMethod, method)
	}
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
//
// Subject DN comparison runs in two passes:
//
//  1. Byte-for-byte compare against [x509.Certificate.RawSubject]
//     (the DER-encoded form). The matcher's SubjectDN is parsed back
//     into a [pkix.Name] and re-marshalled to DER so RFC 4514 string-
//     ordering differences (CN/O/OU swaps that the standard library
//     emits in attribute-OID order rather than the registration form)
//     do not produce spurious mismatches.
//  2. Fallback to [pkix.Name.String] equality for matchers stored in
//     a non-canonical RFC 4514 string the DER round-trip cannot
//     reproduce (e.g. matchers registered with custom RDN ordering).
//     The fallback is conservative: it accepts only inputs the
//     standard library produces from the cert verbatim.
func VerifyTLSClientAuth(cert *x509.Certificate, expected ClientMatcher) error {
	if cert == nil {
		return fmt.Errorf("%w: nil certificate", ErrNoClientCert)
	}
	if !expected.hasAny() {
		return ErrNoMatcherConfigured
	}
	if expected.SubjectDN != "" {
		if subjectDNMatches(cert, expected.SubjectDN) {
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

// subjectDNMatches reports whether expected names the same DN as the
// cert's subject. The function is the dual-form compare documented on
// [VerifyTLSClientAuth]: it tries the DER round-trip first (so RFC
// 4514 string-ordering differences disappear) and falls back to the
// standard library's string form for matchers the DER pipeline cannot
// canonicalise.
//
// A matcher input that fails RFC 4514 parsing falls onto the string
// compare alone: rejecting parseable-but-malformed matchers here would
// surface as ErrSubjectMismatch on a perfectly valid registration, so
// the conservative posture preserves admission while logging would
// reveal the parse failure if the OP added a debug log point. The
// function returns false rather than an error because the caller
// already maps a non-match onto ErrSubjectMismatch.
func subjectDNMatches(cert *x509.Certificate, expected string) bool {
	// Pass 1: DER round-trip. The standard library's
	// [pkix.Name.String] emits attributes in OID order, which is the
	// same order the cert's DER encoding uses, so re-marshalling the
	// expected DN through pkix.Name catches the case where the
	// matcher was stored with a different surface ordering than the
	// cert carries.
	if expectedDER, ok := derFromDNString(expected); ok {
		if bytes.Equal(cert.RawSubject, expectedDER) {
			return true
		}
	}
	// Pass 2: standard-library string equality. This catches matchers
	// stored in a non-OID-order string the DER round-trip cannot
	// reproduce, but only when the cert's standard string form
	// happens to match verbatim. RFC 8705 §2.1.2 leaves the precise
	// comparison to the AS; the dual-form policy is documented on
	// [VerifyTLSClientAuth].
	return cert.Subject.String() == expected
}

// derFromDNString parses an RFC 4514 DN string and returns the
// canonical DER encoding the standard library would emit for the
// same name. The function is the dual-form compare's DER fast-path
// in [subjectDNMatches]: a parse failure returns ok=false and the
// caller falls back to the string-compare path.
//
// The standard library exposes no [pkix.ParseName] helper, so the
// parser walks the RFC 4514 form directly: comma-separated RDNs,
// each RDN a "key=value" attribute name. The parsed RDN slice goes
// through [pkix.Name.FillFromRDNSequence] + [pkix.Name.ToRDNSequence]
// so the resulting marshal lands in the canonical attribute order
// the standard library uses for [x509.Certificate.RawSubject].
// Attributes outside the closed catalogue [knownDNAttributes] return
// ok=false so the matcher falls back to the verbatim string compare.
func derFromDNString(dn string) ([]byte, bool) {
	seq, ok := parseDNString(dn)
	if !ok {
		return nil, false
	}
	// Round-trip the parsed RDN sequence through pkix.Name so the
	// resulting marshalled DER matches the canonical attribute
	// ordering the standard library uses when emitting the cert's
	// RawSubject. FillFromRDNSequence reads the DER form (root-
	// first); we already reversed inside parseDNString so the
	// typed Name is filled correctly. ToRDNSequence then re-emits
	// the same fields in the standard library's canonical order
	// (the same order x509.CreateCertificate uses), so the
	// marshalled bytes end up byte-equal to RawSubject when the
	// matcher named the same attribute set as the cert.
	var name pkix.Name
	name.FillFromRDNSequence(&seq)
	der, err := asn1.Marshal(name.ToRDNSequence())
	if err != nil {
		return nil, false
	}
	return der, true
}

// knownDNAttributes is the closed catalogue of RFC 4514 attribute
// names [parseDNString] accepts. The mapping picks the OID the
// standard library's [pkix.Name] surfaces under each attribute name
// (see pkix.Name.String) so the resulting DN re-marshals through the
// same encoding path the cert library used when emitting
// [x509.Certificate.RawSubject]. Attributes outside the catalogue
// (organisationalUnit pseudo-OIDs, extension fields) fall onto the
// string-compare path; the catalogue covers the attributes the standard
// library canonicalises verbatim
// (CN/O/OU/L/ST/C/STREET/POSTALCODE/SERIALNUMBER/DC/UID).
//
//nolint:gochecknoglobals // closed catalogue; immutable.
var knownDNAttributes = map[string]asn1.ObjectIdentifier{
	"CN":           {2, 5, 4, 3},
	"SERIALNUMBER": {2, 5, 4, 5},
	"C":            {2, 5, 4, 6},
	"L":            {2, 5, 4, 7},
	"ST":           {2, 5, 4, 8},
	"STREET":       {2, 5, 4, 9},
	"O":            {2, 5, 4, 10},
	"OU":           {2, 5, 4, 11},
	"POSTALCODE":   {2, 5, 4, 17},
	"DC":           {0, 9, 2342, 19200300, 100, 1, 25},
	"UID":          {0, 9, 2342, 19200300, 100, 1, 1},
}

// parseDNString splits an RFC 4514 DN into its RDN sequence. The
// parser is intentionally narrow — it walks comma-separated
// "key=value" pairs and resolves each key through
// [knownDNAttributes] — so it canonicalises the standard inputs
// without dragging the rest of RFC 4514 (escapes, multi-valued
// RDNs, dotted-decimal OID forms) onto the comparison path. Inputs
// outside that subset return ok=false; callers fall back to the
// verbatim string compare in [subjectDNMatches].
//
// RFC 4514 §2.1 spells RDNs most-specific first ("CN=...,O=..."),
// while the cert's DER encoding (RFC 5280 §4.1.2.4) lists the same
// RDNs root-first. The function reverses the parsed slice so the
// resulting RDNSequence — once asn1.Marshal'd — matches the byte
// shape [x509.Certificate.RawSubject] carries.
func parseDNString(dn string) (pkix.RDNSequence, bool) {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return nil, false
	}
	parts := splitDNComponents(dn)
	seq := make(pkix.RDNSequence, 0, len(parts))
	for _, raw := range parts {
		eq := strings.IndexByte(raw, '=')
		if eq <= 0 {
			return nil, false
		}
		key := strings.ToUpper(strings.TrimSpace(raw[:eq]))
		value := strings.TrimSpace(raw[eq+1:])
		if key == "" || value == "" {
			return nil, false
		}
		oid, known := knownDNAttributes[key]
		if !known {
			return nil, false
		}
		seq = append(seq, pkix.RelativeDistinguishedNameSET{
			{Type: oid, Value: value},
		})
	}
	if len(seq) == 0 {
		return nil, false
	}
	// RFC 4514 puts CN first; DER puts the root attribute (typically
	// C / DC) first. Reverse so the marshalled bytes match the cert's
	// RawSubject ordering.
	for i, j := 0, len(seq)-1; i < j; i, j = i+1, j-1 {
		seq[i], seq[j] = seq[j], seq[i]
	}
	return seq, true
}

// splitDNComponents splits dn on the unescaped commas that separate
// RDNs. RFC 4514 §2.4 lets RDNs carry escaped commas (",") inside an
// attribute value; the parser tolerates that escape so a matcher
// containing "L=Mountain View, O=Example" survives as a two-RDN DN
// rather than fracturing into three. Multi-valued RDNs joined with
// "+" are not split here — [parseDNString] already rejects them via
// the known-attribute table because the resulting RDN would not be a
// single attribute.
func splitDNComponents(dn string) []string {
	parts := make([]string, 0, 4)
	var b strings.Builder
	escaped := false
	for i := range len(dn) {
		c := dn[i]
		switch {
		case escaped:
			b.WriteByte(c)
			escaped = false
		case c == '\\':
			b.WriteByte(c)
			escaped = true
		case c == ',':
			parts = append(parts, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	if b.Len() > 0 {
		parts = append(parts, b.String())
	}
	return parts
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
// case folding. DNS names are case-insensitive per RFC 5280 §7.2,
// and email addresses are folded across the whole address per the
// matcher policy documented on [ClientMatcher.SANEmail] (more
// permissive than RFC 5280 §3.4.4 / RFC 5321 §2.4 strictly require).
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
