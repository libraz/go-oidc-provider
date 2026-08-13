package dpop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// proofTyp is the value RFC 9449 §4.2 mandates for the JOSE "typ"
// header on a DPoP proof. RPs that emit a different value (or omit
// the header) are rejected before any signature work is done.
const proofTyp = "dpop+jwt"

// maxJTILen bounds the "jti" claim length. RFC 9449 sets no cap, but
// the verifier rejects oversized values to close the unbounded-
// allocation surface (replay store key, audit log column). The value
// is comfortably above any UUID encoding the typical client emits.
const maxJTILen = 256

// allowedProofAlgs is the set of "alg" values [parseProof] accepts on
// the JWS header. ES256 / EdDSA are FAPI 2.0 baseline; PS256 is included
// because RFC 9449 §4.1 permits any asymmetric JWS algorithm "deemed
// secure" and PS256 (RSASSA-PSS) is the FAPI-recommended RSA scheme.
// RS256 (PKCS#1 v1.5) is excluded — modern profiles steer RSA toward PSS
// and OFCS's negative-test pipeline relies on this rejection. ES384 is
// absent because [jose.Algorithm] has no member for it — the
// verification alg set is a closed enum there, so widening this map
// alone would name a constant that does not exist.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var allowedProofAlgs = map[jose.Algorithm]struct{}{
	jose.AlgES256: {},
	jose.AlgEdDSA: {},
	jose.AlgPS256: {},
}

// proofClaims is the decoded claim bundle of a DPoP proof JWT. RFC 9449
// §4.2 marks "jti" / "htm" / "htu" / "iat" as required; "ath" is
// required when the proof is presented alongside an access token; and
// "nonce" is required when the verifier has been configured with a
// [NonceVerifier] (RFC 9449 §8 / §9 server-supplied nonce flow).
// Without that config the field is parsed but unread, so a proof
// minted with a nonce claim still round-trips.
type proofClaims struct {
	JTI      string `json:"jti"`
	HTM      string `json:"htm"`
	HTU      string `json:"htu"`
	IssuedAt int64  `json:"iat"`
	ATH      string `json:"ath,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

// parsedProof is the internal projection of a successfully-parsed proof
// JWT. The verifier consumes this shape; tests may inspect it directly.
type parsedProof struct {
	// claims is the decoded claim bundle.
	claims proofClaims

	// jwk is the public key embedded in the JWS header. The signature
	// has already been verified against this key by the time the
	// caller observes the value; downstream code uses it to derive
	// the cnf.jkt thumbprint.
	jwk *josev4.JSONWebKey
}

// parseProof validates the proof JWT structurally and verifies its
// self-signature. The function returns either a [*parsedProof] or one
// of the [Err*] sentinels; it never returns a wrapped third-party
// error to the caller because the HTTP layer must echo a fixed wire
// code.
func parseProof(raw string) (*parsedProof, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: empty proof", ErrProofMalformed)
	}
	jws, alg, err := jose.ParseSigned(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProofMalformed, err)
	}
	if _, ok := allowedProofAlgs[alg]; !ok {
		return nil, fmt.Errorf("%w: alg %q not allowed for DPoP", ErrProofMalformed, alg)
	}
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("%w: DPoP proof must carry exactly one signature", ErrProofMalformed)
	}
	if err := assertProofTyp(jws.Signatures[0]); err != nil {
		return nil, err
	}
	jwk := jws.Signatures[0].Header.JSONWebKey
	if jwk == nil {
		return nil, fmt.Errorf("%w: missing jwk header", ErrProofMalformed)
	}
	if !jwk.IsPublic() {
		return nil, fmt.Errorf("%w: jwk header must be a public key", ErrProofMalformed)
	}
	if err := assertSupportedKeyType(jwk); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProofMalformed, err)
	}

	payload, err := jws.Verify(jwk.Key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProofSignature, err)
	}

	claims, err := decodeProofClaims(payload)
	if err != nil {
		return nil, err
	}
	return &parsedProof{claims: claims, jwk: jwk}, nil
}

// assertProofTyp checks the JOSE "typ" header. The value lives in the
// signature's ExtraHeaders map because go-jose only promotes "kid",
// "alg", "jwk", and "nonce" into the typed [Header] struct.
func assertProofTyp(sig josev4.Signature) error {
	for _, hdr := range []map[josev4.HeaderKey]any{sig.Protected.ExtraHeaders, sig.Header.ExtraHeaders} {
		if v, ok := hdr[josev4.HeaderType]; ok {
			if s, ok := v.(string); ok {
				if s == proofTyp {
					return nil
				}
				return fmt.Errorf("%w: typ %q is not %q", ErrProofMalformed, s, proofTyp)
			}
		}
	}
	return fmt.Errorf("%w: missing typ header", ErrProofMalformed)
}

// decodeProofClaims parses payload into a [proofClaims], surfacing
// [ErrProofMalformed] for malformed JSON or missing mandatory members.
// RFC 9449 §4.2 allows extension members so the decoder tolerates them
// silently: the package only projects the claims it acts on.
func decodeProofClaims(payload []byte) (proofClaims, error) {
	var c proofClaims
	if err := json.NewDecoder(bytes.NewReader(payload)).Decode(&c); err != nil {
		return proofClaims{}, fmt.Errorf("%w: decode payload: %w", ErrProofMalformed, err)
	}
	if c.JTI == "" {
		return proofClaims{}, ErrProofMissingJTI
	}
	// RFC 9449 sets no upper bound on the "jti" claim, but every
	// downstream consumer (replay store key length, audit log column,
	// debug-trace size) benefits from a hard cap. 256 bytes is
	// comfortably above any sensible client-emitted JTI (UUIDv4 in
	// hex with separators is 36 bytes; UUIDv7 base64url is 22) while
	// closing the unbounded-allocation vector at the verifier
	// boundary. ErrProofMalformed is the right shape: an oversized jti
	// is a syntactically malformed proof, not a replay.
	if len(c.JTI) > maxJTILen {
		return proofClaims{}, fmt.Errorf("%w: jti too long", ErrProofMalformed)
	}
	if c.HTM == "" || c.HTU == "" {
		return proofClaims{}, fmt.Errorf("%w: htm / htu are required", ErrProofMalformed)
	}
	if c.IssuedAt == 0 {
		return proofClaims{}, fmt.Errorf("%w: iat is required", ErrProofMalformed)
	}
	return c, nil
}

// canonicalRequestURL returns the canonical "htu" value for r per RFC
// 9449 §4.3: scheme + host + path with the scheme/host lower-cased,
// any default port (":80" for http, ":443" for https) stripped, and
// the query / fragment removed.
//
// The function is tolerant of the transports the OP runs on top of:
// when internal/proxy has rewritten the inbound request through the
// trusted-proxy middleware (XFP / XFH), the cloned URL carries the
// externally-visible scheme and host, and this canonicalisation
// observes them verbatim. Callers that bypass that middleware MAY pass
// the request URL with [requestURLSource.TLS] set so the scheme
// fallback derives from the live TLS state.
func canonicalRequestURL(r requestURLSource) string {
	u := *r.URL
	if u.Scheme == "" {
		// http.Request from the standard library leaves Scheme
		// empty for incoming requests — the test server fills the
		// host but expects the handler to derive scheme from TLS.
		// When a trusted reverse proxy terminated TLS the scheme
		// is already populated by the internal/proxy middleware,
		// so this fallback only fires for direct connections.
		if r.TLS {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	if u.Host == "" {
		u.Host = r.Host
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = stripDefaultPort(strings.ToLower(u.Host), u.Scheme)
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// requestURLSource is the small subset of [http.Request] fields
// [canonicalRequestURL] needs. The struct exists so unit tests can
// build inputs without fabricating an entire [http.Request].
type requestURLSource struct {
	URL  *url.URL
	Host string
	TLS  bool
}

// canonicalEqual reports whether two URLs match after canonicalisation.
// Used by the verifier to compare the proof's "htu" against the
// computed request URL.
//
// Both inputs are folded to RFC 9449 §4.3 canonical form (scheme and
// host lower-cased; query and fragment stripped) and any default port
// (":80" for http, ":443" for https) is removed before comparison.
// The default-port normalisation makes "https://op.example.com/token"
// and "https://op.example.com:443/token" — both spec-conformant — the
// same value to the verifier.
func canonicalEqual(htu, request string) bool {
	if htu == request {
		return true
	}
	a, errA := url.Parse(htu)
	b, errB := url.Parse(request)
	if errA != nil || errB != nil {
		return false
	}
	a.RawQuery, a.Fragment = "", ""
	b.RawQuery, b.Fragment = "", ""
	a.Scheme = strings.ToLower(a.Scheme)
	b.Scheme = strings.ToLower(b.Scheme)
	a.Host = normalizeHost(strings.ToLower(a.Host), a.Scheme)
	b.Host = normalizeHost(strings.ToLower(b.Host), b.Scheme)
	return a.String() == b.String()
}

func normalizeHost(host, scheme string) string {
	host = stripDefaultPort(host, scheme)
	if strings.HasSuffix(host, ".") {
		return strings.TrimSuffix(host, ".")
	}
	return host
}

// stripDefaultPort returns host with any default port for scheme
// removed. The function is RFC 3986 §3.2.3 normalisation applied to
// the host:port form Go's [url.URL.Host] field carries: ":80" is the
// default for http, ":443" for https. The helper is conservative —
// any non-default explicit port is preserved verbatim — so a proof
// that pins ":8443" still has to be compared verbatim.
//
// IPv6 hosts arrive bracketed ("[::1]:443"); the function rewrites the
// suffix without unwrapping the bracket so callers do not have to
// special-case the literal.
func stripDefaultPort(host, scheme string) string {
	if host == "" {
		return host
	}
	colon := strings.LastIndexByte(host, ':')
	if colon < 0 {
		return host
	}
	// IPv6 literals carry colons inside the brackets; only the
	// trailing ":port" suffix sits outside the closing bracket.
	if strings.HasPrefix(host, "[") {
		bracket := strings.LastIndexByte(host, ']')
		if bracket < 0 || colon < bracket {
			return host
		}
	}
	port := host[colon+1:]
	switch {
	case scheme == "https" && port == "443":
		return host[:colon]
	case scheme == "http" && port == "80":
		return host[:colon]
	default:
		return host
	}
}

// withinIatWindow reports whether iat is within ±window of now. The
// window is symmetric on purpose: a proof minted in the future is just
// as suspicious as one from the past, and RFC 9449 §11.1 instructs the
// server to reject either direction.
//
// The comparison is between instants, never between a difference and
// the window. [time.Time.Sub] saturates at ±[time.Duration] range, so a
// far-future iat yields math.MinInt64 — whose negation wraps back to
// itself, leaving a "distance" that compares as less than any window.
// A client-supplied timestamp decides that comparison, so the
// saturating form fails open at exactly the input an attacker controls.
// Comparing now.Add(±window) against the instant has no such edge: an
// out-of-range iat lands outside the bounds in whichever direction it
// overflowed, and is refused.
func withinIatWindow(iat int64, now time.Time, window time.Duration) bool {
	if window <= 0 {
		return false
	}
	t := time.Unix(iat, 0)
	return !t.Before(now.Add(-window)) && !t.After(now.Add(window))
}
