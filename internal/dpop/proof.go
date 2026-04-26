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

// allowedProofAlgs is the set of "alg" values [parseProof] accepts on
// the JWS header. ES256 and EdDSA are FAPI 2.0 baseline; RS256 is
// excluded because RFC 9449 §4.1 explicitly discourages it on the
// proof JWT (the JWK is RP-supplied and RS256's larger keys widen the
// per-request CPU cost). ES384 is reserved for a future jose-package
// expansion (see [internal/tokens] §150 on the same gating).
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var allowedProofAlgs = map[jose.Algorithm]struct{}{
	jose.AlgES256: {},
	jose.AlgEdDSA: {},
}

// proofClaims is the decoded claim bundle of a DPoP proof JWT. RFC 9449
// §4.2 marks "jti" / "htm" / "htu" / "iat" as required; "ath" is
// required when the proof is presented alongside an access token; and
// "nonce" is parsed but ignored (server-supplied nonces are out of
// scope for v0.x — the field is here so the wire form round-trips
// without surprise when the upstream feature ships).
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
	if c.HTM == "" || c.HTU == "" {
		return proofClaims{}, fmt.Errorf("%w: htm / htu are required", ErrProofMalformed)
	}
	if c.IssuedAt == 0 {
		return proofClaims{}, fmt.Errorf("%w: iat is required", ErrProofMalformed)
	}
	return c, nil
}

// canonicalRequestURL returns the canonical "htu" value for r per RFC
// 9449 §4.3: scheme + host + path with the scheme/host lower-cased and
// the query / fragment stripped. The function is tolerant of the
// transports the OP runs on top of (TLS-terminating proxies set
// X-Forwarded-Proto, but the issuer URL is fixed at startup so the
// caller passes an already-resolved request URL when those concerns
// matter).
func canonicalRequestURL(r requestURLSource) string {
	u := *r.URL
	if u.Scheme == "" {
		// http.Request from the standard library leaves Scheme
		// empty for incoming requests — the test server fills the
		// host but expects the handler to derive scheme from TLS.
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
	u.Host = strings.ToLower(u.Host)
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
	a.Host = strings.ToLower(a.Host)
	b.Host = strings.ToLower(b.Host)
	return a.String() == b.String()
}

// withinIatWindow reports whether iat is within ±window of now. The
// window is symmetric on purpose: a proof minted in the future is just
// as suspicious as one from the past, and RFC 9449 §11.1 instructs the
// server to reject either direction.
func withinIatWindow(iat int64, now time.Time, window time.Duration) bool {
	if window <= 0 {
		return false
	}
	t := time.Unix(iat, 0)
	delta := now.Sub(t)
	if delta < 0 {
		delta = -delta
	}
	return delta <= window
}
