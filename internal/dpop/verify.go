package dpop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// DefaultIatWindow is the symmetric tolerance applied to the proof
// "iat" claim when [VerifyOptions.IatWindow] is unset. RFC 9449 §11.1
// recommends "a few minutes"; the value here matches the design doc's
// 5-minute replay-store TTL while keeping the per-request window
// short enough that a stolen proof has a small replay surface.
const DefaultIatWindow = 60 * time.Second

// Clock is the package-local view of the wall clock. It mirrors the
// verifier-shaped Clock used in [internal/tokens] so an [op.Clock]
// value satisfies it without an explicit adapter, and a nil falls
// back to the system clock.
type Clock interface {
	Now() time.Time
}

// NonceVerifier is the contract the [Verifier] consults when the
// deployment opts into the RFC 9449 §8 / §9 server-supplied nonce
// flow. A nil [VerifierConfig.Nonces] disables the check entirely:
// proofs without a "nonce" claim are accepted, and proofs that carry
// one are not validated against any list.
//
// Implementations MUST be safe for concurrent use; the verifier
// invokes [Validate] from every request goroutine. The embedder is
// responsible for the rotation policy (single value, sliding window,
// HMAC-keyed, etc.); the dpop package does not assume one.
type NonceVerifier interface {
	// Validate reports whether nonce is currently acceptable. The
	// implementation MAY treat empty input as "not acceptable"
	// directly; the verifier already short-circuits on empty before
	// reaching this method, but the interface is permissive so a
	// caller embedding the implementation outside the verifier need
	// not duplicate that guard.
	Validate(nonce string) bool
}

// NonceIssuer is the contract HTTP handlers consult when they need
// to stamp a fresh "DPoP-Nonce" response header — both on the
// `use_dpop_nonce` challenge that follows [ErrProofNonceMissing] /
// [ErrProofNonceInvalid] and on success-path rotation. It is
// deliberately split from [NonceVerifier] so a resource-server-style
// embedder that only validates existing nonces can satisfy
// [NonceVerifier] without owning an issuance pipeline; the typical
// embedder satisfies both with a single struct.
//
// Implementations MUST be safe for concurrent use; the handler
// invokes [IssueNonce] from every request goroutine. An empty return
// value is treated by callers as "issuer offline": the challenge is
// emitted without a DPoP-Nonce header. Implementations SHOULD never
// return empty in normal operation.
type NonceIssuer interface {
	IssueNonce() string
}

// IsNonceError reports whether err is one of the RFC 9449 §8 / §9
// nonce sentinels — [ErrProofNonceMissing] or [ErrProofNonceInvalid].
// Endpoint code uses this to dispatch onto the `use_dpop_nonce`
// challenge response without re-implementing the [errors.Is]
// disjunction in every package.
func IsNonceError(err error) bool {
	return errors.Is(err, ErrProofNonceMissing) || errors.Is(err, ErrProofNonceInvalid)
}

// Verifier is the request-scoped entry point. Construct it once at
// startup with [NewVerifier]; the value is immutable and safe for
// concurrent use.
type Verifier struct {
	clock      Clock
	jtis       store.ConsumedJTIStore
	iatWindow  time.Duration
	replayLeew time.Duration
	nonces     NonceVerifier
}

// VerifierConfig is the parameter bundle for [NewVerifier].
type VerifierConfig struct {
	// JTIs is the replay store the verifier marks "jti" claims into.
	// Required.
	JTIs store.ConsumedJTIStore

	// Clock supplies the current wall-clock reading. A nil value
	// falls back to [internal/timex.SystemClock].
	Clock Clock

	// IatWindow overrides [DefaultIatWindow]. Zero or negative falls
	// back to the default.
	IatWindow time.Duration

	// Nonces opts the verifier into the RFC 9449 §8 / §9
	// server-supplied nonce flow. When non-nil, every proof MUST
	// carry a "nonce" claim accepted by [NonceVerifier.Validate];
	// otherwise the verifier returns [ErrProofNonceMissing] or
	// [ErrProofNonceInvalid] and the HTTP layer issues the
	// "use_dpop_nonce" challenge. A nil value (the default) leaves
	// the proof's nonce claim unread, matching the v0.x posture.
	Nonces NonceVerifier
}

// NewVerifier builds a [*Verifier] from cfg. The function returns an
// error when a required field is missing so the embedder fails fast
// at startup rather than at the first request.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.JTIs == nil {
		return nil, errors.New("dpop: NewVerifier requires JTIs store")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = timex.SystemClock
	}
	window := cfg.IatWindow
	if window <= 0 {
		window = DefaultIatWindow
	}
	return &Verifier{
		clock:      clock,
		jtis:       cfg.JTIs,
		iatWindow:  window,
		replayLeew: window,
		nonces:     cfg.Nonces,
	}, nil
}

// VerifyInput bundles the per-request inputs to [Verifier.Verify].
type VerifyInput struct {
	// ProofHeader is the raw "DPoP" HTTP header value the RP sent.
	ProofHeader string

	// Method is the request's HTTP verb, used to validate "htm".
	Method string

	// URL is the request URL the verifier compares against "htu".
	// Callers MUST pass the URL the RP would have addressed (i.e.
	// taking any reverse-proxy rewrite into account); the verifier
	// strips query / fragment internally.
	URL *url.URL

	// Host is consulted as a fallback when URL.Host is empty (the
	// standard-library [http.Request.URL] often is).
	Host string

	// TLS is true when the connection terminated TLS at the OP. It
	// drives the canonical scheme when URL.Scheme is empty.
	TLS bool

	// AccessToken is the bearer token the request also carries, or
	// "" if the proof is not paired with an access token (the typical
	// shape at /token, where the access token has not been issued
	// yet). When non-empty, the verifier requires the proof's "ath"
	// claim to match SHA-256(access_token).
	AccessToken string
}

// VerifyResult is the projection [Verifier.Verify] returns on success.
// Callers thread the JKT into the issued access token / refresh token
// so subsequent uses of the credential can be matched against the
// same key.
type VerifyResult struct {
	// JKT is the RFC 7638 SHA-256 thumbprint of the proof's JWK,
	// base64url-no-pad. The OP places it in cnf.jkt.
	JKT string

	// JTI is the proof's "jti" claim. Already marked consumed by
	// the time the caller observes the value; exposed for audit
	// logging only.
	JTI string
}

// Verify runs the full RFC 9449 §4.3 checklist on the supplied proof:
// parse + signature + typ/alg gate, htm/htu/iat/jti claim validation,
// optional ath binding, and replay marking via
// [store.ConsumedJTIStore]. The function returns a typed error from
// the [Err*] sentinel set on every failure path; the caller maps the
// sentinel onto an HTTP status without inspecting the wrapped cause.
func (v *Verifier) Verify(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
	if in.URL == nil {
		return nil, fmt.Errorf("%w: nil request URL", ErrProofMalformed)
	}
	parsed, err := parseProof(in.ProofHeader)
	if err != nil {
		return nil, err
	}

	if !equalFold(parsed.claims.HTM, in.Method) {
		return nil, ErrProofHTMMismatch
	}
	requestURL := canonicalRequestURL(requestURLSource{URL: in.URL, Host: in.Host, TLS: in.TLS})
	if !canonicalEqual(parsed.claims.HTU, requestURL) {
		return nil, ErrProofHTUMismatch
	}

	now := v.clock.Now()
	if !withinIatWindow(parsed.claims.IssuedAt, now, v.iatWindow) {
		return nil, ErrProofIatWindow
	}

	if in.AccessToken != "" {
		if parsed.claims.ATH == "" {
			return nil, ErrProofATHMismatch
		}
		if parsed.claims.ATH != AccessTokenHash(in.AccessToken) {
			return nil, ErrProofATHMismatch
		}
	}

	if err := v.checkNonce(parsed.claims.Nonce); err != nil {
		return nil, err
	}

	jkt, err := Thumbprint(parsed.jwk)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProofMalformed, err)
	}

	// Replay detection runs LAST so a malformed proof never advances
	// the consumed-jti table. The expiresAt value is now + window so
	// a record naturally falls out of the store after the same
	// duration the iat check would have rejected for.
	expiresAt := now.Add(v.replayLeew)
	if err := v.jtis.Mark(ctx, parsed.claims.JTI, expiresAt); err != nil {
		if errors.Is(err, store.ErrAlreadyConsumed) {
			return nil, ErrProofReplayed
		}
		return nil, fmt.Errorf("dpop: mark jti: %w", err)
	}

	return &VerifyResult{JKT: jkt, JTI: parsed.claims.JTI}, nil
}

// checkNonce runs the optional RFC 9449 §8 / §9 nonce gate. The
// check sits ahead of the replay mark in [Verifier.Verify] so a
// stale-nonce proof does not consume a jti slot the legitimate retry
// would need: the client is expected to retry with a fresh proof
// (new jti, new nonce), and burning the failed jti would force the
// retry to surface as a spurious replay.
//
// A nil [Verifier.nonces] disables the gate; this matches the v0.x
// posture where proofs without a nonce claim were always accepted.
func (v *Verifier) checkNonce(nonce string) error {
	if v.nonces == nil {
		return nil
	}
	if nonce == "" {
		return ErrProofNonceMissing
	}
	if !v.nonces.Validate(nonce) {
		return ErrProofNonceInvalid
	}
	return nil
}

// VerifyHTTPRequest is the convenience wrapper that pulls inputs off
// an [*http.Request] before calling [Verifier.Verify]. The OP-side
// HTTP handlers use this entry point; tests that need finer control
// over the URL / Host pair go through [Verifier.Verify] directly.
//
// RFC 9449 §4.1 requires exactly one DPoP proof per request; multiple
// "DPoP" header values surface as [ErrProofMalformed] so the handler
// emits invalid_request rather than silently picking the first proof.
func (v *Verifier) VerifyHTTPRequest(ctx context.Context, r *http.Request, accessToken string) (*VerifyResult, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil request", ErrProofMalformed)
	}
	headers := r.Header.Values("DPoP")
	if len(headers) > 1 {
		return nil, fmt.Errorf("%w: multiple DPoP proofs", ErrProofMalformed)
	}
	header := ""
	if len(headers) == 1 {
		header = headers[0]
	}
	return v.Verify(ctx, VerifyInput{
		ProofHeader: header,
		Method:      r.Method,
		URL:         r.URL,
		Host:        r.Host,
		TLS:         r.TLS != nil,
		AccessToken: accessToken,
	})
}

// AccessTokenHash returns the SHA-256 base64url-no-pad hash of token,
// which is the value RFC 9449 §4.3 binds to the proof's "ath" claim
// when the proof is presented alongside an access token. The function
// is exported so the token-binding layer can compute the value
// without re-implementing it.
func AccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// equalFold reports whether s and t are equal under ASCII case
// folding. RFC 9449 §4.3 says HTTP method comparisons are case-
// sensitive ("GET" matches only "GET"), but RP libraries occasionally
// up-case the verb in the proof; we tolerate that on the proof side
// because the OP itself normalises to upper-case in
// [canonicalRequestURL]. The fold is bounded to ASCII because HTTP
// methods are ASCII per RFC 9110.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if 'a' <= ca && ca <= 'z' {
			ca -= 'a' - 'A'
		}
		if 'a' <= cb && cb <= 'z' {
			cb -= 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
