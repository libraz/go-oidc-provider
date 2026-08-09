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

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// AuditEventLooseMethodCaseAdmitted is the canonical event name the
// verifier emits when [VerifierConfig.AllowLooseMethodCase] is set
// AND a proof's "htm" claim differed from the request method only in
// ASCII case. The wire response is unchanged — the proof was admitted
// — but SOC tooling needs a signal so it can pin the bridge while
// the responsible RP library is fixed. The value comes from the registry
// exposed publicly as [op.AuditDPoPLooseMethodCaseAdmitted].
const AuditEventLooseMethodCaseAdmitted = string(auditevent.AuditDPoPLooseMethodCaseAdmitted)

// DefaultIatWindow is the symmetric tolerance applied to the proof
// "iat" claim when [VerifyOptions.IatWindow] is unset. RFC 9449 §11.1
// recommends "a few minutes"; this OP sits at the short end of that
// range so a stolen proof has a small replay surface, and the JTI
// replay marker's retention is derived from the window rather than
// configured independently, which keeps the two from drifting apart.
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
	clock         Clock
	jtis          store.ConsumedJTIStore
	iatWindow     time.Duration
	replayLeew    time.Duration
	nonces        NonceVerifier
	looseMethCase bool
	emitter       audit.Emitter
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
	// the proof's nonce claim unread.
	Nonces NonceVerifier

	// AllowLooseMethodCase, when true, compares the proof's "htm"
	// claim to the request method under ASCII case folding rather
	// than the RFC 9449 §4.3 byte-equal rule. The default false is
	// strict (case-sensitive) so a proof carrying "post" against a
	// "POST" request fails [ErrProofHTMMismatch]; embedders facing
	// non-conforming RP libraries that up-case the verb in the
	// proof opt in via this flag. The opt-in is deliberately narrow
	// because tolerating case-variation widens the attack surface
	// for proof-substitution across endpoints whose method differs
	// only in case (none in HTTP today, but the RFC keeps the
	// distinction structural for forward-compatibility).
	//
	// Operational guidance: keep the default (strict, byte-equal)
	// in every greenfield deployment. RFC 9110 §9.1 pins HTTP
	// methods to canonical upper-case ("GET", "POST", …), and
	// RFC 9449 §4.3 inherits the byte-equal compare from there;
	// any RP that submits a lower-case "htm" is buggy under both
	// RFCs. Only flip this on after observing an interoperability
	// failure that traces to a specific RP library — and even
	// then, treat the loose mode as a temporary bridge while the
	// RP team ships the fix. Leaving the flag on indefinitely
	// silently accepts non-conforming proofs from every client,
	// not just the one that prompted the change.
	//
	// Observability: when [VerifierConfig.Emitter] is non-nil,
	// every loose-mode admission emits a warn-level audit event
	// named [AuditEventLooseMethodCaseAdmitted] carrying the
	// presented "htm" value and the canonical method. SOC
	// dashboards pin a counter on the event so the bridge is
	// visible operationally; embedders that ship the audit chain
	// see the signal even though the wire response was a normal
	// 200.
	AllowLooseMethodCase bool

	// Emitter is the optional audit-event sink the verifier
	// invokes when [AllowLooseMethodCase] admits a proof whose
	// "htm" differed from the request method only in ASCII case.
	// A nil emitter collapses to the no-op [audit.Discard] so the
	// verifier path is unconditional; embedders that want the
	// signal supply the OP-wide [audit.Emitter] (typically the
	// value [op/audit.Slog] returned).
	Emitter audit.Emitter
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
	emitter := cfg.Emitter
	if emitter == nil {
		emitter = audit.Discard()
	}
	return &Verifier{
		clock:     clock,
		jtis:      cfg.JTIs,
		iatWindow: window,
		// replayLeew is anchored on the proof's iat, but the iat
		// gate accepts the proof anywhere in [iat - iatWindow,
		// iat + iatWindow]. Setting the JTI expiry to iat + 2*window
		// guarantees the entry outlives the latest acceptable replay
		// attempt no matter when the legitimate use first marked it
		// (the worst case is mark at iat - iatWindow, replay at
		// iat + iatWindow — a gap of 2*iatWindow). A retention of
		// iat + iatWindow would leave a boundary where the entry
		// expires exactly when the iat gate still accepts the proof,
		// letting a replay at now == iat + iatWindow through both
		// gates.
		replayLeew:    2 * window,
		nonces:        cfg.Nonces,
		looseMethCase: cfg.AllowLooseMethodCase,
		emitter:       emitter,
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

// Checked is a proof that passed every stateless RFC 9449 §4.3 gate —
// parse, signature, typ/alg, htm, htu, iat, the optional "ath"
// binding, and the §8 / §9 nonce gate — but whose replay marker has
// NOT been written yet. [Verifier.Commit] performs that write and is
// what makes the proof single-use.
//
// The two-phase shape exists so an endpoint can reject a bad proof —
// including answering the §8 `use_dpop_nonce` challenge — before it
// has authenticated the client, without letting the unauthenticated
// request reach the durable replay table. RFC 9449 imposes no ordering
// between proof verification and client authentication: the proof is
// bound to the HTTP request (htm / htu / iat / ath / nonce) and to its
// own key, never to the client's credential, so deferring the write
// leaves every gate answering exactly the question it answered before.
// A caller that has no reason to split the two uses [Verifier.Verify],
// which runs both phases back to back.
type Checked struct {
	// JKT is the RFC 7638 SHA-256 thumbprint of the proof's JWK,
	// base64url-no-pad. The OP places it in cnf.jkt.
	JKT string

	// JTI is the proof's "jti" claim, exposed for audit logging.
	JTI string

	// replayExpiresAt is the retention deadline the replay marker
	// carries. It is derived from the proof's own iat rather than
	// from the commit time so a deferred [Verifier.Commit] cannot
	// stretch the entry past the window the iat gate accepts.
	replayExpiresAt time.Time
}

// Verify runs the full RFC 9449 §4.3 checklist on the supplied proof:
// parse + signature + typ/alg gate, htm/htu/iat/jti claim validation,
// optional ath binding, and replay marking via
// [store.ConsumedJTIStore]. The function returns a typed error from
// the [Err*] sentinel set on every failure path; the caller maps the
// sentinel onto an HTTP status without inspecting the wrapped cause.
//
// Verify is [Verifier.Check] followed immediately by
// [Verifier.Commit]; endpoints that must answer a proof rejection
// before authenticating the client call the two phases separately so
// an unauthenticated request performs no durable write.
func (v *Verifier) Verify(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
	checked, err := v.Check(ctx, in)
	if err != nil {
		return nil, err
	}
	if err := v.Commit(ctx, checked); err != nil {
		return nil, err
	}
	return &VerifyResult{JKT: checked.JKT, JTI: checked.JTI}, nil
}

// Commit writes the replay marker for a proof [Verifier.Check] already
// accepted, making that proof single-use. It returns [ErrProofReplayed]
// when the same (key, jti) pair was already committed.
//
// Commit is the only phase that touches storage, so a caller that runs
// it after client authentication keeps the durable write behind a
// credential. Two concurrent requests carrying the same proof still
// resolve deterministically: the store's compare-and-set decides, and
// the loser sees ErrProofReplayed exactly as it would have under
// [Verifier.Verify].
func (v *Verifier) Commit(ctx context.Context, checked *Checked) error {
	if checked == nil {
		return fmt.Errorf("%w: nil checked proof", ErrProofMalformed)
	}
	if err := v.jtis.Mark(ctx, "dpop:"+checked.JKT+":"+checked.JTI, checked.replayExpiresAt); err != nil {
		if errors.Is(err, store.ErrAlreadyConsumed) {
			return ErrProofReplayed
		}
		return fmt.Errorf("dpop: mark jti: %w", err)
	}
	return nil
}

// Check runs every stateless RFC 9449 §4.3 gate on the supplied proof
// and returns the accepted proof without marking it consumed. See
// [Checked] for why the replay marking is a separate phase.
//
// The gates are deliberately enumerated in flat shape so each one maps
// onto its RFC 9449 §4 / §6 clause; do not fold them into helpers to
// shorten the function.
func (v *Verifier) Check(ctx context.Context, in VerifyInput) (*Checked, error) {
	if in.URL == nil {
		return nil, fmt.Errorf("%w: nil request URL", ErrProofMalformed)
	}
	parsed, err := parseProof(in.ProofHeader)
	if err != nil {
		return nil, err
	}

	if !v.compareMethod(parsed.claims.HTM, in.Method) {
		return nil, ErrProofHTMMismatch
	}
	if v.looseMethCase && parsed.claims.HTM != in.Method {
		// Loose-mode admission: the strict byte-equal compare
		// would have rejected this proof. Emit the warn-level
		// audit signal so SOC tooling can spot the bridge while
		// the responsible RP library is fixed (B-DPoP §4.3 strict
		// posture is the default; loose mode is opt-in).
		v.emitter.Emit(ctx, audit.Event{
			Name:    AuditEventLooseMethodCaseAdmitted,
			Level:   audit.LevelWarn,
			Message: "DPoP proof admitted with case-folded htm",
			Extras: map[string]any{
				"htm":            parsed.claims.HTM,
				"request_method": in.Method,
			},
		})
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

	// Compute the JWK thumbprint after the nonce gate succeeds, then
	// namespace the replay key by the proof key as well as its jti.
	// The order closes a replay
	// vector where an attacker observes a valid (htm/htu/iat/ath)
	// proof, races the legitimate retry whose nonce-check fails on
	// stale input, and then resubmits the SAME jti with a fresh
	// nonce. Every nonce-passing proof advances the consumed-jti
	// table under its JKT, so a second use of the same JTI by the
	// same proof key — regardless of the second submission's nonce
	// — surfaces as ErrProofReplayed. Pre-nonce failures (htm /
	// htu / iat / ath / nonce) never reach this point, preserving
	// the "malformed proof never advances the table" property the
	// previous ordering relied on.
	jkt, err := Thumbprint(parsed.jwk)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProofMalformed, err)
	}

	return &Checked{
		JKT:             jkt,
		JTI:             parsed.claims.JTI,
		replayExpiresAt: time.Unix(parsed.claims.IssuedAt, 0).Add(v.replayLeew),
	}, nil
}

// checkNonce runs the optional RFC 9449 §8 / §9 nonce gate. The check
// sits ahead of the replay mark in [Verifier.Verify] so a stale-nonce
// proof does not consume a jti slot the legitimate retry would need:
// the client is expected to retry with a fresh proof (new jti, new
// nonce), and burning the failed jti would force the retry to surface
// as a spurious replay. A nonce-passing proof DOES mark its jti
// immediately afterwards (see the reorder note in [Verifier.Verify])
// so the same jti cannot be reused against a fresh nonce.
//
// A nil [Verifier.nonces] disables the gate: proofs without a nonce
// claim are then always accepted.
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
	in, err := httpVerifyInput(r, accessToken)
	if err != nil {
		return nil, err
	}
	return v.Verify(ctx, in)
}

// CheckHTTPRequest is the [Verifier.Check] counterpart of
// [Verifier.VerifyHTTPRequest]: it runs the stateless gates over an
// [*http.Request] and leaves the replay marking to a later
// [Verifier.Commit]. Endpoints that authenticate the client between
// the two phases use this entry point.
func (v *Verifier) CheckHTTPRequest(ctx context.Context, r *http.Request, accessToken string) (*Checked, error) {
	in, err := httpVerifyInput(r, accessToken)
	if err != nil {
		return nil, err
	}
	return v.Check(ctx, in)
}

// httpVerifyInput projects an [*http.Request] onto a [VerifyInput].
// It is shared by the two HTTP entry points so the header handling
// (including the §4.1 single-proof rule) cannot drift between them.
func httpVerifyInput(r *http.Request, accessToken string) (VerifyInput, error) {
	if r == nil {
		return VerifyInput{}, fmt.Errorf("%w: nil request", ErrProofMalformed)
	}
	headers := r.Header.Values("DPoP")
	if len(headers) > 1 {
		return VerifyInput{}, fmt.Errorf("%w: multiple DPoP proofs", ErrProofMalformed)
	}
	header := ""
	if len(headers) == 1 {
		header = headers[0]
	}
	return VerifyInput{
		ProofHeader: header,
		Method:      r.Method,
		URL:         r.URL,
		Host:        r.Host,
		TLS:         r.TLS != nil,
		AccessToken: accessToken,
	}, nil
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

// compareMethod runs the htm-vs-method comparison. The default posture
// is byte-equal per RFC 9449 §4.3; when [VerifierConfig.AllowLooseMethodCase]
// is set the comparison falls back to ASCII case folding so a proof
// carrying "post" against a "POST" request still matches. The opt-in
// is package-local rather than a global default because the spec
// pins the rule and only RP libraries that violate it benefit from
// the relaxation.
func (v *Verifier) compareMethod(htm, method string) bool {
	if v.looseMethCase {
		return equalFold(htm, method)
	}
	return htm == method
}

// equalFold reports whether s and t are equal under ASCII case
// folding. The helper is the relaxed branch of [Verifier.compareMethod];
// it is also exercised by the proof parser. The fold is bounded to
// ASCII because HTTP methods are ASCII per RFC 9110.
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
