package userinfo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Clock is the package-local view of the wall clock. It is duplicated
// here (rather than imported from internal/timex) so this package keeps
// the same boundary discipline as internal/tokens: the public op/
// namespace forwards its [op.Clock] without an explicit adapter because
// Go interface satisfaction is structural. A nil [HandlerDeps.Clock]
// falls back to the verifier's own system-clock default.
type Clock interface {
	Now() time.Time
}

// HandlerDeps bundles the runtime dependencies the /userinfo handler
// needs. The HTTP layer constructs a HandlerDeps once at startup and
// passes it to [Handler]; the handler is otherwise self-contained.
type HandlerDeps struct {
	// Keys is the set of public keys used to verify the bearer access
	// token. The active key plus all retiring keys MUST be present so
	// that tokens minted before a rotation continue to verify.
	Keys *keys.Set

	// Issuer is the value the access token's "iss" claim is compared
	// against. An empty Issuer disables the check; callers MUST set
	// it for any production deployment.
	Issuer string

	// Clients is the read-only client registry. The handler consults
	// it after access-token verification to project the registered
	// userinfo response shape — encrypted JWE wrap when the client
	// registered userinfo_encrypted_response_alg / _enc, signed JWT
	// otherwise. A nil value disables the encryption branch and the
	// handler always emits the signed (or JSON) shape.
	Clients store.ClientStore

	// UserStore is the read-only end-user lookup the handler consults
	// after the bearer token has verified. It MUST return
	// [store.ErrNotFound] when the subject does not exist.
	UserStore store.UserStore

	// SubjectProjector, when non-nil, converts the OP-internal raw
	// subject into the per-client public OIDC "sub" value the userinfo
	// response carries (OIDC Core §5.4: userinfo "sub" matches the
	// corresponding id_token "sub"; §8.1: pairwise subjects are
	// per-client opaque). The raw subject is recovered by pivoting
	// through the access token's "gid" private claim to the owning
	// grant — see [assembleClaims] / [resolveRawSubject]. UserStore
	// lookup keys on the raw value so pairwise subjects do not become
	// database keys.
	SubjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error)

	// Grants is the read-only grant lookup the handler consults to
	// honour any OIDC Core 1.0 §5.5 "claims" request that was
	// persisted on the originating grant. A nil store disables the
	// per-claim projection — the handler falls back to scope-derived
	// release, which is the v0.x default for embedders that have not
	// yet wired the grant store into the userinfo handler.
	Grants store.GrantStore

	// Clock supplies the current wall-clock reading consumed by the
	// access-token verifier. A nil Clock falls back to the system
	// clock inside [tokens.AccessTokenVerifier].
	Clock Clock

	// Leeway is the symmetric tolerance applied to the access-token
	// "exp" / "iat" comparisons. RFC 7519 §4.1.4 caps the recommended
	// value at two minutes; the HTTP layer typically passes a smaller
	// value so a clock-skewed RP retries quickly.
	Leeway time.Duration

	// CustomScopeClaims maps a scope name to the list of claim names
	// it releases. Embedders register custom scopes via op.WithScope;
	// the value is threaded through to [Build] verbatim.
	CustomScopeClaims map[string][]string

	// DPoP is the RFC 9449 proof verifier. A nil value disables
	// DPoP enforcement entirely; tokens carrying cnf.jkt are then
	// rejected to fail closed (silently downgrading a sender-
	// constrained token to bearer would defeat the binding).
	DPoP *dpop.Verifier

	// DPoPNonces is the RFC 9449 §9 nonce issuer consulted on the
	// `use_dpop_nonce` challenge response. A nil value omits the
	// "DPoP-Nonce" response header on the challenge but the
	// WWW-Authenticate value still carries error="use_dpop_nonce" so
	// a debugger can see the gate triggered. The expected wiring is
	// one struct that satisfies both [dpop.NonceVerifier] (consumed by
	// [HandlerDeps.DPoP]) and [dpop.NonceIssuer] (this field) so
	// issuance and validation share a rotation pipeline.
	DPoPNonces dpop.NonceIssuer

	// MTLS is the RFC 8705 client-cert verifier. A nil value
	// disables mTLS enforcement entirely; tokens carrying
	// cnf.x5t#S256 are then rejected to fail closed.
	MTLS *mtls.Verifier

	// AccessTokens is the [store.AccessTokenRegistry] consulted after
	// signature / cnf checks pass to reject tokens that have been
	// revoked since issuance (RFC 6749 §4.1.2 cascade, RFC 7662 §2.2
	// implicit "active" semantics). The lookup runs late on purpose:
	// an obviously-malformed or expired token is rejected without
	// paying for the registry round-trip. A nil value disables the
	// check entirely; the handler then returns the legacy behaviour
	// (bearer tokens stay valid until exp regardless of any
	// revocation that landed between issuance and the call).
	AccessTokens store.AccessTokenRegistry

	// OpaqueAccessTokens is the [store.OpaqueAccessTokenStore] the
	// opaque-format /userinfo branch consults (ADR 0024). When the
	// presented bearer is not JWS-shaped the handler hashes it,
	// looks the digest up here, and applies the same revoked /
	// expired / cnf-mismatch checks as the JWT path before releasing
	// claims. A nil value disables the opaque branch; non-JWS tokens
	// then collapse onto the existing invalid_token response,
	// mirroring the JWT-only legacy posture.
	OpaqueAccessTokens store.OpaqueAccessTokenStore

	// GrantRevocations is the [store.GrantRevocationStore] consulted
	// by the grant-tombstone JWT access-token revocation strategy
	// (ADR 0025). The /userinfo handler uses it to reject access
	// tokens whose grant has been tombstoned; the lookup is keyed by
	// the AT's "gid" private claim. A nil value disables the lookup
	// and the handler falls back to whichever legacy behaviour
	// [RevocationStrategy] selects.
	GrantRevocations store.GrantRevocationStore

	// RevocationStrategy selects the JWT access-token revocation
	// shape (ADR 0025). The zero value is
	// [store.RevocationStrategyGrantTombstone], which is the
	// documented default; the library wires this from
	// [op.WithAccessTokenRevocationStrategy].
	RevocationStrategy store.AccessTokenRevocationStrategy

	// ClientEncJWKs resolves the RP's encryption recipient when the
	// client registered userinfo_encrypted_response_alg / _enc and the
	// response is JWT-shaped (RFC 6750 / OIDC Core 1.0 §5.3.2). A nil
	// value disables outbound userinfo encryption; clients that
	// registered the metadata still see signed JWT responses, which
	// the OP signals upstream as a configuration mismatch via the
	// validator at registration time.
	ClientEncJWKs *clientencjwks.Resolver
}

// Handler returns the /userinfo [http.Handler]. Behaviour follows
// RFC 6750 (bearer extraction) and OpenID Connect Core 1.0 §5.3 (claim
// release). The returned handler is safe for concurrent use; deps MUST
// NOT be mutated after the call.
func Handler(deps HandlerDeps) http.Handler {
	// The userinfo Clock and the tokens Clock share a structural shape;
	// a non-nil value satisfies both interfaces directly, and a nil
	// propagates so the verifier falls back to its system clock.
	var verifierClock tokens.Clock
	if deps.Clock != nil {
		verifierClock = deps.Clock
	}
	verifier := &tokens.AccessTokenVerifier{
		Keys:   deps.Keys,
		Issuer: deps.Issuer,
		Clock:  verifierClock,
		Leeway: deps.Leeway,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveUserInfo(w, r, deps, verifier)
	})
}

// serveUserInfo runs one /userinfo request through the dispatch ladder:
// method gate → bearer extraction → opaque-or-JWT branch → claim
// assembly. Pulled out of [Handler] so the cognitive complexity of each
// individual function stays under the lint budget.
func serveUserInfo(w http.ResponseWriter, r *http.Request, deps HandlerDeps, verifier *tokens.AccessTokenVerifier) {
	if !methodAllowed(r.Method) {
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := extractBearer(w, r)
	if err != nil {
		respondBearerExtractError(w, err)
		return
	}
	// Opaque first: a presented bearer that is not JWS-shaped resolves
	// through the opaque substore (ADR 0024). The JWT verifier would
	// always reject a non-JWS shape, so taking the opaque branch ahead
	// of it avoids a spurious "malformed JWT" diagnostic and keeps the
	// WWW-Authenticate challenges aligned with the format the token
	// endpoint actually issued.
	if !looksLikeJWT(raw) && deps.OpaqueAccessTokens != nil {
		serveUserInfoOpaque(w, r, deps, raw)
		return
	}
	serveUserInfoJWT(w, r, deps, verifier, raw)
}

func serveUserInfoJWT(w http.ResponseWriter, r *http.Request, deps HandlerDeps, verifier *tokens.AccessTokenVerifier, raw string) {
	claims, _, err := verifier.Verify(raw)
	if err != nil {
		respondInvalidToken(w, err)
		return
	}
	if !enforceAudience(w, deps.Issuer, claims.Audience) {
		return
	}
	if !enforceCnfBinding(w, r, deps, claims, raw) {
		return
	}
	if !enforceRevocationStatus(r.Context(), w, deps, claims) {
		return
	}
	out, client, ok := assembleClaims(r.Context(), w, deps, claims)
	if !ok {
		return
	}
	dispatchUserInfoResponse(r, w, deps, claims.ClientID, out, client)
}

// dispatchUserInfoResponse picks the response shape based on the
// request's Accept header and the configured client metadata. The
// default OIDC Core 1.0 §5.3.1.1 shape is application/json; the
// JWT-shape (signed-only or signed-then-encrypted) fires when the
// request opts into it via Accept: application/jwt or when the
// AT-bound client registered userinfo_encrypted_response_alg / _enc.
//
// On the JWT-shape path the handler MUST resolve the AT-bound client
// before signing so a deleted client surfaces as invalid_token rather
// than a body the RP cannot route. A nil [HandlerDeps.Clients] (the
// embedder did not wire a client store, e.g. legacy tests) collapses
// onto the JSON shape because there is no metadata to consult.
//
// resolved is the [*store.Client] the pairwise subject projection already
// fetched (see [assembleClaims]); when non-nil it is reused so the client
// store is hit at most once per request. A nil resolved falls back to a
// lazy [resolveClient] here, which is the non-pairwise path where the
// projection did not need the client.
func dispatchUserInfoResponse(
	r *http.Request,
	w http.ResponseWriter,
	deps HandlerDeps,
	clientID string,
	body map[string]any,
	resolved *store.Client,
) {
	wantsJWT := wantsJWTShape(r)
	client, ok := resolved, resolved != nil
	if !ok {
		client, ok = resolveClient(r.Context(), deps, clientID)
	}
	encryptionRegistered := ok && client != nil && client.UserInfoEncryptedResponseAlg != ""
	if !wantsJWT && !encryptionRegistered {
		writeJSON(w, body)
		return
	}
	if !ok {
		// Client was deleted between AT issuance and the JWT-shape
		// userinfo call.
		respondGenericInvalidToken(w)
		return
	}
	// JWT-shape path requires the client metadata. Without it the
	// handler cannot decide whether to wrap the JWS in a JWE; the
	// nil-store / empty-client_id case collapses onto signed-only
	// (maybeEncryptUserInfo will short-circuit on
	// ErrNoEncryptionConfigured).
	writeUserInfoJWT(r.Context(), w, deps, clientID, body)
}

// enforceAudience refuses an access token whose "aud" claim is set but
// does not contain the OP's issuer URL. The check keeps a token minted
// for an external resource server (RFC 8707 §2.1, aud=<resource>) from
// being usable at /userinfo even though it shares the OP's signing key.
//
// An empty Audience is accepted: aud is OPTIONAL on the OP-default
// access token shape (and on legacy / external tokens that the
// embedder may also accept), so an absent claim is the audience-less
// path covered by RI-070.
//
// On rejection the response is the bare RFC 6750 §3.1 invalid_token
// challenge — the description does not name the sub-cause, matching
// the privacy posture every other userinfo failure path takes.
func enforceAudience(w http.ResponseWriter, issuer string, audience []string) bool {
	if issuer == "" || len(audience) == 0 {
		return true
	}
	for _, a := range audience {
		if a == issuer {
			return true
		}
	}
	w.Header().Set("WWW-Authenticate", buildBearerChallenge("invalid_token", "The access token is invalid"))
	w.WriteHeader(http.StatusUnauthorized)
	return false
}

// enforceCnfBinding verifies the sender-constraint proof on the
// request whenever the access token carries a cnf claim (RFC 7800).
// Two binding methods are recognised:
//
//   - "jkt": RFC 9449 DPoP. Requires a "DPoP" header carrying a proof
//     whose JWK thumbprint equals the bound value.
//   - "x5t#S256": RFC 8705 §3. Requires a client cert (TLS handshake
//     or trusted reverse-proxy header) whose DER bytes hash to the
//     bound value.
//
// A token may carry BOTH members; the function then enforces both
// proofs. A token with no cnf claim leaves the request on the
// bearer path. The function emits a 401 with the appropriate
// WWW-Authenticate challenge and returns false on any failure.
func enforceCnfBinding(
	w http.ResponseWriter,
	r *http.Request,
	deps HandlerDeps,
	claims *tokens.AccessTokenClaims,
	rawAccessToken string,
) bool {
	cnf := claims.Confirmation
	if len(cnf) == 0 {
		// Bearer token: nothing to enforce.
		return true
	}
	if jkt := cnf["jkt"]; jkt != "" {
		if !enforceDPoPCnf(w, r, deps, jkt, rawAccessToken) {
			return false
		}
	}
	if x5t := cnf["x5t#S256"]; x5t != "" {
		if !enforceMTLSCnf(w, r, deps, x5t) {
			return false
		}
	}
	return true
}

// enforceDPoPCnf is the DPoP-specific half of [enforceCnfBinding].
// Split out so the two confirmation methods stay readable when both
// are present on the same token.
func enforceDPoPCnf(
	w http.ResponseWriter,
	r *http.Request,
	deps HandlerDeps,
	jkt, rawAccessToken string,
) bool {
	if deps.DPoP == nil {
		respondDPoPInvalid(w, "DPoP verification is not enabled")
		return false
	}
	header := r.Header.Get("DPoP")
	if header == "" {
		respondDPoPInvalid(w, "DPoP proof required")
		return false
	}
	res, err := deps.DPoP.VerifyHTTPRequest(r.Context(), r, rawAccessToken)
	if err != nil {
		if dpop.IsNonceError(err) {
			respondUseDPoPNonce(w, deps)
			return false
		}
		respondDPoPInvalid(w, "DPoP proof rejected")
		return false
	}
	if res.JKT != jkt {
		respondDPoPInvalid(w, "DPoP proof key does not match the bound thumbprint")
		return false
	}
	return true
}

// enforceMTLSCnf is the mTLS-specific half of [enforceCnfBinding]. It
// surfaces the appropriate WWW-Authenticate challenge for missing /
// mismatched client certificates without leaking which sub-class of
// failure produced the rejection.
func enforceMTLSCnf(
	w http.ResponseWriter,
	r *http.Request,
	deps HandlerDeps,
	bound string,
) bool {
	if deps.MTLS == nil {
		respondMTLSInvalid(w, "mTLS verification is not enabled")
		return false
	}
	if err := deps.MTLS.VerifyBoundRequest(r, bound); err != nil {
		respondMTLSInvalid(w, "client certificate does not match the bound thumbprint")
		return false
	}
	return true
}

// respondDPoPInvalid writes the RFC 9449 §7.1 challenge for a token
// that requires DPoP but failed verification. The library uses the
// "invalid_token" code (rather than the spec's "invalid_dpop_proof")
// so RP libraries that key off the OAuth-Bearer challenge taxonomy
// continue to function; the description carries enough detail for
// the operator to triage the failure from logs.
func respondDPoPInvalid(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate", buildDPoPChallenge("invalid_token", description))
	w.WriteHeader(http.StatusUnauthorized)
}

// respondUseDPoPNonce writes the RFC 9449 §9 nonce challenge: a 401
// with WWW-Authenticate: DPoP error="use_dpop_nonce" and a
// "DPoP-Nonce" response header carrying a fresh value the client
// should embed in the next proof's "nonce" claim. A nil
// [HandlerDeps.DPoPNonces] omits the "DPoP-Nonce" header (the issuer
// is offline) but still carries the error code so a debugger can see
// the gate fired; the client then has no nonce to retry with, which
// is the most truthful signal the server can give in that
// misconfiguration.
func respondUseDPoPNonce(w http.ResponseWriter, deps HandlerDeps) {
	if deps.DPoPNonces != nil {
		if nonce := deps.DPoPNonces.IssueNonce(); nonce != "" {
			w.Header().Set("DPoP-Nonce", nonce)
		}
	}
	w.Header().Set("WWW-Authenticate", buildDPoPChallenge("use_dpop_nonce",
		"DPoP proof requires a server-supplied nonce; retry using the value in the DPoP-Nonce response header"))
	w.WriteHeader(http.StatusUnauthorized)
}

// respondMTLSInvalid writes the RFC 8705 §3.2 equivalent challenge for
// a token that requires a client certificate but failed verification.
// The challenge stays on the OAuth-Bearer code "invalid_token" so RP
// libraries that key off the bearer state machine continue to
// function; mTLS does not define a new error code for this case.
func respondMTLSInvalid(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate", buildBearerChallenge("invalid_token", description))
	w.WriteHeader(http.StatusUnauthorized)
}

// methodAllowed reports whether method is one of the two verbs the
// /userinfo endpoint accepts (OIDC Core 1.0 §5.3).
func methodAllowed(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodPost
}

// bearerError discriminates the three RFC 6750 §3 failure shapes the
// handler emits before signature verification: "no credentials" (which
// produces a bare WWW-Authenticate challenge), "invalid request"
// (which produces an error="invalid_request" challenge per §3.1), and
// "request body too large" (which produces a 413 Request Entity Too
// Large with the same invalid_request code so RP libraries that key
// off the bearer state machine still see a recognised challenge).
type bearerError struct {
	missing  bool
	tooLarge bool
	desc     string
}

func (e *bearerError) Error() string { return e.desc }

// extractBearer returns the access token from the request, applying
// RFC 6750 §2 source rules:
//
//   - §2.1 Authorization: Bearer header is the canonical channel.
//   - §2.2 application/x-www-form-urlencoded body is accepted ONLY for
//     POST requests whose Content-Type matches.
//   - §2 forbids combining channels; the handler rejects requests that
//     present both with error="invalid_request".
//   - §2.3 (URI query) is intentionally skipped: RFC 9700 §2.4 calls
//     query-string credentials out as a hardening risk, and the
//     handler MUST NOT consult [http.Request.URL.Query()].
//
// The "no credentials at all" case returns a bearerError with
// missing=true so the caller can emit a bare challenge.
//
// The w argument is hoisted here only so the form-body branch can
// install the [http.MaxBytesReader] cap before invoking ParseForm; the
// header-only path never touches the response writer.
func extractBearer(w http.ResponseWriter, r *http.Request) (string, error) {
	header := bearerFromHeader(r.Header.Get("Authorization"))
	body, bodyPresent, err := bearerFromBody(w, r)
	if err != nil {
		return "", err
	}
	if header != "" && bodyPresent {
		return "", &bearerError{desc: "access token presented in multiple channels"}
	}
	if header != "" {
		return header, nil
	}
	if bodyPresent {
		return body, nil
	}
	return "", &bearerError{missing: true, desc: "missing access token"}
}

// bearerFromHeader extracts the token from the Authorization header,
// case-insensitively matching either the "Bearer" scheme (RFC 6750
// §2.1) or the "DPoP" scheme (RFC 9449 §7.1). The "DPoP" prefix is
// what a client signals when presenting a DPoP-bound access token at
// a protected resource: the value is the same access token, but the
// scheme name tells the resource server that a "DPoP" proof header
// is also present. Returns "" when the header is empty or does not
// carry a recognised credential.
//
// Delegates to [endpointsupport.BearerFromHeader] so the scheme list
// stays in lockstep with the sibling endpoints.
func bearerFromHeader(value string) string {
	tok, _ := endpointsupport.BearerFromHeader(value)
	return tok
}

// bearerFromBody extracts the token from a POST application/x-www-form-
// urlencoded body. The third return value is the parse error (if any);
// the second reports whether an access_token field was observed at all.
//
// The function caps the body via [endpointsupport.LimitFormBody] before
// invoking ParseForm so a multi-megabyte payload is short-circuited at
// read time. RFC 6750 §2.2 has no upper bound on the access_token form
// field, but legitimate OAuth bearer tokens (opaque or JWT) comfortably
// fit in a few KiB; the 64 KiB cap is far above any real-world value
// while bounding memory use against pathological inputs (gosec G120).
func bearerFromBody(w http.ResponseWriter, r *http.Request) (string, bool, error) {
	if r.Method != http.MethodPost {
		return "", false, nil
	}
	if !isFormContent(r.Header.Get("Content-Type")) {
		return "", false, nil
	}
	endpointsupport.LimitFormBody(w, r)
	// G120 false positive: LimitFormBody wraps r.Body in
	// http.MaxBytesReader on the line above so ParseForm reads from a
	// bounded reader. The MaxBytesError surfaces below so callers map
	// it to invalid_request / 413.
	if err := r.ParseForm(); err != nil { //nolint:gosec // body bounded by LimitFormBody above
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return "", false, &bearerError{tooLarge: true, desc: "request body exceeds the userinfo endpoint size limit"}
		}
		return "", false, &bearerError{desc: "malformed form body"}
	}
	values, ok := r.PostForm["access_token"]
	if !ok {
		return "", false, nil
	}
	if len(values) > 1 {
		return "", true, &bearerError{desc: "access_token specified multiple times"}
	}
	return values[0], true, nil
}

// isFormContent reports whether ct is an application/x-www-form-
// urlencoded media type. Parameters (charset, boundary) are tolerated.
// Delegates to [endpointsupport.IsFormContent] so the contract stays
// uniform across the form-accepting endpoints.
func isFormContent(ct string) bool {
	return endpointsupport.IsFormContent(ct)
}

// respondBearerExtractError writes the 401/400/413 response that
// matches the failure mode of [extractBearer]: "missing" -> bare
// challenge, "tooLarge" -> 413 with invalid_request, "multiple
// channels / malformed" -> 400 invalid_request.
func respondBearerExtractError(w http.ResponseWriter, err error) {
	var be *bearerError
	if errors.As(err, &be) {
		switch {
		case be.missing:
			w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		case be.tooLarge:
			w.Header().Set("WWW-Authenticate", buildBearerChallenge("invalid_request",
				"The request body exceeds the maximum allowed size"))
			http.Error(w, "", http.StatusRequestEntityTooLarge)
			return
		}
	}
	w.Header().Set("WWW-Authenticate", buildBearerChallenge("invalid_request",
		"The request is missing a required parameter or is malformed"))
	http.Error(w, "", http.StatusBadRequest)
}

// buildBearerChallenge composes the WWW-Authenticate value for an
// RFC 6750 §3.1 invalid_request / invalid_token challenge,
// running the description through [endpointsupport.SanitizeChallengeValue]
// so a CR/LF/quote/backslash byte cannot inject a header break or
// terminate the auth-param prematurely. See [endpointsupport.SanitizeChallengeValue]
// for the exact byte allow-list.
func buildBearerChallenge(code, description string) string {
	return endpointsupport.BuildBearerChallenge(endpointsupport.BearerSchemeBearer,
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeError, Value: code},
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeErrorDescription, Value: description},
	)
}

// buildDPoPChallenge is the DPoP-scheme counterpart of [buildBearerChallenge]
// for RFC 9449 §7.1 / §9 challenges. The description flows through the
// same [endpointsupport.SanitizeChallengeValue] gate so the two challenge
// shapes share their CR/LF/quote/backslash defenses.
func buildDPoPChallenge(code, description string) string {
	return endpointsupport.BuildBearerChallenge(endpointsupport.BearerSchemeDPoP,
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeError, Value: code},
		endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeErrorDescription, Value: description},
	)
}

// enforceRevocationStatus rejects the request when the access token has
// been revoked. The actual lookup shape depends on
// [HandlerDeps.RevocationStrategy] (ADR 0025):
//
//   - [store.RevocationStrategyGrantTombstone] (default): consult
//     [store.GrantRevocationStore.IsRevoked] keyed by the AT's "gid"
//     private claim. Legacy ATs without "gid" fall back to the
//     [store.AccessTokenRegistry] when one is configured (ADR 0025
//     §Migration); embedders that wired neither substore opt out
//     entirely.
//   - [store.RevocationStrategyJTIRegistry]: consult the registry by
//     JTI; the marked-revoked row collapses onto invalid_token. This
//     is the ADR 0013 behaviour preserved for embedders pinning the
//     legacy strategy.
//   - [store.RevocationStrategyNone]: no check; the JWT lives until
//     exp.
//
// Lookup errors are fatal on every path: silently allowing the request
// would re-introduce the cascade gap that the revocation registry
// closes.
func enforceRevocationStatus(
	ctx context.Context,
	w http.ResponseWriter,
	deps HandlerDeps,
	claims *tokens.AccessTokenClaims,
) bool {
	revoked, ok := endpointsupport.JWTAccessTokenRevoked(ctx, endpointsupport.JWTRevocationOpts{
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		RevocationStrategy: deps.RevocationStrategy,
	}, claims)
	if !ok {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return false
	}
	if revoked {
		w.Header().Set("WWW-Authenticate", buildBearerChallenge("invalid_token", "The access token has been revoked"))
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

// respondInvalidToken writes a 401 response with the error="invalid_token"
// challenge mandated by RFC 6750 §3.1. The description distinguishes
// the expired case (so RPs can decide whether to refresh) but does NOT
// leak which sub-class of signature / parse failure produced any other
// rejection.
func respondInvalidToken(w http.ResponseWriter, err error) {
	desc := invalidTokenDescription
	if errors.Is(err, tokens.ErrAccessTokenExpired) {
		desc = "The access token expired"
	}
	w.Header().Set("WWW-Authenticate", buildBearerChallenge("invalid_token", desc))
	w.WriteHeader(http.StatusUnauthorized)
}

const invalidTokenDescription = "The access token is invalid"

func respondGenericInvalidToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", buildBearerChallenge("invalid_token", invalidTokenDescription))
	w.WriteHeader(http.StatusUnauthorized)
}

// assembleClaims looks the subject up in the user store, projects the
// granted scopes onto the claim universe, and returns the response
// body. The bool reports success; on false the handler has already
// written the response and the caller MUST return.
//
// When the access token's "sub" carries the per-client pairwise value
// (RFC 9068 §3 / OIDC Core §8.1 — minted that way so RS-visible and
// id_token "sub" agree), the raw OP-internal subject is recovered by
// pivoting through the access token's "gid" private claim to the owning
// grant. UserStore lookup and the OIDC Core §5.5 claims-request resolution
// both key on the raw value; the response "sub" is then re-projected so
// the client observes the pairwise value end-to-end. The opaque-format
// path leaves "gid" empty and stamps the raw subject on the claims it
// hands here, so the pivot is a no-op on that branch.
// The returned [*store.Client] is the AT-bound client resolved by the
// pairwise subject projection, or nil when no projector is configured (the
// non-pairwise path resolves the client lazily in
// [dispatchUserInfoResponse]). Threading it out lets the caller reuse a
// single [store.ClientStore.GetClient] per request in the pairwise config.
func assembleClaims(
	ctx context.Context,
	w http.ResponseWriter,
	deps HandlerDeps,
	claims *tokens.AccessTokenClaims,
) (map[string]any, *store.Client, bool) {
	rawSubject, ok := resolveRawSubject(ctx, w, deps, claims)
	if !ok {
		return nil, nil, false
	}
	user, err := deps.UserStore.FindBySubject(ctx, rawSubject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			respondGenericInvalidToken(w)
			return nil, nil, false
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return nil, nil, false
	}
	source := userClaims(user)
	publicSubject, client, ok := projectResponseSubject(ctx, w, deps, rawSubject, claims.ClientID)
	if !ok {
		return nil, nil, false
	}
	out, err := Build(Input{
		Subject:           publicSubject,
		Scopes:            claims.Scope,
		Source:            source,
		CustomScopeClaims: deps.CustomScopeClaims,
		Claims:            lookupClaimsRequest(ctx, deps, rawSubject, claims.ClientID),
	})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return nil, nil, false
	}
	return out, client, true
}

// resolveRawSubject returns the OP-internal stable subject identifier
// for the presented access token. JWT tokens minted under a configured
// SubjectProjector carry the per-client pairwise value in "sub" and the
// stable identifier on the originating grant; the function recovers the
// raw value by looking the grant up through the "gid" private claim
// (RFC 7519 §4.3) the token endpoint stamps on every JWT it issues. The
// opaque-format path (and legacy JWT tokens minted before pairwise was
// configured) carries the raw subject in "sub" directly and the GrantID
// is empty; the function returns the claim verbatim on that branch.
//
// A missing or unrecoverable grant collapses onto invalid_token rather
// than silently falling back to the pairwise value: the grant being
// gone means the consent the token descends from has been revoked, and
// continuing to serve userinfo would defeat that.
func resolveRawSubject(
	ctx context.Context,
	w http.ResponseWriter,
	deps HandlerDeps,
	claims *tokens.AccessTokenClaims,
) (string, bool) {
	// When no SubjectProjector is configured the JWT "sub" claim is
	// already the OP-internal value (mintAccessToken stamps raw ==
	// public on that branch), so the grant pivot would be a no-op DB
	// hit. Short-circuit to keep the non-pairwise hot path free of the
	// extra lookup.
	if deps.SubjectProjector == nil {
		return claims.Subject, true
	}
	if claims.GrantID == "" || deps.Grants == nil {
		respondGenericInvalidToken(w)
		return "", false
	}
	g, err := deps.Grants.Find(ctx, claims.GrantID)
	if err != nil || g == nil {
		respondGenericInvalidToken(w)
		return "", false
	}
	if g.Subject == "" {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return "", false
	}
	return g.Subject, true
}

// projectResponseSubject converts the raw OP-internal subject into the
// per-client public "sub" value. When a [HandlerDeps.SubjectProjector] is
// configured it resolves the AT-bound client and returns it alongside the
// projected subject so the caller can thread the same [*store.Client] into
// the response-shape dispatch without a second [store.ClientStore.GetClient]
// round-trip. The non-pairwise path (nil projector) returns a nil client
// and the caller resolves lazily where it is actually needed.
func projectResponseSubject(
	ctx context.Context,
	w http.ResponseWriter,
	deps HandlerDeps,
	rawSubject, clientID string,
) (string, *store.Client, bool) {
	if deps.SubjectProjector == nil {
		return rawSubject, nil, true
	}
	client, ok := resolveClient(ctx, deps, clientID)
	if !ok {
		respondGenericInvalidToken(w)
		return "", nil, false
	}
	projected, err := deps.SubjectProjector(ctx, rawSubject, client)
	if err != nil || projected == "" {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return "", nil, false
	}
	return projected, client, true
}

// lookupClaimsRequest resolves the OIDC Core 1.0 §5.5 "claims" payload
// that was persisted on the grant from which claims.Subject /
// claims.ClientID's access token descends. Returns nil when:
//
//   - the deps.Grants substore is not wired (embedders that have not
//     yet adopted the per-claim projection),
//   - the lookup fails (the grant was revoked between issuance and the
//     userinfo call),
//   - the grant carries no §5.5 payload (every claim was scope-driven).
//
// The resolution path uses [store.GrantStore.FindBySubjectClient] which
// returns the active grant for the (subject, client) pair. Multiple
// historical grants are not exercised by the v0.x library; the path
// will continue to read the latest active grant, which matches the
// expectation that consent only ever broadens, not narrows, between
// issuances of the same chain.
func lookupClaimsRequest(
	ctx context.Context,
	deps HandlerDeps,
	subject, clientID string,
) *authorize.ClaimsRequest {
	if deps.Grants == nil || subject == "" || clientID == "" {
		return nil
	}
	g, err := deps.Grants.FindBySubjectClient(ctx, subject, clientID)
	if err != nil || g == nil {
		return nil
	}
	return authorize.DecodeClaimsFromGrant(g.Claims)
}

// userClaims returns the claim source map for u, defending against a
// nil user (which the substore should never return alongside a nil
// error, but library code is small enough to be paranoid).
//
// When [store.User.UpdatedAt] is non-zero and the embedder did not
// already populate "updated_at" in [store.User.Claims], the timestamp
// is projected as Unix-seconds so the "profile" scope's allow-list
// can release it. The merge happens in a fresh map so the embedder's
// backing store stays untouched (the contract says Claims is treated
// read-only).
func userClaims(u *store.User) map[string]any {
	if u == nil {
		return nil
	}
	if u.UpdatedAt.IsZero() {
		return u.Claims
	}
	if _, has := u.Claims["updated_at"]; has {
		return u.Claims
	}
	out := make(map[string]any, len(u.Claims)+1)
	for k, v := range u.Claims {
		out[k] = v
	}
	out["updated_at"] = u.UpdatedAt.Unix()
	return out
}

// writeJSON encodes body with json.Marshal, stamps the cache and
// content-type headers OIDC Core 1.0 §5.3.1.1 / RFC 6749 §5.1 mandate,
// and writes the response. Marshal failures fall back to a 500 with no
// body so a malformed Source map cannot leak claim names through an
// error string.
//
// The cache-control posture pairs the modern "no-store" directive with
// "Pragma: no-cache" for HTTP/1.0 intermediaries that still ignore
// Cache-Control (RFC 6749 §5.1 calls both out as MUST). The "private"
// modifier on Cache-Control is preserved for downstream caches that
// honour the OIDC Core hint while still seeing the no-store gate.
func writeJSON(w http.ResponseWriter, body map[string]any) {
	payload, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
	_, _ = w.Write(payload)
}
