package userinfo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
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

	// UserStore is the read-only end-user lookup the handler consults
	// after the bearer token has verified. It MUST return
	// [store.ErrNotFound] when the subject does not exist.
	UserStore store.UserStore

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
		if !methodAllowed(r.Method) {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		raw, err := extractBearer(r)
		if err != nil {
			respondBearerExtractError(w, err)
			return
		}
		claims, _, err := verifier.Verify(raw)
		if err != nil {
			respondInvalidToken(w, err)
			return
		}
		if !enforceCnfBinding(w, r, deps, claims, raw) {
			return
		}
		out, ok := assembleClaims(r.Context(), w, deps, claims)
		if !ok {
			return
		}
		writeJSON(w, out)
	})
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
	w.Header().Set("WWW-Authenticate",
		`DPoP error="invalid_token", error_description="`+description+`"`)
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
	w.Header().Set("WWW-Authenticate",
		`DPoP error="use_dpop_nonce", error_description="DPoP proof requires a server-supplied nonce; retry using the value in the DPoP-Nonce response header"`)
	w.WriteHeader(http.StatusUnauthorized)
}

// respondMTLSInvalid writes the RFC 8705 §3.2 equivalent challenge for
// a token that requires a client certificate but failed verification.
// The challenge stays on the OAuth-Bearer code "invalid_token" so RP
// libraries that key off the bearer state machine continue to
// function; mTLS does not define a new error code for this case.
func respondMTLSInvalid(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate",
		`Bearer error="invalid_token", error_description="`+description+`"`)
	w.WriteHeader(http.StatusUnauthorized)
}

// methodAllowed reports whether method is one of the two verbs the
// /userinfo endpoint accepts (OIDC Core 1.0 §5.3).
func methodAllowed(method string) bool {
	return method == http.MethodGet || method == http.MethodPost
}

// bearerError discriminates the two RFC 6750 §3 failure shapes the
// handler emits before signature verification: "no credentials" (which
// produces a bare WWW-Authenticate challenge) and "invalid request"
// (which produces an error="invalid_request" challenge per §3.1).
type bearerError struct {
	missing bool
	desc    string
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
//     handler MUST NOT consult [http.Request.URL.Query].
//
// The "no credentials at all" case returns a bearerError with
// missing=true so the caller can emit a bare challenge.
func extractBearer(r *http.Request) (string, error) {
	header := bearerFromHeader(r.Header.Get("Authorization"))
	body, bodyPresent, err := bearerFromBody(r)
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
// case-insensitively matching "Bearer" per RFC 6750 §2.1. Returns "" when
// the header is empty or does not carry a Bearer credential.
func bearerFromHeader(value string) string {
	const prefix = "Bearer "
	if len(value) <= len(prefix) {
		return ""
	}
	if !strings.EqualFold(value[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(value[len(prefix):])
}

// bearerFromBody extracts the token from a POST application/x-www-form-
// urlencoded body. The third return value is the parse error (if any);
// the second reports whether an access_token field was observed at all.
func bearerFromBody(r *http.Request) (string, bool, error) {
	if r.Method != http.MethodPost {
		return "", false, nil
	}
	if !isFormContent(r.Header.Get("Content-Type")) {
		return "", false, nil
	}
	if err := r.ParseForm(); err != nil {
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
func isFormContent(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded")
}

// respondBearerExtractError writes the 401/400 response that matches
// the failure mode of [extractBearer]: "missing" -> bare challenge,
// "multiple channels / malformed" -> 400 invalid_request.
func respondBearerExtractError(w http.ResponseWriter, err error) {
	var be *bearerError
	if errors.As(err, &be) && be.missing {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("WWW-Authenticate",
		`Bearer error="invalid_request", error_description="The request is missing a required parameter or is malformed"`)
	http.Error(w, "", http.StatusBadRequest)
}

// respondInvalidToken writes a 401 response with the error="invalid_token"
// challenge mandated by RFC 6750 §3.1. The description distinguishes
// the expired case (so RPs can decide whether to refresh) but does NOT
// leak which sub-class of signature / parse failure produced any other
// rejection.
func respondInvalidToken(w http.ResponseWriter, err error) {
	desc := "The access token is invalid"
	if errors.Is(err, tokens.ErrAccessTokenExpired) {
		desc = "The access token expired"
	}
	w.Header().Set("WWW-Authenticate",
		`Bearer error="invalid_token", error_description="`+desc+`"`)
	w.WriteHeader(http.StatusUnauthorized)
}

// assembleClaims looks the subject up in the user store, projects the
// granted scopes onto the claim universe, and returns the response
// body. The bool reports success; on false the handler has already
// written the response and the caller MUST return.
func assembleClaims(
	ctx context.Context,
	w http.ResponseWriter,
	deps HandlerDeps,
	claims *tokens.AccessTokenClaims,
) (map[string]any, bool) {
	user, err := deps.UserStore.FindBySubject(ctx, claims.Subject)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.Header().Set("WWW-Authenticate",
				`Bearer error="invalid_token", error_description="subject unknown"`)
			w.WriteHeader(http.StatusUnauthorized)
			return nil, false
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return nil, false
	}
	source := userClaims(user)
	out, err := Build(Input{
		Subject:           claims.Subject,
		Scopes:            claims.Scope,
		Source:            source,
		CustomScopeClaims: deps.CustomScopeClaims,
	})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return nil, false
	}
	return out, true
}

// userClaims returns the claim source map for u, defending against a
// nil user (which the substore should never return alongside a nil
// error, but library code is small enough to be paranoid).
func userClaims(u *store.User) map[string]any {
	if u == nil {
		return nil
	}
	return u.Claims
}

// writeJSON encodes body with json.Marshal, stamps the cache and
// content-type headers OIDC Core 1.0 §5.3.1.1 hints at, and writes
// the response. Marshal failures fall back to a 500 with no body so a
// malformed Source map cannot leak claim names through an error string.
func writeJSON(w http.ResponseWriter, body map[string]any) {
	payload, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, private")
	_, _ = w.Write(payload)
}
