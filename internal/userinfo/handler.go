package userinfo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
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
		out, ok := assembleClaims(r.Context(), w, deps, claims)
		if !ok {
			return
		}
		writeJSON(w, out)
	})
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
