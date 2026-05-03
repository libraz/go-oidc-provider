package userinfo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// serveUserInfoOpaque implements the ADR 0024 opaque-format /userinfo
// branch. The bearer is hashed inside [resolveOpaqueAccessTokenAt],
// which also runs the revoked / expired / cnf-mismatch checks; this
// wrapper hands the projected claims to [assembleClaims] verbatim so
// the JWT and opaque paths share their tail half.
func serveUserInfoOpaque(w http.ResponseWriter, r *http.Request, deps HandlerDeps, raw string) {
	claims, ok := resolveOpaqueAccessTokenAt(r.Context(), w, r, deps, raw)
	if !ok {
		return
	}
	out, ok := assembleClaims(r.Context(), w, deps, claims)
	if !ok {
		return
	}
	writeJSON(w, out)
}

// resolveOpaqueAccessTokenAt handles the ADR 0024 opaque-format path
// at /userinfo. The substore lookup is hashed inside the
// implementation; this function applies the revoked / expired /
// cnf-mismatch checks and projects a successful record onto an
// [*tokens.AccessTokenClaims] so the caller can reuse [assembleClaims]
// verbatim.
//
// Every failure path emits the appropriate WWW-Authenticate challenge
// and returns ok=false so the caller stops without writing an
// additional response. The function never returns a nil claims with
// ok=true.
func resolveOpaqueAccessTokenAt(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps HandlerDeps,
	raw string,
) (*tokens.AccessTokenClaims, bool) {
	rec, err := deps.OpaqueAccessTokens.Find(ctx, raw)
	if err != nil || rec == nil {
		// ErrNotFound and any other store error surface as
		// invalid_token. RFC 6750 §3.1 forbids leaking which
		// sub-class produced the rejection.
		respondOpaqueInvalid(w, "The access token is invalid")
		return nil, false
	}
	if rec.Revoked {
		respondOpaqueInvalid(w, "The access token has been revoked")
		return nil, false
	}
	now := userInfoNow(deps).UTC()
	if !rec.ExpiresAt.After(now) {
		respondOpaqueInvalid(w, "The access token has expired")
		return nil, false
	}
	if !enforceAudience(w, deps.Issuer, opaqueAudience(rec)) {
		return nil, false
	}
	if !enforceOpaqueCnf(w, r, deps, rec, raw) {
		return nil, false
	}
	return projectOpaqueAccessTokenClaims(rec), true
}

// opaqueAudience normalises the opaque-access-token record's audience
// onto the []string shape [enforceAudience] consumes. The
// [store.OpaqueAccessToken.Audience] field is a single string per the
// substore schema, so the projection wraps it into a one-element slice
// (or returns nil when the record has no audience pinned).
func opaqueAudience(rec *store.OpaqueAccessToken) []string {
	if rec.Audience == "" {
		return nil
	}
	return []string{rec.Audience}
}

// userInfoNow returns the wall-clock reading the userinfo handler
// uses for opaque-token expiry comparisons. The function honours the
// optional [HandlerDeps.Clock] (also threaded into the JWT verifier)
// and falls back to [internal/timex.SystemClock] when the field is
// nil; the reference matches the boundary discipline of the sibling
// endpoints (no direct [time.Now] call).
func userInfoNow(deps HandlerDeps) time.Time {
	if deps.Clock != nil {
		return deps.Clock.Now()
	}
	return timex.SystemClock.Now()
}

// enforceOpaqueCnf re-verifies the sender-constraint proof on the
// request when the opaque-access-token record was issued with a cnf
// thumbprint. Mirrors [enforceCnfBinding] so the wire response stays
// uniform between the JWT and opaque paths; the difference is that
// the bound thumbprint comes from the persistent record rather than
// from a JWT claim. The raw bearer value is threaded in by the caller
// because the request's body has already been consumed by the
// initial [extractBearer]: re-extracting would surface a "malformed
// form body" on POST requests.
func enforceOpaqueCnf(
	w http.ResponseWriter,
	r *http.Request,
	deps HandlerDeps,
	rec *store.OpaqueAccessToken,
	raw string,
) bool {
	if rec.DPoPJKT != "" {
		if !enforceDPoPCnf(w, r, deps, rec.DPoPJKT, raw) {
			return false
		}
	}
	if rec.MTLSCertThumbprint != "" {
		if !enforceMTLSCnf(w, r, deps, rec.MTLSCertThumbprint) {
			return false
		}
	}
	return true
}

// projectOpaqueAccessTokenClaims projects an opaque-access-token
// record onto the [*tokens.AccessTokenClaims] shape the rest of the
// /userinfo pipeline consumes. Only the fields downstream code reads
// (Subject, ClientID, Scope) are populated; cnf / JTI are intentionally
// omitted because the opaque path has already enforced them and the
// revocation registry keys on JTI which has no counterpart for the
// opaque format.
func projectOpaqueAccessTokenClaims(rec *store.OpaqueAccessToken) *tokens.AccessTokenClaims {
	return &tokens.AccessTokenClaims{
		Subject:  rec.Subject,
		ClientID: rec.ClientID,
		Scope:    append([]string(nil), rec.Scope...),
	}
}

// respondOpaqueInvalid writes the RFC 6750 §3.1 invalid_token
// challenge for the opaque-format path. The description distinguishes
// the revoked / expired / generic cases for the operator's logs but
// stays out of any claim values so a curious client cannot probe the
// substore through error strings.
//
// The challenge value is composed via [buildBearerChallenge] so any
// CR / LF / quote / backslash byte in the description (defensive
// guard; no current call site supplies attacker-controlled input) is
// scrubbed before it lands in the response header.
func respondOpaqueInvalid(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate", buildBearerChallenge("invalid_token", description))
	w.WriteHeader(http.StatusUnauthorized)
}

// looksLikeJWT reports whether token has the structural shape of a
// compact-serialised JWS: three base64url segments separated by dots,
// with the header decoding to a JSON object. The check is deliberately
// shallow — full parsing happens inside [tokens.AccessTokenVerifier] —
// because the only purpose of this dispatcher is to pick which branch
// to take. Mirrors the helper in the sibling endpoints
// (introspectendpoint / revokeendpoint) so the JWT-shape probe stays
// uniform across the protocol surfaces.
//
// A token whose header is not valid base64url-encoded JSON is treated
// as opaque so a malformed JWT cannot bypass the opaque lookup; the
// JWT branch would reject it anyway, but the conservative choice
// keeps the dispatcher simple to reason about.
func looksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}
	return len(header) > 0
}
