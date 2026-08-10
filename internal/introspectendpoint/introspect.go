package introspectendpoint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// response is the wire shape of an introspection response. RFC 7662 §2.2
// lists every member with omitempty semantics: an inactive response
// carries only "active": false, while an active response includes
// whichever members the OP can populate. The struct uses omitempty on
// every optional field so a single shape services both cases.
//
// "username" is intentionally absent: v1.0 does not surface user-facing
// names by default (privacy posture; embedders who want it wrap the
// handler). "token_type" is set unconditionally on active responses to
// the constant [tokenTypeBearer] — DPoP / mTLS bindings surface through
// "cnf" rather than the type tag (RFC 9449 §6 / RFC 8705 §3 do not
// rename the type).
type response struct {
	Active    bool              `json:"active"`
	Scope     string            `json:"scope,omitempty"`
	ClientID  string            `json:"client_id,omitempty"`
	TokenType string            `json:"token_type,omitempty"`
	Exp       int64             `json:"exp,omitempty"`
	Iat       int64             `json:"iat,omitempty"`
	Nbf       int64             `json:"nbf,omitempty"`
	Sub       string            `json:"sub,omitempty"`
	Aud       []string          `json:"aud,omitempty"`
	Iss       string            `json:"iss,omitempty"`
	JTI       string            `json:"jti,omitempty"`
	Cnf       map[string]string `json:"cnf,omitempty"`
	AuthTime  int64             `json:"auth_time,omitempty"`
	ACR       string            `json:"acr,omitempty"`
	AMR       []string          `json:"amr,omitempty"`

	// AuthorizationDetails echoes the RFC 9396 authorization_details the
	// token's grant was issued with (RFC 9396 §9). Populated for tokens
	// that descend from a grant carrying details; nil otherwise.
	AuthorizationDetails []map[string]any `json:"authorization_details,omitempty"`
}

// mayIntrospectForResource reports whether the authenticated client is
// registered as an introspection client for at least one of the
// resources the token is addressed to.
//
// This is what makes RFC 7662's canonical deployment possible — a
// resource server introspecting the tokens its callers present, which
// were issued to those callers and not to it. The permission is scoped
// to the audience deliberately: a listed client can read only tokens
// meant for the resource it speaks for, so registering an API gateway
// never turns into blanket visibility over every client's tokens.
//
// A nil [Deps.IntrospectionDelegates] answers false for everything,
// which is the same-client-only posture a deployment gets by not
// naming any introspection client.
func (d Deps) mayIntrospectForResource(authenticatedClientID string, audience []string) bool {
	if len(d.IntrospectionDelegates) == 0 || authenticatedClientID == "" {
		return false
	}
	allowed := d.IntrospectionDelegates[authenticatedClientID]
	if len(allowed) == 0 {
		return false
	}
	for _, aud := range audience {
		if _, ok := allowed[aud]; ok {
			return true
		}
	}
	return false
}

// audienceList lifts an opaque record's single-valued Audience onto the
// slice shape [Deps.mayIntrospectForResource] takes, so the two token
// formats are compared against the delegation map identically. An empty
// audience yields a nil slice and therefore never matches.
func audienceList(audience string) []string {
	if audience == "" {
		return nil
	}
	return []string{audience}
}

// inactive is the canonical "active": false response. RFC 7662 §2.2
// requires that an inactive response carry ONLY the "active" member;
// the helper makes the rule explicit at every call site.
func inactive() response { return response{Active: false} }

// resolveToken dispatches to the JWT or opaque branch based on the
// token's structural shape and the supplied hint. The function never
// surfaces an error: every failure path collapses onto [inactive] so
// the caller can write a uniform 200 response per RFC 7662 §2.2.
//
// The hint dictates which branch tries first; both branches still run
// on miss because RFC 7662 §2.1 says the server MUST extend its search
// across all supported token types when the hint does not locate a
// record.
func resolveToken(
	ctx context.Context,
	deps Deps,
	verifier *tokens.AccessTokenVerifier,
	authenticatedClientID, token, hint string,
) response {
	// The JWT branch only makes sense when the token actually looks
	// like a JWS; a non-JWT-shaped token would always miss there, so
	// short-circuit to opaque immediately to avoid pointless verifier
	// work (and the spurious "malformed JWT" log entries it would
	// emit).
	jwtShaped := looksLikeJWT(token)
	for _, branch := range branchOrder(hint, jwtShaped) {
		if got, ok := branch(ctx, deps, verifier, authenticatedClientID, token); ok {
			return got
		}
	}
	return inactive()
}

// branchFn is the resolver shape shared by [resolveJWT] / [resolveOpaque].
// Returning the canonical [resolveToken] signature lets [branchOrder]
// emit a slice the dispatcher can iterate without a per-hint switch
// inside [resolveToken] itself.
type branchFn func(
	ctx context.Context,
	deps Deps,
	verifier *tokens.AccessTokenVerifier,
	authenticatedClientID, token string,
) (response, bool)

// branchOrder returns the resolver branches to try, in the order
// dictated by token_type_hint and the JWT-shape probe. An unrecognised
// or absent hint prefers JWT first when the shape matches, then opaque,
// per the RFC 7662 §2.1 fallthrough rule.
func branchOrder(hint string, jwtShaped bool) []branchFn {
	jwt := func() branchFn {
		if !jwtShaped {
			return nil
		}
		return resolveJWT
	}
	opq := func() branchFn {
		return func(ctx context.Context, deps Deps, _ *tokens.AccessTokenVerifier, c, t string) (response, bool) {
			return resolveOpaque(ctx, deps, c, t)
		}
	}
	switch hint {
	case hintRefreshToken:
		return appendNonNil(opq(), jwt())
	case hintAccessToken, "":
		return appendNonNil(jwt(), opq())
	default:
		return appendNonNil(jwt(), opq())
	}
}

// appendNonNil returns a slice containing only the non-nil branches. A
// nil entry means the JWT branch is disabled because the token does not
// look like a JWS; collapsing it out keeps [resolveToken]'s loop free
// of per-iteration nilness checks.
func appendNonNil(branches ...branchFn) []branchFn {
	out := make([]branchFn, 0, len(branches))
	for _, b := range branches {
		if b != nil {
			out = append(out, b)
		}
	}
	return out
}

// resolveJWT verifies token as a JWT-formatted access token and
// projects its claims onto the introspection response. The bool return
// reports success: false means the verifier rejected the token (or
// same-client-only failed) and the caller MUST fall through.
func resolveJWT(ctx context.Context, deps Deps, verifier *tokens.AccessTokenVerifier, authenticatedClientID, token string) (response, bool) {
	claims, _, err := verifier.Verify(ctx, token)
	if err != nil {
		return response{}, false
	}
	if claims.ClientID != authenticatedClientID &&
		!deps.mayIntrospectForResource(authenticatedClientID, claims.Audience) {
		// Same-client-only unless the caller is a registered
		// introspection client for a resource this token is addressed
		// to. RFC 7662 §2.2 leaves cross-client introspection to the
		// OP's discretion; the default stays the most conservative
		// reading and returns inactive without leaking why.
		return response{}, false
	}
	if revoked, ok := isJWTAccessTokenRevoked(ctx, deps, claims); !ok || revoked {
		return response{}, false
	}
	return projectAccessTokenClaims(claims), true
}

// isJWTAccessTokenRevoked dispatches the revoked-state check by
// [Deps.RevocationStrategy]. The bool return is `revoked`; the second
// bool reports whether the lookup succeeded. A failed lookup ((false,
// false)) collapses onto {"active": false} per RFC 7662 §2.2 — the
// introspection endpoint never exposes a 5xx for a credential check.
func isJWTAccessTokenRevoked(
	ctx context.Context,
	deps Deps,
	claims *tokens.AccessTokenClaims,
) (revoked, ok bool) {
	return endpointsupport.JWTAccessTokenRevoked(ctx, endpointsupport.JWTRevocationOpts{
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		Clients:            deps.Clients,
		RevocationStrategy: deps.RevocationStrategy,
	}, claims)
}

// projectAccessTokenClaims builds an active introspection response
// from a verified [tokens.AccessTokenClaims]. Only fields the JWT
// actually carries are populated; absent claims stay zero-valued and
// are dropped by omitempty on the wire.
func projectAccessTokenClaims(c *tokens.AccessTokenClaims) response {
	out := response{
		Active:    true,
		ClientID:  c.ClientID,
		TokenType: tokenTypeBearer,
		Exp:       c.ExpiresAt,
		Iat:       c.IssuedAt,
		Sub:       c.Subject,
		Iss:       c.Issuer,
		JTI:       c.JTI,
		AuthTime:  c.AuthTime,
		ACR:       c.ACR,
	}
	if len(c.Scope) > 0 {
		out.Scope = strings.Join(c.Scope, " ")
	}
	if len(c.Audience) > 0 {
		out.Aud = append([]string(nil), c.Audience...)
	}
	if len(c.AMR) > 0 {
		out.AMR = append([]string(nil), c.AMR...)
	}
	if len(c.Confirmation) > 0 {
		out.Cnf = cloneStringMap(c.Confirmation)
	}
	if len(c.AuthorizationDetails) > 0 {
		out.AuthorizationDetails = c.AuthorizationDetails
	}
	return out
}

// resolveOpaque looks token up as either an opaque access token or a
// refresh token in the configured stores and projects a live record
// onto the introspection response. The bool return reports success;
// false means neither store had a live record (not found, revoked /
// consumed, expired, cross-client, or store fault) and the caller
// MUST fall through.
//
// The opaque-access-token substore is consulted first. The two stores
// have disjoint id spaces (opaque ATs descend from a [Grant] minted at
// /token, refresh tokens are rotated via /token); a presented bearer
// resolves to at most one of them in practice, but the AT-first order
// keeps the wire response lined up with the format the token endpoint
// most recently issued.
//
// A nil substore disables the corresponding branch. With both nil the
// opaque path short-circuits and the caller's final inactive() fallback
// takes over.
func resolveOpaque(ctx context.Context, deps Deps, authenticatedClientID, token string) (response, bool) {
	if deps.OpaqueAccessTokens != nil {
		if got, ok := resolveOpaqueAccessToken(ctx, deps, authenticatedClientID, token); ok {
			return got, true
		}
	}
	if deps.RefreshTokens == nil {
		return response{}, false
	}
	rec, err := deps.RefreshTokens.Find(ctx, token)
	if err != nil {
		// ErrNotFound and any other store error collapse onto
		// inactive: RFC 7662 §2.2 forbids leaking which sub-class
		// produced the rejection.
		return response{}, false
	}
	if rec == nil {
		return response{}, false
	}
	if rec.ConsumedAt != nil {
		return response{}, false
	}
	now := deps.now().UTC()
	if !rec.ExpiresAt.After(now) {
		return response{}, false
	}
	if rec.ClientID != authenticatedClientID {
		// Same-client-only: a refresh token issued to another client
		// is inactive from this client's point of view.
		return response{}, false
	}
	publicSubject, ok := projectIntrospectionSubject(ctx, deps, rec.Subject, rec.ClientID)
	if !ok {
		return response{}, false
	}
	out := projectRefreshToken(rec, publicSubject, deps.Issuer)
	out.AuthorizationDetails = grantAuthorizationDetails(ctx, deps, rec.GrantID)
	return out, true
}

// resolveOpaqueAccessToken looks token up in the opaque-access-token
// substore and projects a live record onto the introspection
// response. The bool return reports success; false means the lookup
// missed, the record was revoked / expired, or another client owns
// it, and the caller MUST fall through to the refresh-token branch.
//
// Every miss path returns the zero response so the caller cannot
// observe which sub-class produced the rejection — RFC 7662 §2.2
// requires the wire shape for "inactive" to be uniform regardless of
// the underlying cause.
func resolveOpaqueAccessToken(ctx context.Context, deps Deps, authenticatedClientID, token string) (response, bool) {
	rec, err := deps.OpaqueAccessTokens.Find(ctx, token)
	if err != nil {
		// ErrNotFound and any other store error collapse onto inactive.
		return response{}, false
	}
	if rec == nil {
		return response{}, false
	}
	if rec.Revoked {
		return response{}, false
	}
	now := deps.now().UTC()
	if !rec.ExpiresAt.After(now) {
		return response{}, false
	}
	if rec.ClientID != authenticatedClientID &&
		!deps.mayIntrospectForResource(authenticatedClientID, audienceList(rec.Audience)) {
		// Same-client-only unless the caller is a registered
		// introspection client for the resource this token names.
		return response{}, false
	}
	publicSubject, ok := projectIntrospectionSubject(ctx, deps, rec.Subject, rec.ClientID)
	if !ok {
		return response{}, false
	}
	out := projectOpaqueAccessToken(rec, publicSubject, deps.Issuer)
	out.AuthorizationDetails = grantAuthorizationDetails(ctx, deps, rec.GrantID)
	return out, true
}

// grantAuthorizationDetails reads the RFC 9396 authorization_details the
// grant was issued with, for the introspection echo (RFC 9396 §9). A nil
// store, an empty grantID, or any lookup failure yields nil so the field
// is simply omitted — introspection never fails on the details echo.
func grantAuthorizationDetails(ctx context.Context, deps Deps, grantID string) []map[string]any {
	if deps.Grants == nil || grantID == "" {
		return nil
	}
	g, err := deps.Grants.Find(ctx, grantID)
	if err != nil || g == nil {
		return nil
	}
	return g.AuthorizationDetails
}

// projectIntrospectionSubject converts the OP-internal raw subject on
// an opaque-access-token or refresh-token record into the per-client
// pairwise value the introspection response carries. A nil
// SubjectProjector (the OP is not configured for pairwise) returns the
// raw value verbatim. A configured projector that errors, returns the
// empty string, or fails to resolve the client collapses onto inactive
// per RFC 7662 §2.2 — leaking a 5xx (or a partially-projected response)
// would reveal that the token does descend from a live record.
func projectIntrospectionSubject(ctx context.Context, deps Deps, rawSubject, clientID string) (string, bool) {
	if deps.SubjectProjector == nil {
		return rawSubject, true
	}
	if deps.Clients == nil {
		return "", false
	}
	client, err := deps.Clients.GetClient(ctx, clientID)
	if err != nil || client == nil {
		return "", false
	}
	projected, err := deps.SubjectProjector(ctx, rawSubject, client)
	if err != nil || projected == "" {
		return "", false
	}
	return projected, true
}

// projectOpaqueAccessToken builds an active introspection response
// from a live opaque-access-token record. Fields the record does not
// carry stay zero-valued and are dropped by omitempty on the wire.
// publicSubject is the per-client pairwise value (or rec.Subject when
// no SubjectProjector is configured) that the wire response carries;
// the caller resolves it through [projectIntrospectionSubject] so the
// "sub" returned here matches what the JWT access-token branch would
// emit for the same chain (RFC 9068 §3 / OIDC Core §8.1). issuer is
// carried for the same reason: a resource server validating "iss"
// must not start failing because the deployment switched the access
// token format.
//
// "jti" stays absent on this branch, and that asymmetry is deliberate
// rather than an oversight. The only identifier an opaque record
// holds is [store.OpaqueAccessToken.ID], which IS the credential
// handed to the client; publishing it as "jti" would echo a bearer
// token back into a response body that routinely lands in resource
// server logs.
func projectOpaqueAccessToken(rec *store.OpaqueAccessToken, publicSubject, issuer string) response {
	out := response{
		Active:    true,
		ClientID:  rec.ClientID,
		TokenType: tokenTypeBearer,
		Sub:       publicSubject,
		Iss:       issuer,
		ACR:       rec.ACR,
	}
	if !rec.IssuedAt.IsZero() {
		out.Iat = rec.IssuedAt.Unix()
	}
	if !rec.ExpiresAt.IsZero() {
		out.Exp = rec.ExpiresAt.Unix()
	}
	if !rec.AuthTime.IsZero() {
		out.AuthTime = rec.AuthTime.Unix()
	}
	if len(rec.Scope) > 0 {
		out.Scope = strings.Join(rec.Scope, " ")
	}
	if rec.Audience != "" {
		out.Aud = []string{rec.Audience}
	}
	if len(rec.AMR) > 0 {
		out.AMR = append([]string(nil), rec.AMR...)
	}
	if cnf := opaqueAccessTokenCnf(rec); cnf != nil {
		out.Cnf = cnf
	}
	return out
}

// opaqueAccessTokenCnf returns the cnf map for an opaque-access-token
// record, or nil when the token is bearer (neither DPoP nor mTLS
// bound). Mirrors [refreshTokenCnf]; the wire format treats the two
// fields as independent (RFC 9449 §6.1, RFC 8705 §3.1).
func opaqueAccessTokenCnf(rec *store.OpaqueAccessToken) map[string]string {
	if rec.DPoPJKT == "" && rec.MTLSCertThumbprint == "" {
		return nil
	}
	cnf := make(map[string]string, 2)
	if rec.DPoPJKT != "" {
		cnf["jkt"] = rec.DPoPJKT
	}
	if rec.MTLSCertThumbprint != "" {
		cnf["x5t#S256"] = rec.MTLSCertThumbprint
	}
	return cnf
}

// projectRefreshToken builds an active introspection response from a
// live refresh-token record. "iat" mirrors the record's CreatedAt and
// "exp" mirrors ExpiresAt; the response carries cnf when the token
// chain is sender-constrained. publicSubject is the per-client pairwise
// value resolved by [projectIntrospectionSubject], so the "sub" on the
// wire matches the JWT access-token branch (RFC 9068 §3 / OIDC §8.1);
// issuer is carried for the same reason. "jti" is omitted here on the
// same grounds as [projectOpaqueAccessToken].
func projectRefreshToken(rec *store.RefreshToken, publicSubject, issuer string) response {
	out := response{
		Active:    true,
		ClientID:  rec.ClientID,
		TokenType: tokenTypeBearer,
		Sub:       publicSubject,
		Iss:       issuer,
		Exp:       rec.ExpiresAt.Unix(),
	}
	if !rec.CreatedAt.IsZero() {
		out.Iat = rec.CreatedAt.Unix()
	}
	if len(rec.Scope) > 0 {
		out.Scope = strings.Join(rec.Scope, " ")
	}
	if cnf := refreshTokenCnf(rec); cnf != nil {
		out.Cnf = cnf
	}
	return out
}

// refreshTokenCnf returns the cnf map for a refresh-token record, or
// nil when the chain is bearer (neither DPoP nor mTLS bound). Both
// fields are projected when set; the wire format treats them as
// independent (RFC 9449 §6.1, RFC 8705 §3.1) even though v1.0 only
// uses one method per chain in practice.
func refreshTokenCnf(rec *store.RefreshToken) map[string]string {
	if rec.DPoPJKT == "" && rec.MTLSCertThumbprint == "" {
		return nil
	}
	cnf := make(map[string]string, 2)
	if rec.DPoPJKT != "" {
		cnf["jkt"] = rec.DPoPJKT
	}
	if rec.MTLSCertThumbprint != "" {
		cnf["x5t#S256"] = rec.MTLSCertThumbprint
	}
	return cnf
}

// cloneStringMap returns a defensive copy of in. The introspection
// response shares a borrowed reference with [tokens.AccessTokenClaims];
// without the copy a caller mutating the returned map would corrupt
// the verifier's decoded claims, which the library treats as
// read-only.
func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// writeResponse marshals body and writes it with the cache-control and
// content-type headers RFC 7662 §2.2 / §4 owe every successful
// response. The status is always 200 — even for inactive — because the
// inactive fallback is structurally identical to a "valid but
// expired" response and RFC 7662 §2.2 forbids distinguishing the two
// at the HTTP layer.
func writeResponse(w http.ResponseWriter, body response) {
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Marshal failures on a fixed-shape struct are programmer bugs;
	// dropping the error here mirrors the parendpoint posture and
	// avoids partial-body collisions with the WriteHeader call.
	_ = json.NewEncoder(w).Encode(body)
}
