package userinfo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/internal/userclaims"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Clock is the package-local name for the shared wall-clock interface; a nil
// Clock falls back to the system clock.
type Clock = timex.Clock

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
	// release, so an embedder that leaves the grant store unwired still
	// receives every scope-implied claim.
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

	// ClaimsParameterEnabled mirrors
	// [authorizeendpoint.Deps.ClaimsParameterEnabled] for the response
	// side: when false the handler ignores any OIDC Core 1.0 §5.5
	// payload persisted on the originating grant and releases claims
	// from the granted scopes alone. The gate reads the grant rather
	// than the request, so a grant established while the parameter was
	// still enabled stops projecting the moment the OP is reconfigured
	// — the stored payload is left intact as the record of what the
	// user consented to. Zero value is false so a Deps assembled
	// without the flag fails closed.
	ClaimsParameterEnabled bool

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
	// opaque-format /userinfo branch consults. When the presented bearer
	// is not JWS-shaped the handler hashes it, looks the digest up here,
	// and applies the same revoked / expired / cnf-mismatch checks as
	// the JWT path before releasing claims. A nil value disables the
	// opaque branch; non-JWS tokens then collapse onto the existing
	// invalid_token response, mirroring the JWT-only legacy posture.
	OpaqueAccessTokens store.OpaqueAccessTokenStore

	// GrantRevocations is the [store.GrantRevocationStore] consulted by
	// the grant-tombstone JWT access-token revocation strategy. The
	// /userinfo handler uses it to reject access tokens whose grant has
	// been tombstoned; the lookup is keyed by the AT's "gid" private
	// claim. A nil value disables the lookup and the handler falls back
	// to whichever legacy behaviour [RevocationStrategy] selects.
	GrantRevocations store.GrantRevocationStore

	// RevocationStrategy selects the JWT access-token revocation shape.
	// The zero value is [store.RevocationStrategyGrantTombstone], which
	// is the documented default; the library wires this from
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The registry is wrapped per request, not once here: the memo
		// is only sound for the duration of a single request, and a
		// handler-lifetime cache would serve a deleted client forever.
		perRequest := deps
		if deps.Clients != nil {
			perRequest.Clients = &requestClientCache{inner: deps.Clients}
		}
		serveUserInfo(w, r, perRequest)
	})
}

// serveUserInfo runs one /userinfo request through the dispatch ladder:
// method gate → bearer extraction → token acceptance → claim assembly.
// Acceptance (JWT or opaque, audience, sender constraint, revocation) is
// [endpointsupport.AcceptBearerToken], shared with every endpoint that
// takes the OP's own access tokens.
func serveUserInfo(w http.ResponseWriter, r *http.Request, deps HandlerDeps) {
	if !httpx.EnforceMethod(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	raw, err := extractBearer(w, r)
	if err != nil {
		respondBearerExtractError(w, err)
		return
	}
	access, err := endpointsupport.AcceptBearerToken(r, raw, bearerDeps(deps))
	if err != nil {
		respondBearerRejected(w, err)
		return
	}
	claims := access.Claims
	out, client, ok := assembleClaims(r.Context(), w, deps, claims, access.AuthorizationRecorded)
	if !ok {
		return
	}
	dispatchUserInfoResponse(r, w, deps, claims.ClientID, out, client)
}

// bearerDeps projects the handler's dependencies onto the shared bearer
// acceptance rules.
func bearerDeps(deps HandlerDeps) endpointsupport.BearerDeps {
	return endpointsupport.BearerDeps{
		Keys:               deps.Keys,
		Issuer:             deps.Issuer,
		Clock:              deps.Clock,
		Leeway:             deps.Leeway,
		Clients:            deps.Clients,
		Grants:             deps.Grants,
		SubjectProjector:   deps.SubjectProjector,
		OpaqueAccessTokens: deps.OpaqueAccessTokens,
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		RevocationStrategy: deps.RevocationStrategy,
		DPoP:               deps.DPoP,
		DPoPNonces:         deps.DPoPNonces,
		MTLS:               deps.MTLS,
	}
}

// respondBearerRejected writes the challenge for a token
// [endpointsupport.AcceptBearerToken] refused.
func respondBearerRejected(w http.ResponseWriter, err error) {
	var be *endpointsupport.BearerError
	if !errors.As(err, &be) {
		writeInternalError(w)
		return
	}
	be.WriteResponse(w)
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
		var err error
		if client, ok, err = resolveClient(r.Context(), deps, clientID); err != nil {
			// Serving JSON here would hand plaintext claims to a client
			// that may have registered userinfo encryption.
			writeInternalError(w)
			return
		}
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
	writeUserInfoJWT(r.Context(), w, deps, clientID, client, body)
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
	header, _ := endpointsupport.BearerFromHeader(r.Header.Get("Authorization"))
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
	if !endpointsupport.IsFormContent(r.Header.Get("Content-Type")) {
		return "", false, nil
	}
	endpointsupport.LimitFormBody(w, r)
	// G120 false positive: LimitFormBody wraps r.Body in
	// http.MaxBytesReader on the line above so ParseForm reads from a
	// bounded reader. The MaxBytesError surfaces below so callers map
	// it to invalid_request / 413.
	if err := r.ParseForm(); err != nil {
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

// respondBearerExtractError writes the 401/400/413 response that
// matches the failure mode of [extractBearer]: "missing" -> bare
// challenge, "tooLarge" -> 413 with invalid_request, "multiple
// channels / malformed" -> 400 invalid_request.
func respondBearerExtractError(w http.ResponseWriter, err error) {
	var be *bearerError
	if errors.As(err, &be) {
		switch {
		case be.missing:
			w.Header().Set("WWW-Authenticate", endpointsupport.BuildBearerChallenge(
				endpointsupport.BearerSchemeBearer,
				endpointsupport.ChallengeParam{Name: endpointsupport.ChallengeRealm, Value: "userinfo"},
			))
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
// RFC 6750 §3.1 invalid_request challenge,
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

// respondGenericInvalidToken writes the invalid_token challenge, which
// names no sub-cause.
func respondGenericInvalidToken(w http.ResponseWriter) {
	endpointsupport.NewInvalidTokenError().WriteResponse(w)
}

// writeInternalError writes the opaque 500 every unanswerable store or
// signing fault collapses onto.
func writeInternalError(w http.ResponseWriter) {
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// assembleClaims looks the subject up in the user store, projects the
// granted scopes onto the claim universe, and returns the response
// body. The bool reports success; on false the handler has already
// written the response and the caller MUST return.
//
// The grant the token descends from is resolved once, from the token's
// own lineage ([resolveGrant]): the raw-subject recovery reads it, and
// the OIDC Core §5.5 claims-request projection falls back to it only for
// a record that predates carrying its own request ([tokenClaimsRequest];
// claimsRecorded reports which).
//
// When the access token's "sub" carries the per-client pairwise value
// (RFC 9068 §3 / OIDC Core §8.1 — minted that way so RS-visible and
// id_token "sub" agree), the raw OP-internal subject is read off that
// grant. UserStore lookup keys on the raw value; the response "sub" is
// then re-projected so the client observes the pairwise value
// end-to-end. The opaque-format path carries the same grant lineage in
// its persistent record and projects it onto the synthetic claims
// handed here.
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
	claimsRecorded bool,
) (map[string]any, *store.Client, bool) {
	if claims.GrantID == "" {
		// A token with no grant lineage (client_credentials) names no
		// end-user; its "sub" is a client_id and must never key a user
		// lookup, whatever the subject configuration.
		respondGenericInvalidToken(w)
		return nil, nil, false
	}
	grant, err := resolveGrant(ctx, deps, claims)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		// The grant store did not answer. Serving the request anyway
		// would fall back to scope-derived claim release and project a
		// set the grant never authorised.
		writeInternalError(w)
		return nil, nil, false
	}
	rawSubject, ok := resolveRawSubject(w, deps, claims, grant)
	if !ok {
		return nil, nil, false
	}
	user, err := deps.UserStore.FindBySubject(ctx, rawSubject)
	if err == nil && user == nil {
		// A nil record alongside a nil error violates the store contract.
		// A subject the backend cannot produce is answered as an unknown
		// one rather than served a claim set assembled from nothing.
		err = store.ErrNotFound
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			respondGenericInvalidToken(w)
			return nil, nil, false
		}
		writeInternalError(w)
		return nil, nil, false
	}
	source := userclaims.Source(user)
	publicSubject, client, ok := projectResponseSubject(ctx, w, deps, rawSubject, claims.ClientID)
	if !ok {
		return nil, nil, false
	}
	out, err := Build(Input{
		Subject:           publicSubject,
		Scopes:            claims.Scope,
		Source:            source,
		CustomScopeClaims: deps.CustomScopeClaims,
		Claims:            tokenClaimsRequest(deps, claims, claimsRecorded, grant),
	})
	if err != nil {
		writeInternalError(w)
		return nil, nil, false
	}
	return out, client, true
}

// resolveGrant loads the grant the presented access token descends
// from. The lineage is carried by the token itself — the "gid" private
// claim (RFC 7519 §4.3) the token endpoint stamps on every JWT it
// issues, or the GrantID column of the opaque access-token record — so
// the lookup is by grant ID and never by (subject, client_id): the
// library does not assume there is at most one grant per pair, and a
// (subject, client_id) search would resolve to whichever grant is
// currently active rather than the one that authorised this token.
//
// [store.ErrNotFound] means "no grant lineage is available", which
// covers an unwired [HandlerDeps.Grants] and a grant that has been
// deleted since issuance.
// Deciding what that absence means belongs to the callers:
// [resolveRawSubject] treats it as fatal while pairwise projection is
// configured, and [claimsRequestFromGrant] falls back to scope-derived
// release.
//
// Any other error means the backend could not answer, which is a
// different thing and is kept different. Falling back to scope-derived
// release because the grant store timed out would release a claim set
// the grant never authorised, and do it silently. Absence and fault
// travel as distinct errors for the same reason the user lookup below
// separates them: a caller that cannot tell them apart has to guess,
// and the safe guess and the useful guess are not the same one.
func resolveGrant(
	ctx context.Context,
	deps HandlerDeps,
	claims *tokens.AccessTokenClaims,
) (*store.Grant, error) {
	if deps.Grants == nil {
		return nil, store.ErrNotFound
	}
	g, err := deps.Grants.Find(ctx, claims.GrantID)
	if err != nil {
		return nil, fmt.Errorf("userinfo: resolve grant: %w", err)
	}
	if g == nil {
		// A nil record alongside a nil error violates the store
		// contract; treat it as the absence it resembles rather than
		// handing a nil grant to the projection.
		return nil, store.ErrNotFound
	}
	return g, nil
}

// resolveRawSubject returns the OP-internal stable subject identifier
// for the presented access token. JWT tokens minted under a configured
// SubjectProjector carry the per-client pairwise value in "sub" and the
// stable identifier on the originating grant, so the raw value is read
// off the grant [resolveGrant] recovered from the token's own lineage.
// Opaque records carry the same GrantID in persistent storage, allowing
// both token formats to follow this path. A token without a GrantID
// never gets here: [assembleClaims] refuses it first.
//
// A missing or unrecoverable grant collapses onto invalid_token rather
// than silently falling back to the pairwise value: the grant being
// gone means the consent the token descends from has been revoked, and
// continuing to serve userinfo would defeat that.
//
// When no SubjectProjector is configured the token's "sub" is already
// the OP-internal value (mintAccessToken stamps raw == public on that
// branch), so the grant is not consulted at all.
func resolveRawSubject(
	w http.ResponseWriter,
	deps HandlerDeps,
	claims *tokens.AccessTokenClaims,
	grant *store.Grant,
) (string, bool) {
	if deps.SubjectProjector == nil {
		return claims.Subject, true
	}
	if grant == nil {
		respondGenericInvalidToken(w)
		return "", false
	}
	if grant.Subject == "" {
		writeInternalError(w)
		return "", false
	}
	return grant.Subject, true
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
	client, ok, err := resolveClient(ctx, deps, clientID)
	if err != nil {
		writeInternalError(w)
		return "", nil, false
	}
	if !ok {
		respondGenericInvalidToken(w)
		return "", nil, false
	}
	projected, err := deps.SubjectProjector(ctx, rawSubject, client)
	if err != nil || projected == "" {
		writeInternalError(w)
		return "", nil, false
	}
	return projected, client, true
}

// tokenClaimsRequest returns the OIDC Core 1.0 §5.5 "claims" request of
// the authorization the presented access token was issued under: the
// "userinfo_claims" claim of a JWT, the claims request of an opaque
// record. The grant the token descends from is shared by every
// authorization of the (subject, client_id) pair, so it is read only for
// a token minted before it carried the request (see
// [tokens.ResolveAuthorization]).
//
// Returns nil — which leaves the response scope-derived — when
// [HandlerDeps.ClaimsParameterEnabled] is false or the authorization
// carried no §5.5 payload. This is the only place the handler reads the
// payload, so the toggle covers every /userinfo response shape (JSON and
// signed JWT alike).
func tokenClaimsRequest(deps HandlerDeps, claims *tokens.AccessTokenClaims, recorded bool, g *store.Grant) *authorize.ClaimsRequest {
	if !deps.ClaimsParameterEnabled {
		return nil
	}
	own := tokens.Authorization{Claims: claims.UserInfoClaims}
	return authorize.DecodeClaimsFromGrant(tokens.ResolveAuthorization(own, recorded, g, claims.ClientID).Claims)
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
		writeInternalError(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	stampUncacheable(w)
	_, _ = w.Write(payload)
}

// userInfoCacheControl is the Cache-Control value every successful
// response carries: no-store per RFC 6749 §5.1, with "private" kept for
// downstream caches that honour the OIDC Core hint.
const userInfoCacheControl = "no-store, private"

// stampUncacheable sets [userInfoCacheControl] plus the HTTP/1.0
// "Pragma: no-cache" companion RFC 6749 §5.1 also requires.
func stampUncacheable(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", userInfoCacheControl)
	w.Header().Set("Pragma", "no-cache")
}
