package endpointsupport

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/revocation"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// BearerSchemeBearer / BearerSchemeDPoP name the two Authorization
// header schemes the OP recognises for bearer-style credentials. The
// constants stay exported so endpoints that need to construct or
// inspect challenges share one canonical spelling.
const (
	BearerSchemeBearer = "Bearer"
	BearerSchemeDPoP   = "DPoP"
)

// BearerFromHeader extracts the credential carried by an Authorization
// header value, matching the RFC 6750 §2.1 ("Bearer") and RFC 9449 §7.1
// ("DPoP") schemes. The match is case-insensitive on the scheme name;
// the returned token is whitespace-trimmed.
//
// The second return reports whether a recognised credential was
// observed at all. An empty header, an unknown scheme, or a scheme
// without a value all return ("", false).
//
// The helper is the consolidated form of the bearer-extraction
// snippets each endpoint was carrying inline. The userinfo handler's
// extractBearer continues to layer additional rules (POST body
// channel, multi-channel rejection) on top of this primitive; only
// the header-parsing slice is shared.
func BearerFromHeader(value string) (string, bool) {
	tok, _, ok := BearerCredentialFromHeader(value)
	return tok, ok
}

// BearerCredentialFromHeader is [BearerFromHeader] that also reports which
// scheme carried the credential — [BearerSchemeBearer] (RFC 6750 §2.1) or
// [BearerSchemeDPoP] (RFC 9449 §7.1). A resource server that must reject a
// DPoP-bound token presented under the wrong scheme (RFC 9449 §7.1
// requires the "DPoP" scheme for sender-constrained tokens) consults the
// scheme; callers that only need the token use [BearerFromHeader]. The
// scheme is returned in its canonical spelling regardless of the input
// header's case. When no recognised credential is present, all three
// returns are zero ("", "", false).
func BearerCredentialFromHeader(value string) (token, scheme string, ok bool) {
	for _, s := range []string{BearerSchemeBearer, BearerSchemeDPoP} {
		prefix := s + " "
		if len(value) <= len(prefix) {
			continue
		}
		if !strings.EqualFold(value[:len(prefix)], prefix) {
			continue
		}
		tok := strings.TrimSpace(value[len(prefix):])
		if tok == "" {
			return "", "", false
		}
		return tok, s, true
	}
	return "", "", false
}

// IsFormContent reports whether ct is application/x-www-form-urlencoded.
// Parameters (charset, boundary, etc.) are tolerated. Mirrors the helper
// each form-accepting endpoint had its own copy of so the form-content
// contract stays uniform.
func IsFormContent(ct string) bool {
	return matchMediaType(ct, "application/x-www-form-urlencoded")
}

// IsJSONContent reports whether ct is application/json. Parameters
// (charset, etc.) are tolerated. Mirrors the helper in the registration
// / par / token endpoints so the JSON-content contract stays uniform.
func IsJSONContent(ct string) bool {
	return matchMediaType(ct, "application/json")
}

// matchMediaType is the shared comparator the IsFormContent /
// IsJSONContent helpers delegate to. It strips any parameters after
// the first ';' and compares the remainder case-insensitively.
func matchMediaType(ct, want string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), want)
}

// BearerDeps bundles what [AcceptBearer] needs to decide whether a
// presented access token authorises the request. Every endpoint that
// accepts the OP's own access tokens fills it from the same option
// wiring, so the acceptance rules (format, revocation, sender
// constraint) cannot drift between them.
type BearerDeps struct {
	// Keys verifies JWT access tokens. The active key plus every
	// retiring key must be present so pre-rotation tokens still verify.
	Keys *keys.Set

	// Issuer is compared against the JWT "iss" claim, and any non-empty
	// audience must contain it. An empty Issuer disables both checks.
	Issuer string

	// Clock drives JWT exp / iat checks and opaque-record expiry. Nil
	// falls back to the system clock.
	Clock tokens.Clock

	// Leeway is the symmetric tolerance on JWT exp / iat comparisons.
	Leeway time.Duration

	// Clients lets revocation treat a deleted client as having retired
	// its tokens. Nil skips that probe.
	Clients store.ClientStore

	// Grants and SubjectProjector feed the opaque-record public subject
	// projection ([tokens.OpaqueAccessTokenLookup]).
	Grants           store.GrantStore
	SubjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error)

	// OpaqueAccessTokens resolves non-JWS bearers. Nil disables the
	// opaque branch; such tokens then fail JWT verification.
	OpaqueAccessTokens store.OpaqueAccessTokenStore

	// AccessTokens, GrantRevocations and RevocationStrategy select and
	// back the JWT revocation lookup ([revocation.JWTAccessTokenRevoked]).
	AccessTokens       store.AccessTokenRegistry
	GrantRevocations   store.GrantRevocationStore
	RevocationStrategy store.AccessTokenRevocationStrategy

	// DPoP verifies proofs for cnf.jkt-bound tokens. Nil rejects every
	// such token rather than downgrading it to bearer.
	DPoP *dpop.Verifier

	// DPoPNonces issues the DPoP-Nonce value on a use_dpop_nonce
	// rejection. Nil omits the header but keeps the error code.
	DPoPNonces dpop.NonceIssuer

	// MTLS verifies the client certificate for cnf.x5t#S256-bound
	// tokens. Nil rejects every such token.
	MTLS *mtls.Verifier
}

// BearerAccess is an access token [AcceptBearer] accepted.
type BearerAccess struct {
	// Claims is the verified claim set. For an opaque token it is the
	// stored record projected onto the same shape: Subject (public),
	// ClientID, GrantID, Scope, Audience, ExpiresAt, Confirmation and
	// UserInfoClaims are populated; JTI and IssuedAt are not.
	Claims *tokens.AccessTokenClaims

	// AuthorizationRecorded reports whether the token carries its own
	// claims request rather than relying on the grant's
	// ([tokens.ResolveAuthorization]).
	AuthorizationRecorded bool
}

// ChallengeUseDPoPNonce is the RFC 9449 §9 error code asking the client
// to retry with the server-supplied nonce.
const ChallengeUseDPoPNonce = "use_dpop_nonce"

// Descriptions carried on invalid_token rejections. They distinguish
// the expired and revoked cases for the client but never name the
// sub-cause of any other failure (RFC 6750 §3.1).
//
//nolint:gosec // G101 false positive: challenge descriptions, not credentials.
const (
	bearerDescInvalid        = "The access token is invalid"
	bearerDescExpiredJWT     = "The access token expired"
	bearerDescExpiredOpaque  = "The access token has expired"
	bearerDescRevoked        = "The access token has been revoked"
	bearerDescUseDPoPNonce   = "DPoP proof requires a server-supplied nonce; retry using the value in the DPoP-Nonce response header"
	bearerDescDPoPDisabled   = "DPoP verification is not enabled"
	bearerDescDPoPScheme     = "DPoP-bound access token must use the DPoP authentication scheme"
	bearerDescDPoPRequired   = "DPoP proof required"
	bearerDescDPoPRejected   = "DPoP proof rejected"
	bearerDescDPoPMismatch   = "DPoP proof key does not match the bound thumbprint"
	bearerDescMTLSDisabled   = "mTLS verification is not enabled"
	bearerDescMTLSMismatched = "client certificate does not match the bound thumbprint"
)

// BearerError is the rejection [AcceptBearer] returns. It carries the
// whole RFC 6750 §3 / RFC 9449 §7.1 response so every caller writes the
// same bytes via [BearerError.WriteResponse].
type BearerError struct {
	// Status is 401 for a refused credential and 500 when a store
	// lookup could not be answered.
	Status int

	// Scheme is the challenge scheme: [BearerSchemeBearer] or
	// [BearerSchemeDPoP].
	Scheme string

	// Code is the challenge error code; empty for a request that
	// carried no recognised credential (RFC 6750 §3.1 bare challenge).
	Code string

	// Description is the challenge error_description.
	Description string

	// Nonce is the DPoP-Nonce response header value, set only on a
	// [ChallengeUseDPoPNonce] rejection with a working issuer.
	Nonce string

	cause error
}

func (e *BearerError) Error() string {
	if e.Code == "" {
		return "bearer: missing access token"
	}
	return "bearer: " + e.Code + ": " + e.Description
}

func (e *BearerError) Unwrap() error { return e.cause }

// WriteResponse writes the rejection: a 500 with no detail for a store
// fault, otherwise a 401 with the WWW-Authenticate challenge (and the
// DPoP-Nonce header when one was issued).
func (e *BearerError) WriteResponse(w http.ResponseWriter) {
	if e.Status == http.StatusInternalServerError {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if e.Nonce != "" {
		w.Header().Set("DPoP-Nonce", e.Nonce)
	}
	w.Header().Set("WWW-Authenticate", BuildBearerChallenge(e.Scheme,
		ChallengeParam{Name: ChallengeError, Value: e.Code},
		ChallengeParam{Name: ChallengeErrorDescription, Value: e.Description},
	))
	w.WriteHeader(e.Status)
}

// NewUseDPoPNonceError builds the RFC 9449 §9 rejection, issuing a
// fresh nonce from nonces on every call (never echoing the client's).
// A nil issuer, or one returning "", leaves Nonce empty.
func NewUseDPoPNonceError(nonces dpop.NonceIssuer) *BearerError {
	e := bearerReject(BearerSchemeDPoP, ChallengeUseDPoPNonce, bearerDescUseDPoPNonce)
	if nonces != nil {
		e.Nonce = nonces.IssueNonce()
	}
	return e
}

func bearerReject(scheme, code, description string) *BearerError {
	return &BearerError{Status: http.StatusUnauthorized, Scheme: scheme, Code: code, Description: description}
}

func invalidBearer(description string) *BearerError {
	return bearerReject(BearerSchemeBearer, "invalid_token", description)
}

func invalidDPoP(description string) *BearerError {
	return bearerReject(BearerSchemeDPoP, "invalid_token", description)
}

func bearerStoreFault(cause error) *BearerError {
	return &BearerError{Status: http.StatusInternalServerError, cause: cause}
}

// errBearerRevocationLookup marks a revocation lookup that could not be
// answered; serving the request anyway would reopen the cascade gap.
var errBearerRevocationLookup = errors.New("bearer: revocation lookup failed")

// AcceptBearer authorises r by the access token in its Authorization
// header ("Bearer" or "DPoP" scheme). A request with no recognised
// credential is rejected with a bare challenge. Every error is a
// [*BearerError].
func AcceptBearer(r *http.Request, deps BearerDeps) (*BearerAccess, error) {
	raw, ok := BearerFromHeader(r.Header.Get("Authorization"))
	if !ok {
		return nil, &BearerError{Status: http.StatusUnauthorized, Scheme: BearerSchemeBearer}
	}
	return AcceptBearerToken(r, raw, deps)
}

// AcceptBearerToken is [AcceptBearer] for a token the caller already
// extracted (an endpoint that also accepts the RFC 6750 §2.2 form-body
// channel). r still supplies the Authorization scheme and the DPoP /
// mTLS proof.
//
// A non-JWS token resolves through the opaque store when one is wired.
// The checks then run in a fixed order — liveness, audience (any
// non-empty audience must contain the issuer), sender constraint, and
// for JWTs the revocation lookup last so a malformed or mis-bound token
// costs no registry round-trip.
func AcceptBearerToken(r *http.Request, raw string, deps BearerDeps) (*BearerAccess, error) {
	if !LooksLikeJWT(raw) && deps.OpaqueAccessTokens != nil {
		return acceptOpaqueBearer(r, raw, deps)
	}
	return acceptJWTBearer(r, raw, deps)
}

func acceptJWTBearer(r *http.Request, raw string, deps BearerDeps) (*BearerAccess, error) {
	verifier := NewAccessTokenVerifier(deps.Keys, deps.Issuer, deps.Clock, deps.Leeway, deps.RevocationStrategy)
	claims, _, err := verifier.Verify(r.Context(), raw)
	if err != nil {
		if errors.Is(err, tokens.ErrAccessTokenExpired) {
			return nil, invalidBearer(bearerDescExpiredJWT)
		}
		return nil, invalidBearer(bearerDescInvalid)
	}
	if err := checkBearerAudience(deps.Issuer, claims.Audience); err != nil {
		return nil, err
	}
	if err := checkBearerCnf(r, deps, claims.Confirmation, raw); err != nil {
		return nil, err
	}
	revoked, ok := revocation.JWTAccessTokenRevoked(r.Context(), revocation.JWTRevocationOpts{
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		Clients:            deps.Clients,
		RevocationStrategy: deps.RevocationStrategy,
	}, claims)
	if !ok {
		return nil, bearerStoreFault(errBearerRevocationLookup)
	}
	if revoked {
		return nil, invalidBearer(bearerDescRevoked)
	}
	return &BearerAccess{Claims: claims, AuthorizationRecorded: claims.UserInfoClaims != nil}, nil
}

func acceptOpaqueBearer(r *http.Request, raw string, deps BearerDeps) (*BearerAccess, error) {
	view, err := tokens.ResolveOpaqueAccessToken(r.Context(), tokens.OpaqueAccessTokenLookup{
		Store:            deps.OpaqueAccessTokens,
		Clients:          deps.Clients,
		SubjectProjector: deps.SubjectProjector,
		Grants:           deps.Grants,
	}, raw, timex.OrSystem(deps.Clock).Now().UTC())
	switch {
	case err == nil:
	case errors.Is(err, tokens.ErrOpaqueAccessTokenRevoked),
		errors.Is(err, tokens.ErrOpaqueAccessTokenClientGone):
		// A deleted client retires its tokens; the JWT path words that
		// outcome the same way.
		return nil, invalidBearer(bearerDescRevoked)
	case errors.Is(err, tokens.ErrOpaqueAccessTokenExpired):
		return nil, invalidBearer(bearerDescExpiredOpaque)
	default:
		// Unknown, projection failure and store faults are not told apart.
		return nil, invalidBearer(bearerDescInvalid)
	}
	claims := projectOpaqueBearer(view)
	if err := checkBearerAudience(deps.Issuer, claims.Audience); err != nil {
		return nil, err
	}
	if err := checkBearerCnf(r, deps, claims.Confirmation, raw); err != nil {
		return nil, err
	}
	return &BearerAccess{Claims: claims, AuthorizationRecorded: view.Record.AuthorizationRecorded}, nil
}

// projectOpaqueBearer maps a live opaque record onto the JWT claim
// shape. JTI is left empty: the JWT revocation registry keys on it and
// has no counterpart for opaque tokens, whose liveness the record
// already decided.
func projectOpaqueBearer(view *tokens.OpaqueAccessTokenView) *tokens.AccessTokenClaims {
	rec := view.Record
	claims := &tokens.AccessTokenClaims{
		Subject:      view.Subject,
		ClientID:     rec.ClientID,
		GrantID:      rec.GrantID,
		Scope:        append([]string(nil), rec.Scope...),
		Confirmation: view.Confirmation(),
		// The record keeps the whole claims request; only its userinfo
		// member is carried.
		UserInfoClaims: rec.Claims,
	}
	if rec.Audience != "" {
		claims.Audience = []string{rec.Audience}
	}
	if !rec.ExpiresAt.IsZero() {
		claims.ExpiresAt = rec.ExpiresAt.Unix()
	}
	return claims
}

// checkBearerAudience refuses a token whose audience is set but does not
// contain the issuer, so a token minted for another resource server
// (RFC 8707) is not usable at the OP. An absent audience is accepted.
func checkBearerAudience(issuer string, audience []string) error {
	if issuer == "" || len(audience) == 0 {
		return nil
	}
	for _, a := range audience {
		if a == issuer {
			return nil
		}
	}
	return invalidBearer(bearerDescInvalid)
}

// checkBearerCnf enforces every sender constraint the token carries
// (RFC 7800): cnf.jkt by DPoP proof, cnf.x5t#S256 by client
// certificate, both when both are present.
func checkBearerCnf(r *http.Request, deps BearerDeps, cnf map[string]string, raw string) error {
	if jkt := cnf[tokens.CnfJKT]; jkt != "" {
		if err := checkBearerDPoP(r, deps, jkt, raw); err != nil {
			return err
		}
	}
	if x5t := cnf[tokens.CnfX5tS256]; x5t != "" {
		if err := checkBearerMTLS(r, deps, x5t); err != nil {
			return err
		}
	}
	return nil
}

func checkBearerDPoP(r *http.Request, deps BearerDeps, jkt, raw string) error {
	if deps.DPoP == nil {
		return invalidDPoP(bearerDescDPoPDisabled)
	}
	// RFC 9449 §7.1: a DPoP-bound token must arrive under the "DPoP"
	// scheme, not "Bearer" nor a schemeless form-body channel.
	if _, scheme, _ := BearerCredentialFromHeader(r.Header.Get("Authorization")); scheme != BearerSchemeDPoP {
		return invalidDPoP(bearerDescDPoPScheme)
	}
	if !dpop.HasProof(r) {
		return invalidDPoP(bearerDescDPoPRequired)
	}
	res, err := deps.DPoP.VerifyHTTPRequest(r.Context(), r, raw)
	if err != nil {
		if dpop.IsNonceError(err) {
			return NewUseDPoPNonceError(deps.DPoPNonces)
		}
		return invalidDPoP(bearerDescDPoPRejected)
	}
	if res.JKT != jkt {
		return invalidDPoP(bearerDescDPoPMismatch)
	}
	return nil
}

func checkBearerMTLS(r *http.Request, deps BearerDeps, bound string) error {
	if deps.MTLS == nil {
		return invalidBearer(bearerDescMTLSDisabled)
	}
	if err := deps.MTLS.VerifyBoundRequest(r, bound); err != nil {
		return invalidBearer(bearerDescMTLSMismatched)
	}
	return nil
}
