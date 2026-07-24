package tokenexchange

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// lookupResult bundles the resolved view together with a non-fatal
// classification of how the token verified. The handler uses [reason]
// to pick the right audit event (external issuer vs revoked vs unknown
// vs malformed).
type lookupResult struct {
	view   TokenView
	reason string
}

// errExternalIssuer signals the caller's iss did not match the OP's
// own issuer URL. Callers translate the value into an audit event
// (subject_token_external / actor_token_external) before surfacing
// invalid_grant.
var errExternalIssuer = errors.New("tokenexchange: token issued by an external issuer")

// errTokenInvalid signals the token failed verification (revoked,
// expired, unknown, malformed, signature mismatch, type mismatch).
// Callers emit token_exchange.subject_token_invalid before surfacing
// invalid_grant.
var errTokenInvalid = errors.New("tokenexchange: token failed verification")

var errIDTokenExpired = errors.New("tokenexchange: id_token expired")

// lookupToken resolves a subject_token or actor_token presented as
// raw bytes plus the URN naming its type.
func (h *Handler) lookupToken(ctx context.Context, raw, urn string) (lookupResult, error) {
	switch urn {
	case TokenTypeAccessToken:
		return h.lookupAccessToken(ctx, raw)
	case TokenTypeJWT:
		return h.lookupJWT(ctx, raw, TokenTypeJWT)
	case TokenTypeIDToken:
		return h.lookupIDToken(raw)
	default:
		return lookupResult{}, fmt.Errorf("%w: unknown token-type urn", errTokenInvalid)
	}
}

// lookupAccessToken handles the urn:ietf:params:oauth:token-type:access_token
// path. The library issues access tokens in either JWT-shape (RFC 9068)
// or opaque-shape; we try the JWT path first and fall back to the
// opaque store when the value does not parse as a JWS.
func (h *Handler) lookupAccessToken(ctx context.Context, raw string) (lookupResult, error) {
	if looksLikeJWS(raw) {
		return h.lookupJWT(ctx, raw, TokenTypeAccessToken)
	}
	return h.lookupOpaqueAccessToken(ctx, raw)
}

// lookupJWT verifies a JWT-shaped token against the OP keyset.
func (h *Handler) lookupJWT(ctx context.Context, raw, urn string) (lookupResult, error) {
	verifier := &tokens.AccessTokenVerifier{
		Keys:   h.keys,
		Issuer: h.issuer,
		Clock:  h.clock,
	}
	claims, _, err := verifier.Verify(raw)
	if err != nil {
		if errors.Is(err, tokens.ErrAccessTokenIssuerMismatch) {
			return lookupResult{reason: "issuer_mismatch"}, errExternalIssuer
		}
		return lookupResult{reason: classifyVerifyErr(err)}, fmt.Errorf("%w: %w", errTokenInvalid, err)
	}
	// Defence-in-depth: reject revoked JWT ATs even if the JWS itself
	// verifies. This follows the same strategy dispatcher as userinfo
	// and introspection, so grant tombstones close the token-exchange
	// bypass as well as per-JTI registry rows.
	if revoked, ok := endpointsupport.JWTAccessTokenRevoked(ctx, endpointsupport.JWTRevocationOpts{
		AccessTokens:       h.accessTokens,
		GrantRevocations:   h.grantRevocations,
		RevocationStrategy: h.revocationStrategy,
	}, claims); !ok {
		return lookupResult{reason: "registry_error"}, fmt.Errorf("%w: registry lookup failed", errTokenInvalid)
	} else if revoked {
		return lookupResult{reason: "revoked"}, errTokenInvalid
	}
	act := extractAct(raw)
	return lookupResult{
		view: TokenView{
			Type:          urn,
			ClientID:      claims.ClientID,
			Subject:       claims.Subject,
			Scope:         append([]string(nil), claims.Scope...),
			Audience:      normaliseAudience(claims.Audience),
			ExpiresAt:     time.Unix(claims.ExpiresAt, 0).UTC(),
			Confirmation:  confirmationFromCnf(claims.Confirmation),
			Act:           act,
			ActChainDepth: depthOfAct(act),
		},
	}, nil
}

// lookupIDToken verifies a JWT-shaped id_token signed by the OP. The
// id_token's typ header is "JWT" (not at+jwt) so the access-token
// verifier rejects it; we therefore parse + verify by hand against
// the same keyset.
func (h *Handler) lookupIDToken(raw string) (lookupResult, error) {
	jws, _, err := jose.ParseSigned(raw)
	if err != nil {
		return lookupResult{reason: "malformed"}, fmt.Errorf("%w: parse: %w", errTokenInvalid, err)
	}
	if len(jws.Signatures) == 0 {
		return lookupResult{reason: "malformed"}, fmt.Errorf("%w: no signature", errTokenInvalid)
	}
	typ, typOK := jws.Signatures[0].Protected.ExtraHeaders["typ"].(string)
	if !typOK || typ != "JWT" {
		return lookupResult{reason: "typ_mismatch"}, fmt.Errorf("%w: id_token typ header is not JWT", errTokenInvalid)
	}
	kid := jws.Signatures[0].Header.KeyID
	if kid == "" {
		return lookupResult{reason: "no_kid"}, fmt.Errorf("%w: kid missing", errTokenInvalid)
	}
	entry, ok := h.keys.Find(kid)
	if !ok {
		return lookupResult{reason: "unknown_kid"}, fmt.Errorf("%w: kid not in keyset", errTokenInvalid)
	}
	payload, err := jws.Verify(entry.Signer.Public())
	if err != nil {
		return lookupResult{reason: "signature"}, fmt.Errorf("%w: verify: %w", errTokenInvalid, err)
	}
	idClaims, aud, reason, err := decodeAndValidateIDTokenClaims(payload, h.now())
	if err != nil {
		return lookupResult{reason: reason}, fmt.Errorf("%w: %w", errTokenInvalid, err)
	}
	if h.issuer != "" && idClaims.Issuer != h.issuer {
		return lookupResult{reason: "issuer_mismatch"}, errExternalIssuer
	}
	scope := oidcscope.Parse(idClaims.Scope)
	aud = normaliseAudience(aud)
	clientID := idClaims.AuthorizedParty
	if clientID == "" {
		clientID = idClaims.ClientID
	}
	if clientID == "" && len(aud) == 1 {
		clientID = aud[0]
	}
	act := extractActFromRaw(idClaims.Act)
	return lookupResult{
		view: TokenView{
			Type:          TokenTypeIDToken,
			ClientID:      clientID,
			Subject:       idClaims.Subject,
			Scope:         scope,
			Audience:      aud,
			ExpiresAt:     time.Unix(idClaims.ExpiresAt, 0).UTC(),
			Confirmation:  confirmationFromCnf(idClaims.Confirmation),
			Act:           act,
			ActChainDepth: depthOfAct(act),
		},
	}, nil
}

// lookupOpaqueAccessToken resolves an opaque AT against the configured
// substore. A nil substore means opaque tokens are not in use; the
// caller surfaces the value as invalid_grant.
func (h *Handler) lookupOpaqueAccessToken(ctx context.Context, raw string) (lookupResult, error) {
	if h.opaqueAccessTokens == nil {
		return lookupResult{reason: "no_substore"}, fmt.Errorf("%w: opaque substore unavailable", errTokenInvalid)
	}
	rec, err := h.opaqueAccessTokens.Find(ctx, raw)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return lookupResult{reason: "unknown"}, errTokenInvalid
		}
		return lookupResult{reason: "store_error"}, fmt.Errorf("%w: store: %w", errTokenInvalid, err)
	}
	if rec == nil {
		return lookupResult{reason: "unknown"}, errTokenInvalid
	}
	if rec.Revoked {
		return lookupResult{reason: "revoked"}, errTokenInvalid
	}
	now := h.now()
	if rec.ExpiresAt.IsZero() {
		return lookupResult{reason: "missing_claim"}, fmt.Errorf("%w: opaque access token expiry missing", errTokenInvalid)
	}
	if !now.Before(rec.ExpiresAt) {
		return lookupResult{reason: "expired"}, errTokenInvalid
	}
	var cnf *Confirmation
	switch {
	case rec.DPoPJKT != "":
		cnf = &Confirmation{JKT: rec.DPoPJKT}
	case rec.MTLSCertThumbprint != "":
		cnf = &Confirmation{X5tS256: rec.MTLSCertThumbprint}
	}
	var aud []string
	if rec.Audience != "" {
		aud = []string{normaliseResource(rec.Audience)}
	}
	return lookupResult{
		view: TokenView{
			Type:         TokenTypeAccessToken,
			ClientID:     rec.ClientID,
			Subject:      rec.Subject,
			Scope:        append([]string(nil), rec.Scope...),
			Audience:     aud,
			ExpiresAt:    rec.ExpiresAt,
			Confirmation: cnf,
		},
	}, nil
}

// looksLikeJWS reports whether s has the three-part shape of a
// compact-serialised JWS.
func looksLikeJWS(s string) bool {
	if s == "" {
		return false
	}
	parts := strings.Split(s, ".")
	return len(parts) == 3 && parts[0] != "" && parts[1] != ""
}

// classifyVerifyErr maps a tokens.AccessTokenVerifier error onto a
// short audit reason string.
func classifyVerifyErr(err error) string {
	switch {
	case errors.Is(err, tokens.ErrAccessTokenExpired):
		return "expired"
	case errors.Is(err, tokens.ErrAccessTokenSignature):
		return "signature"
	case errors.Is(err, tokens.ErrAccessTokenMalformed):
		return "malformed"
	case errors.Is(err, tokens.ErrAccessTokenTypeMismatch):
		return "typ_mismatch"
	default:
		return "verify_error"
	}
}

// confirmationFromCnf projects an RFC 7800 cnf claim onto the
// internal Confirmation shape.
func confirmationFromCnf(cnf map[string]string) *Confirmation {
	if len(cnf) == 0 {
		return nil
	}
	out := &Confirmation{}
	if v, ok := cnf["jkt"]; ok {
		out.JKT = v
	}
	if v, ok := cnf["x5t#S256"]; ok {
		out.X5tS256 = v
	}
	if out.JKT == "" && out.X5tS256 == "" {
		return nil
	}
	return out
}

// extractAct re-parses raw to pull the act claim object. The
// AccessTokenVerifier projects only the standard claim set onto
// AccessTokenClaims; the act payload rides as an extension claim.
func extractAct(raw string) map[string]any {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Fall back to standard encoding for tolerance.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var generic struct {
		Act json.RawMessage `json:"act"`
	}
	if err := json.Unmarshal(payload, &generic); err != nil {
		return nil
	}
	return extractActFromRaw(generic.Act)
}

// extractActFromRaw decodes a raw act JSON message into a
// map[string]any tree.
func extractActFromRaw(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normaliseAudience applies the RFC 8707 §2 canonicalisation rule to
// every entry of aud so [TokenView.Audience] carries the same
// normalised form the policy-facing godoc promises. A nil input
// yields nil so callers do not need to special-case the empty set.
func normaliseAudience(aud []string) []string {
	if len(aud) == 0 {
		return nil
	}
	out := make([]string, len(aud))
	for i, v := range aud {
		out[i] = normaliseResource(v)
	}
	return out
}

// decodeRequiredAudience handles the dual aud shape RFC 7519 §4.1.3
// mandates and rejects missing, empty, or malformed values.
func decodeRequiredAudience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("aud claim missing")
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return nil, errors.New("aud claim empty")
		}
		return []string{single}, nil
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err != nil {
		return nil, fmt.Errorf("aud claim malformed: %w", err)
	}
	if len(multi) == 0 {
		return nil, errors.New("aud claim empty")
	}
	for _, audience := range multi {
		if audience == "" {
			return nil, errors.New("aud claim contains an empty audience")
		}
	}
	return multi, nil
}

func decodeAndValidateIDTokenClaims(payload []byte, now time.Time) (idTokenClaims, []string, string, error) {
	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return idTokenClaims{}, nil, "malformed", fmt.Errorf("decode id_token claims: %w", err)
	}
	audience, err := decodeRequiredAudience(claims.AudienceRaw)
	if err != nil {
		return idTokenClaims{}, nil, "missing_claim", err
	}
	if err := validateIDTokenClaims(claims, audience, now); err != nil {
		return idTokenClaims{}, nil, classifyIDTokenClaimsErr(err), err
	}
	return claims, audience, "", nil
}

// validateIDTokenClaims enforces the OIDC Core 1.0 §2 required claim
// set and its time bounds. Token exchange cannot apply its mandatory
// source-token TTL cap unless exp is present and still in the future.
func validateIDTokenClaims(claims idTokenClaims, audience []string, now time.Time) error {
	switch {
	case claims.Issuer == "":
		return errors.New("iss claim missing")
	case claims.Subject == "":
		return errors.New("sub claim missing")
	case len(audience) == 0:
		return errors.New("aud claim missing")
	case claims.ExpiresAt <= 0:
		return errors.New("exp claim missing")
	case claims.IssuedAt <= 0:
		return errors.New("iat claim missing")
	case len(audience) > 1 && claims.AuthorizedParty == "":
		return errors.New("azp claim missing for multiple audiences")
	}
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	if !now.Before(expiresAt) {
		return errIDTokenExpired
	}
	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	if issuedAt.After(now) {
		return errors.New("iat claim is in the future")
	}
	if !issuedAt.Before(expiresAt) {
		return errors.New("exp claim does not follow iat")
	}
	return nil
}

func classifyIDTokenClaimsErr(err error) string {
	if errors.Is(err, errIDTokenExpired) {
		return "expired"
	}
	return "missing_claim"
}

// idTokenClaims is the minimal projection of the OIDC Core 1.0 §2
// id_token claim set the lookup needs.
type idTokenClaims struct {
	Issuer          string            `json:"iss"`
	Subject         string            `json:"sub"`
	AudienceRaw     json.RawMessage   `json:"aud"`
	AuthorizedParty string            `json:"azp"`
	ClientID        string            `json:"client_id"`
	IssuedAt        int64             `json:"iat"`
	ExpiresAt       int64             `json:"exp"`
	Scope           string            `json:"scope"`
	Confirmation    map[string]string `json:"cnf"`
	Act             json.RawMessage   `json:"act"`
}
