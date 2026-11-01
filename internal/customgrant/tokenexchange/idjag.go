package tokenexchange

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// idjagTokenTypeNA is the token_type an ID-JAG is answered with: it is
// not an access token, so RFC 8693 §2.2.1 "N_A" applies even under DPoP.
const idjagTokenTypeNA = "N_A"

// maxIDJAGTTL caps the ID-JAG lifetime; it is also the lifetime a policy
// that states none receives. It is the exp bound the redeeming side
// enforces.
const maxIDJAGTTL = clientauth.MaxAssertionLifetime

// idjagJTIBytes is the jti entropy, the same 128 bits the OP's other
// opaque identifiers carry.
const idjagJTIBytes = 16

// idjagInput is the request shape the ID-JAG branch has validated before
// the policy runs.
type idjagInput struct {
	subjectRaw string
	audience   string
	resource   []string
	scope      []string
}

// handleIDJAG issues an ID-JAG for requested_token_type
// [TokenTypeIDJAG]. Scope, audience and resource name the audience
// authorization server's namespace, so none of the access-token
// exchange's checks against the client's own registration run here;
// the policy is the only gate on them.
func (h *Handler) handleIDJAG(ctx context.Context, req customgrant.Request) (customgrant.Response, error) {
	// draft §4.3.3: the IdP MUST authenticate the client.
	if clientauth.IsPublicClient(req.Client) {
		return customgrant.Response{}, invalidClient("ID-JAG issuance requires client authentication")
	}
	in, err := parseIDJAGForm(req)
	if err != nil {
		return customgrant.Response{}, err
	}
	result, err := h.lookupToken(ctx, in.subjectRaw, TokenTypeIDToken)
	if err != nil {
		return customgrant.Response{}, h.translateLookupErr(ctx, req.Client, err, result, true)
	}
	subjectView := result.view
	if err := requireIDTokenAudience(req.Client.ID, subjectView); err != nil {
		return customgrant.Response{}, err
	}
	if err := requireMatchingSenderConstraint(req, subjectView); err != nil {
		return customgrant.Response{}, err
	}
	lineage, err := h.grantLineage(ctx, req.Client, subjectView)
	if err != nil {
		return customgrant.Response{}, err
	}
	decision, policyErr := h.idjagPolicy(ctx, IDJAGRequest{
		Client:   req.Client,
		Subject:  subjectView.Subject,
		Audience: in.audience,
		Resource: slices.Clone(in.resource),
		Scope:    slices.Clone(in.scope),
	})
	if err := h.checkIDJAGDecision(ctx, req.Client, subjectView.Subject, in, decision, policyErr); err != nil {
		return customgrant.Response{}, err
	}
	ttl := decision.TTL
	if ttl <= 0 || ttl > maxIDJAGTTL {
		ttl = maxIDJAGTTL
	}
	jti, err := keys.RandomBase64URL(idjagJTIBytes)
	if err != nil {
		return customgrant.Response{}, serverError()
	}
	now := h.now()
	claims := h.idjagClaims(req, in, subjectView, decision, jti, now, ttl)
	signed, err := tokens.SignTypedJWT(tokens.FromInternalEntry(h.keys.Active()), jose.TypIDJAG, claims)
	if err != nil {
		return customgrant.Response{}, serverError()
	}
	resp := customgrant.Response{
		AccessToken:     signed,
		AccessTokenTTL:  ttl,
		TokenType:       idjagTokenTypeNA,
		IssuedTokenType: TokenTypeIDJAG,
		Subject:         subjectView.Subject,
		Scope:           slices.Clone(decision.Scope),
	}
	if lineage != nil {
		resp.GrantID, resp.GrantSubject = lineage.ID, lineage.Subject
	}
	clientID, subject := clientIDOf(req.Client), subjectView.Subject
	extras := map[string]any{
		"audience":      in.audience,
		"aud_client_id": decision.ClientID,
		"granted_scope": slices.Clone(decision.Scope),
		"resource":      slices.Clone(decision.Resource),
		"ttl_seconds":   int64(ttl.Seconds()),
		"jti":           jti,
	}
	resp.OnIssued = func(ctx context.Context, _ bool) {
		h.emit(ctx, auditIDJAGIssued, audit.LevelInfo, "token-exchange ID-JAG issued", clientID, subject, extras)
	}
	return resp, nil
}

// parseIDJAGForm validates the request parameters the ID-JAG branch
// accepts: an id_token subject_token, exactly one audience, optional
// resource values, and no actor_token.
func parseIDJAGForm(req customgrant.Request) (idjagInput, error) {
	if _, ok := req.Form["actor_token"]; ok {
		return idjagInput{}, invalidRequest("actor_token is not supported for ID-JAG issuance")
	}
	if _, ok := req.Form["actor_token_type"]; ok {
		return idjagInput{}, invalidRequest("actor_token_type is not supported for ID-JAG issuance")
	}
	subjectRaw, err := requireFormSingle(req.Form, "subject_token")
	if err != nil {
		return idjagInput{}, err
	}
	subjectType, err := requireFormSingle(req.Form, "subject_token_type")
	if err != nil {
		return idjagInput{}, err
	}
	if subjectType != TokenTypeIDToken {
		return idjagInput{}, invalidRequest("ID-JAG issuance requires an id_token subject_token")
	}
	audience, err := requireFormSingle(req.Form, "audience")
	if err != nil {
		return idjagInput{}, err
	}
	var resource []string
	for _, v := range req.Form["resource"] {
		if v != "" {
			resource = append(resource, v)
		}
	}
	return idjagInput{
		subjectRaw: subjectRaw,
		audience:   audience,
		resource:   resource,
		scope:      slices.Clone(req.RequestedScope),
	}, nil
}

// checkIDJAGDecision maps the policy outcome onto the wire: the two
// sentinels and a nil decision are the policy's refusals, anything else
// it returns that the OP cannot issue is the policy's defect.
func (h *Handler) checkIDJAGDecision(ctx context.Context, client *store.Client, subject string, in idjagInput, decision *IDJAGDecision, err error) error {
	clientID := clientIDOf(client)
	switch {
	case errors.Is(err, ErrIDJAGUnknownAudience):
		h.emit(ctx, auditPolicyDenied, audit.LevelInfo, "token-exchange ID-JAG audience unknown",
			clientID, subject, map[string]any{"reason": "unknown_audience", "audience": in.audience})
		return invalidTarget("audience is not a known authorization server")
	case errors.Is(err, ErrIDJAGDenied), err == nil && decision == nil:
		h.emit(ctx, auditPolicyDenied, audit.LevelInfo, "token-exchange ID-JAG denied",
			clientID, subject, map[string]any{"reason": "denied", "audience": in.audience})
		return accessDenied("ID-JAG issuance denied")
	case err != nil:
		h.emit(ctx, auditPolicyError, audit.LevelError, "token-exchange ID-JAG policy error",
			clientID, subject, map[string]any{"cause": err.Error()})
		return serverError()
	}
	reason := ""
	switch {
	case decision.ClientID == "":
		reason = "empty_client_id"
	case !resourceSubset(decision.Resource, in.resource):
		reason = "resource_not_requested"
	}
	if reason != "" {
		h.emit(ctx, auditPolicyError, audit.LevelError, "token-exchange ID-JAG policy returned an unusable decision",
			clientID, subject, map[string]any{"cause": reason})
		return serverError()
	}
	if len(in.resource) > 0 && len(decision.Resource) == 0 {
		h.emit(ctx, auditPolicyDenied, audit.LevelInfo, "token-exchange ID-JAG resource not granted",
			clientID, subject, map[string]any{"reason": "resource_not_granted", "requested": in.resource})
		return invalidTarget("none of the requested resources was granted")
	}
	return nil
}

// resourceSubset reports whether every granted value is one of the
// requested values, compared verbatim: the ID-JAG carries the strings
// the client sent, in the audience's namespace.
func resourceSubset(granted, requested []string) bool {
	for _, g := range granted {
		if !slices.Contains(requested, g) {
			return false
		}
	}
	return true
}

// idjagClaims builds the draft §3.1 claim set. cnf follows the request
// binding with one method only (§9.11): jkt when a DPoP proof was
// presented, otherwise x5t#S256.
func (h *Handler) idjagClaims(req customgrant.Request, in idjagInput, subjectView TokenView, decision *IDJAGDecision, jti string, now time.Time, ttl time.Duration) map[string]any {
	claims := map[string]any{
		"iss":       h.issuer,
		"sub":       subjectView.Subject,
		"aud":       in.audience,
		"client_id": decision.ClientID,
		"jti":       jti,
		"iat":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
	}
	if len(decision.Scope) > 0 {
		claims["scope"] = strings.Join(decision.Scope, " ")
	}
	if len(decision.Resource) == 1 {
		claims["resource"] = decision.Resource[0]
	} else if len(decision.Resource) > 1 {
		claims["resource"] = slices.Clone(decision.Resource)
	}
	if decision.Email != "" {
		claims["email"] = decision.Email
	}
	if !subjectView.AuthTime.IsZero() {
		claims["auth_time"] = subjectView.AuthTime.Unix()
	}
	acr, amr := idTokenAuthContext(in.subjectRaw)
	if acr != "" {
		claims["acr"] = acr
	}
	if len(amr) > 0 {
		claims["amr"] = amr
	}
	if cnf := idjagConfirmation(req); cnf != nil {
		claims["cnf"] = cnf
	}
	return claims
}

// idjagConfirmation narrows the request binding [buildCnfClaim] yields to
// a single confirmation method, DPoP first as token_type selection does.
func idjagConfirmation(req customgrant.Request) map[string]string {
	cnf := buildCnfClaim(req)
	if jkt, ok := cnf[tokens.CnfJKT]; ok {
		return map[string]string{tokens.CnfJKT: jkt}
	}
	return cnf
}

// idTokenAuthContext reads acr and amr off an id_token payload the lookup
// has already verified; the lookup's claim projection does not carry them.
func idTokenAuthContext(raw string) (string, []string) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil
	}
	var c struct {
		ACR string   `json:"acr"`
		AMR []string `json:"amr"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", nil
	}
	return c.ACR, c.AMR
}
