package tokenexchange

import (
	"context"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// reservedClaims are the protocol-managed names a handler-supplied
// ExtraClaims map MUST NOT carry. The token-exchange handler builds
// its own act chain and cnf binding; an embedder-injected act or cnf
// would otherwise undermine the chain's structural unforgeability and
// the RFC 9449 / RFC 8705 sender-constraint pin.
//
//nolint:gochecknoglobals // closed catalog; immutable.
var reservedClaims = map[string]struct{}{
	"iss":       {},
	"sub":       {},
	"aud":       {},
	"iat":       {},
	"exp":       {},
	"auth_time": {},
	"nonce":     {},
	"acr":       {},
	"amr":       {},
	"azp":       {},
	"at_hash":   {},
	"c_hash":    {},
	"sid":       {},
	"act":       {},
	"cnf":       {},
}

// Config bundles the dependencies the handler needs. The op-side
// adapter constructs the value once at provider build time.
type Config struct {
	// Policy is the embedder-supplied admission hook. Required; a nil
	// value is rejected at op.New construction time.
	Policy PolicyFunc

	// Issuer is the OP issuer URL. The handler uses it both as the
	// pin against subject_token / actor_token "iss" claims (external-
	// issuer rejection) and as the value the issued token will carry.
	Issuer string

	// Keys is the OP signing key set. The handler uses the public
	// material to verify subject_token / actor_token JWS shapes.
	Keys *keys.Set

	// AccessTokens is the JWT access-token registry. When non-nil the
	// lookup path consults it to reject revoked JTIs even when the
	// JWS verifies cleanly.
	AccessTokens store.AccessTokenRegistry

	// GrantRevocations is the grant-tombstone store consulted when
	// RevocationStrategy is RevocationStrategyGrantTombstone. When nil,
	// the lookup path falls back to the JTI registry for the legacy
	// migration window.
	GrantRevocations store.GrantRevocationStore

	// RevocationStrategy selects how JWT access-token revocation is
	// checked for subject_token / actor_token lookup.
	RevocationStrategy store.AccessTokenRevocationStrategy

	// OpaqueAccessTokens is the opaque AT substore. When non-nil the
	// lookup path falls back onto it for subject_token values that do
	// not parse as a JWS.
	OpaqueAccessTokens store.OpaqueAccessTokenStore

	// Grants is the persisted-consent substore. It is the scope source
	// for an id_token subject_token, which carries no scope claim of
	// its own, and the revocation gate on that path. A nil value leaves
	// id_token subject tokens unexchangeable; access-token and JWT
	// subject tokens are unaffected.
	Grants store.GrantStore

	// Clients is the read-only client registry. The lookup path uses it
	// to reject a JWT subject_token whose client has been deleted; a
	// deletion leaves no grant IDs to tombstone and a client_credentials
	// token has no grant at all, so the client_id claim is the only
	// handle either case shares. A nil value disables that check.
	Clients store.ClientStore

	// Audit is the structured audit-event sink.
	Audit audit.Emitter

	// Clock supplies the wall-clock reading; nil falls back to the
	// system clock through internal/timex.SystemClock.
	Clock interface{ Now() time.Time }

	// MaxAccessTTL is the global access-token cap the handler applies
	// to the issued token's lifetime alongside the subject-token
	// remaining and handler-requested bounds.
	MaxAccessTTL time.Duration

	// Leeway is the symmetric tolerance the subject-token / actor-token
	// verifier applies to the "exp" and "iat" comparisons. Zero falls
	// back to [tokens.DefaultLeeway], which is the same value
	// /userinfo, /introspect and /revoke resolve to.
	//
	// The agreement is the point. A subject_token presented here is an
	// access token the RP could equally have presented to any of those
	// three, and its validity belongs to the token rather than to the
	// endpoint reading it — so a narrower tolerance here would make
	// exchange the one surface that rejects a token every other surface
	// still honours, on exactly the clock skew the tolerance exists to
	// absorb.
	Leeway time.Duration
}

// Handler is the customgrant.Handler implementation. It is
// constructed by [New]; the zero value is not usable.
type Handler struct {
	policy             PolicyFunc
	issuer             string
	keys               *keys.Set
	accessTokens       store.AccessTokenRegistry
	grantRevocations   store.GrantRevocationStore
	revocationStrategy store.AccessTokenRevocationStrategy
	opaqueAccessTokens store.OpaqueAccessTokenStore
	grants             store.GrantStore
	clients            store.ClientStore
	audit              audit.Emitter
	clock              interface{ Now() time.Time }
	maxAccessTTL       time.Duration
	leeway             time.Duration
}

// New constructs a Handler from cfg. Construction-time invariants
// surface here: a nil policy yields an error so the op layer can
// fail op.New rather than panic at request time.
func New(cfg Config) (*Handler, error) {
	if cfg.Policy == nil {
		return nil, errors.New("tokenexchange: nil policy")
	}
	if cfg.Keys == nil {
		return nil, errors.New("tokenexchange: nil keyset")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("tokenexchange: empty issuer")
	}
	leeway := cfg.Leeway
	if leeway <= 0 {
		leeway = tokens.DefaultLeeway
	}
	return &Handler{
		policy:             cfg.Policy,
		issuer:             cfg.Issuer,
		keys:               cfg.Keys,
		accessTokens:       cfg.AccessTokens,
		grantRevocations:   cfg.GrantRevocations,
		revocationStrategy: cfg.RevocationStrategy,
		opaqueAccessTokens: cfg.OpaqueAccessTokens,
		grants:             cfg.Grants,
		clients:            cfg.Clients,
		audit:              cfg.Audit,
		clock:              cfg.Clock,
		maxAccessTTL:       cfg.MaxAccessTTL,
		leeway:             leeway,
	}, nil
}

// now returns the current wall-clock reading.
func (h *Handler) now() time.Time {
	if h.clock == nil {
		return timex.SystemClock.Now()
	}
	return h.clock.Now()
}

// Name implements customgrant.Handler.
func (h *Handler) Name() string { return GrantType }

// ParamPolicy implements customgrant.Handler. The token-exchange
// parameter set comes from RFC 8693 §2.1; only audience and resource
// admit duplicates because every other parameter is single-valued
// (and several are credential-shaped).
func (h *Handler) ParamPolicy() customgrant.ParamPolicy {
	return customgrant.ParamPolicy{
		Allowed: []string{
			"subject_token",
			"subject_token_type",
			"actor_token",
			"actor_token_type",
			"requested_token_type",
			"audience",
			"resource",
		},
		DupesAllowed: []string{"audience", "resource"},
	}
}

// Handle implements customgrant.Handler. The function orchestrates
// the full state machine documented in the package doc; the heavy
// lifting lives in the helpers below so each phase stays focused.
func (h *Handler) Handle(ctx context.Context, req customgrant.Request) (customgrant.Response, error) {
	subjectView, actorView, err := h.parseAndVerify(ctx, req)
	if err != nil {
		return customgrant.Response{}, err
	}
	requestedAudience := computeRequestedAudience(req.Form, subjectView)
	requestedScope := h.resolveRequestedScope(req, subjectView)
	h.emitRequestedAudit(ctx, req.Client, subjectView, actorView, requestedAudience, requestedScope)
	if err := h.enforceScopeAudience(ctx, req.Client, subjectView, requestedScope, requestedAudience); err != nil {
		return customgrant.Response{}, err
	}
	decision, err := h.policy(ctx, RequestView{
		Client:            req.Client,
		Subject:           subjectView.Subject,
		SubjectToken:      subjectView,
		Actor:             actorSubOf(actorView),
		ActorToken:        actorView,
		RequestedAudience: requestedAudience,
		RequestedScope:    requestedScope,
		DPoPJKT:           req.DPoPJKT,
		DPoPJTI:           req.DPoPJTI,
		MTLSCert:          req.MTLSCert,
	})
	if err != nil {
		return customgrant.Response{}, h.translatePolicyErr(ctx, req.Client, subjectView.Subject, err)
	}
	return h.buildResponse(ctx, req, subjectView, actorView, requestedScope, requestedAudience, decision)
}

// parseAndVerify executes the structural validation and token lookup
// phase. Steps 1-7 of the state machine — form-shape checks, token
// verification, actor/subject distinctness — collapse to one helper
// the orchestrator can call before any audience or scope work begins.
//
//nolint:gocognit // parseAndVerify enumerates the RFC 8693 §2.1 subject/actor token gates in flat shape; refactor would obscure spec mapping.
func (h *Handler) parseAndVerify(ctx context.Context, req customgrant.Request) (TokenView, *TokenView, error) {
	if err := validateRequestedTokenType(req.Form); err != nil {
		return TokenView{}, nil, err
	}
	subjectRaw, err := requireFormSingle(req.Form, "subject_token")
	if err != nil {
		return TokenView{}, nil, err
	}
	subjectType, err := requireFormSingle(req.Form, "subject_token_type")
	if err != nil {
		return TokenView{}, nil, err
	}
	if !knownTokenType(subjectType) {
		return TokenView{}, nil, invalidRequest("subject_token_type is not recognised")
	}
	actorRaw, actorType, err := extractActorToken(req.Form)
	if err != nil {
		return TokenView{}, nil, err
	}
	subjectResult, err := h.lookupToken(ctx, subjectRaw, subjectType)
	if err != nil {
		return TokenView{}, nil, h.translateLookupErr(ctx, req.Client, err, subjectResult, true)
	}
	subjectView := subjectResult.view
	if err := requireIDTokenAudience(req.Client.ID, subjectView); err != nil {
		return TokenView{}, nil, err
	}
	if err := requireMatchingSenderConstraint(req, subjectView); err != nil {
		return TokenView{}, nil, err
	}
	var actorView *TokenView
	if actorRaw != "" {
		actorResult, aerr := h.lookupToken(ctx, actorRaw, actorType)
		if aerr != nil {
			return TokenView{}, nil, h.translateLookupErr(ctx, req.Client, aerr, actorResult, false)
		}
		v := actorResult.view
		if err := requireIDTokenAudience(req.Client.ID, v); err != nil {
			return TokenView{}, nil, err
		}
		if err := requireMatchingSenderConstraint(req, v); err != nil {
			return TokenView{}, nil, err
		}
		actorView = &v
	}
	if actorView != nil && actorView.Subject == subjectView.Subject {
		h.emit(ctx, auditActorEqualsSubject, audit.LevelInfo,
			"token-exchange rejected: actor equals subject",
			clientIDOf(req.Client), subjectView.Subject, nil)
		return TokenView{}, nil, invalidRequest("actor_token resolves to the same subject as subject_token")
	}
	return subjectView, actorView, nil
}

// resolveRequestedScope returns the post-default-fill, post-client-
// intersection scope set the policy will see. The dispatcher pre-
// parses the form's "scope" field onto [customgrant.Request.RequestedScope]
// so handlers do not duplicate the splitter; an empty value falls back
// to the subject_token's scope per RFC 8693 §2.1.
func (h *Handler) resolveRequestedScope(req customgrant.Request, subjectView TokenView) []string {
	requested := req.RequestedScope
	if len(requested) == 0 {
		requested = append([]string(nil), subjectView.Scope...)
	}
	return intersectScope(requested, req.Client.Scopes)
}

// emitRequestedAudit fires the entry-side audit event after the
// structural checks pass but before any policy decision runs, so the
// audit chain captures every attempt that survived parse-time gates.
func (h *Handler) emitRequestedAudit(ctx context.Context, client *store.Client, subjectView TokenView, actorView *TokenView, requestedAudience, requestedScope []string) {
	h.emit(ctx, auditRequested, audit.LevelInfo,
		"token-exchange requested",
		clientIDOf(client), subjectView.Subject,
		map[string]any{
			"actor":              actorSubOf(actorView),
			"requested_audience": append([]string(nil), requestedAudience...),
			"requested_scope":    append([]string(nil), requestedScope...),
		})
}

// enforceScopeAudience runs the cross-cutting downscope checks that
// every exchange must clear regardless of the policy decision: scope
// must subset the subject_token's scope, audience must subset the
// client's registered resources.
func (h *Handler) enforceScopeAudience(ctx context.Context, client *store.Client, subjectView TokenView, requestedScope, requestedAudience []string) error {
	if !scopeSubset(requestedScope, subjectView.Scope) {
		h.emit(ctx, auditScopeInflationBlocked, audit.LevelWarn,
			"token-exchange rejected: requested scope inflates beyond subject_token",
			clientIDOf(client), subjectView.Subject,
			map[string]any{
				"requested": requestedScope,
				"original":  subjectView.Scope,
			})
		return invalidScope("requested scope exceeds the subject_token's scope")
	}
	if !audienceAllowed(requestedAudience, client) {
		h.emit(ctx, auditAudienceBlocked, audit.LevelWarn,
			"token-exchange rejected: requested audience not in client allowlist",
			clientIDOf(client), subjectView.Subject,
			map[string]any{
				"requested": requestedAudience,
				"allowed":   append([]string(nil), client.Resources...),
			})
		return invalidTarget("requested audience contains entries the client is not authorized for")
	}
	return nil
}

// buildResponse executes the post-policy phase: decision merge, scope
// gate, TTL cap, act chain construction, response shape. Errors from
// the act-chain gate (depth > 5) and the empty-scope gate ride through
// here so the orchestrator can return them as wire errors.
func (h *Handler) buildResponse(ctx context.Context, req customgrant.Request, subjectView TokenView, actorView *TokenView, requestedScope, requestedAudience []string, decision *Decision) (customgrant.Response, error) {
	grantedScope, grantedAudience, grantedTTL, issueIDToken, issueRefresh, extraClaims := applyDecision(
		decision, requestedScope, requestedAudience, subjectView.Type == TokenTypeIDToken,
	)
	if len(grantedScope) == 0 {
		h.emit(ctx, auditEmptyScopeRejected, audit.LevelWarn,
			"token-exchange rejected: empty scope after downscope",
			clientIDOf(req.Client), subjectView.Subject, nil)
		return customgrant.Response{}, invalidScope("granted scope cannot be empty")
	}
	// RFC 8693 §2.1 — a policy decision may only narrow, never broaden.
	// The granted scope MUST remain a subset of the subject-bounded
	// requested scope and the granted audience MUST remain a subset of
	// the RFC 8707-normalised requested audience; a policy that returns
	// a broader set is a privilege escalation and is rejected here.
	if !scopeSubset(grantedScope, requestedScope) {
		h.emit(ctx, auditScopeInflationBlocked, audit.LevelWarn,
			"token-exchange rejected: policy granted scope inflates beyond requested scope",
			clientIDOf(req.Client), subjectView.Subject,
			map[string]any{
				"granted":   grantedScope,
				"requested": requestedScope,
			})
		return customgrant.Response{}, invalidScope("granted scope exceeds the requested scope")
	}
	if !audienceSubset(grantedAudience, requestedAudience) {
		h.emit(ctx, auditAudienceBlocked, audit.LevelWarn,
			"token-exchange rejected: policy granted audience inflates beyond requested audience",
			clientIDOf(req.Client), subjectView.Subject,
			map[string]any{
				"granted":   grantedAudience,
				"requested": requestedAudience,
			})
		return customgrant.Response{}, invalidTarget("granted audience exceeds the requested audience")
	}
	if subjectView.ExpiresAt.IsZero() || !h.now().Before(subjectView.ExpiresAt) {
		return customgrant.Response{}, invalidGrant("subject_token has no positive remaining lifetime")
	}
	ttl, ttlReason := h.computeTTL(grantedTTL, subjectView.ExpiresAt)
	if ttlReason != "" {
		h.emit(ctx, auditTTLCapped, audit.LevelInfo,
			"token-exchange TTL capped",
			clientIDOf(req.Client), subjectView.Subject,
			map[string]any{
				"requested": grantedTTL.Seconds(),
				"granted":   ttl.Seconds(),
				"reason":    ttlReason,
			})
	}
	actChain, depth := buildActChain(subjectView, actorView, req.Client.ID)
	if depth > MaxActChainDepth {
		h.emit(ctx, auditActChainTooDeep, audit.LevelWarn,
			"token-exchange rejected: act chain exceeds maximum depth",
			clientIDOf(req.Client), subjectView.Subject,
			map[string]any{"depth": depth, "max": MaxActChainDepth})
		return customgrant.Response{}, invalidGrant("act chain depth exceeds the maximum permitted")
	}
	if actorView == nil && req.Client.ID == subjectView.ClientID {
		h.emit(ctx, auditSelfExchange, audit.LevelInfo,
			"token-exchange self-exchange detected",
			clientIDOf(req.Client), subjectView.Subject,
			map[string]any{"audience": grantedAudience})
	}
	resp := h.assembleResponse(req, subjectView, grantedScope, grantedAudience, ttl, actChain, extraClaims, issueIDToken)
	if issueRefresh {
		// The handler signals intent only; the OP mints and persists
		// the refresh token on the shared custom-grant path so it
		// rides the rotation / replay-cascade / cnf-binding lineage.
		resp.IssueRefreshToken = true
		h.emit(ctx, auditRefreshIssued, audit.LevelInfo,
			"token-exchange refresh token issuance requested",
			clientIDOf(req.Client), subjectView.Subject,
			map[string]any{
				"actor":    actorSubOf(actorView),
				"audience": grantedAudience,
			})
	}
	h.emit(ctx, auditGranted, audit.LevelInfo,
		"token-exchange granted",
		clientIDOf(req.Client), subjectView.Subject,
		map[string]any{
			"actor":            actorSubOf(actorView),
			"granted_audience": grantedAudience,
			"granted_scope":    grantedScope,
			"ttl_seconds":      int64(ttl.Seconds()),
			"act_chain_depth":  depth,
		})
	return resp, nil
}

// assembleResponse builds the customgrant.Response shape with the
// BoundAccessToken bundle the dispatcher stamps cnf onto, plus the
// optional id_token claim merge so the OP-built act chain rides on
// both tokens regardless of which the resource server inspects.
func (h *Handler) assembleResponse(req customgrant.Request, subjectView TokenView, grantedScope, grantedAudience []string, ttl time.Duration, actChain, extraClaims map[string]any, issueIDToken bool) customgrant.Response {
	mergedExtras := filterReservedClaims(extraClaims)
	if actChain != nil {
		mergedExtras["act"] = actChain
	}
	boundAud := append([]string(nil), grantedAudience...)
	if len(boundAud) == 0 {
		boundAud = []string{req.Client.ID}
	}
	resp := customgrant.Response{
		BoundAccessToken: &customgrant.BoundAccessToken{
			Subject:     subjectView.Subject,
			Audience:    boundAud,
			TTL:         ttl,
			ExtraClaims: mergedExtras,
		},
		AccessTokenTTL: ttl,
		Subject:        subjectView.Subject,
		Scope:          append([]string(nil), grantedScope...),
		Audience:       append([]string(nil), grantedAudience...),
	}
	if issueIDToken && containsOpenID(grantedScope) {
		resp.AuthTime = h.now()
		idClaims := filterReservedClaims(extraClaims)
		if actChain != nil {
			if idClaims == nil {
				idClaims = make(map[string]any)
			}
			idClaims["act"] = actChain
		}
		// RFC 9449 §6.1 / RFC 8705 §3 — when the request is sender-
		// constrained the issued id_token MUST carry the same cnf
		// claim the access_token does, so a resource server that
		// validates id_token-side proof-of-possession sees the matching
		// key. The wire layer stamps cnf onto the access_token
		// automatically (tokenBinding.confirmation); the id_token claim
		// map is owned by the handler so we mirror the rule here.
		if cnf := buildCnfClaim(req); cnf != nil {
			if idClaims == nil {
				idClaims = make(map[string]any)
			}
			idClaims["cnf"] = cnf
		}
		resp.ExtraClaims = idClaims
	}
	return resp
}

// translateLookupErr maps an errExternalIssuer / errTokenInvalid
// onto the right audit event and a wire error. Both classes surface
// as invalid_grant on the wire — the wire shape MUST stay collapsed
// so an attacker cannot probe for a known token via the audit channel —
// but a transient registry / opaque-store fault is emitted on a
// dedicated audit event so SOC tooling can distinguish it from an
// actual revocation. The wire response is invalid_grant in both cases.
func (h *Handler) translateLookupErr(ctx context.Context, client *store.Client, err error, result lookupResult, isSubject bool) error {
	switch {
	case errors.Is(err, errExternalIssuer):
		event := auditSubjectTokenExternal
		msg := "token-exchange rejected: subject_token issued by external issuer"
		if !isSubject {
			event = auditActorTokenExternal
			msg = "token-exchange rejected: actor_token issued by external issuer"
		}
		h.emit(ctx, event, audit.LevelInfo, msg,
			clientIDOf(client), "",
			map[string]any{"detected_issuer": result.reason})
		return invalidGrant("token issuer not recognised")
	case errors.Is(err, errTokenInvalid):
		if isRegistryFaultReason(result.reason) {
			h.emit(ctx, auditSubjectTokenRegistryError, audit.LevelWarn,
				"token-exchange rejected: subject_token registry observation failed",
				clientIDOf(client), "",
				map[string]any{"reason": result.reason, "is_subject": isSubject})
			return invalidGrant("token failed verification")
		}
		h.emit(ctx, auditSubjectTokenInvalid, audit.LevelInfo,
			"token-exchange rejected: subject_token failed verification",
			clientIDOf(client), "",
			map[string]any{"reason": result.reason, "is_subject": isSubject})
		return invalidGrant("token failed verification")
	default:
		return invalidGrant("token failed verification")
	}
}

// isRegistryFaultReason reports whether the lookup classifier produced
// a reason that names a transient registry / opaque-store fault rather
// than an actual revocation, expiry, or signature mismatch. The set
// agrees with the reason strings lookup.go writes when the registry
// or opaque substore returns a non-ErrNotFound error.
func isRegistryFaultReason(reason string) bool {
	switch reason {
	case "registry_error", "store_error":
		return true
	default:
		return false
	}
}

// translatePolicyErr handles the two policy-error paths: a typed op
// error rides through verbatim (caller decides the wire shape), a
// generic Go error collapses to invalid_grant.
func (h *Handler) translatePolicyErr(ctx context.Context, client *store.Client, subject string, err error) error {
	if isOpError(err) {
		h.emit(ctx, auditPolicyDenied, audit.LevelInfo,
			"token-exchange policy denied",
			clientIDOf(client), subject,
			map[string]any{"reason": err.Error()})
		return err
	}
	h.emit(ctx, auditPolicyError, audit.LevelError,
		"token-exchange policy error",
		clientIDOf(client), subject,
		map[string]any{"cause": err.Error()})
	return invalidGrant("token-exchange policy denied the request")
}

// computeTTL returns the bounded TTL alongside the cap reason (empty
// when no cap applied).
func (h *Handler) computeTTL(requested time.Duration, subjectExpiresAt time.Time) (time.Duration, string) {
	now := h.now()
	if requested <= 0 {
		requested = h.maxAccessTTL
	}
	out := requested
	reason := ""
	subjRemaining := subjectExpiresAt.Sub(now)
	if subjRemaining > 0 && subjRemaining < out {
		out = subjRemaining
		reason = "subject_token_remaining"
	}
	if h.maxAccessTTL > 0 && out > h.maxAccessTTL {
		out = h.maxAccessTTL
		reason = "global_ceiling"
	}
	if requested > 0 && out < requested && reason == "" {
		reason = "handler_request"
	}
	return out, reason
}

// validateRequestedTokenType rejects requested_token_type values
// other than access_token (or absent).
func validateRequestedTokenType(form map[string][]string) error {
	values, ok := form["requested_token_type"]
	if !ok || len(values) == 0 {
		return nil
	}
	if len(values) > 1 {
		return invalidRequest("requested_token_type must be a single value")
	}
	if values[0] != "" && values[0] != TokenTypeAccessToken {
		return invalidRequest("requested_token_type is not supported")
	}
	return nil
}

// requireFormSingle extracts the single-valued form parameter named
// by key; an absent or multi-valued entry yields invalid_request.
func requireFormSingle(form map[string][]string, key string) (string, error) {
	values, ok := form[key]
	if !ok || len(values) == 0 || values[0] == "" {
		return "", invalidRequest(key + " is required")
	}
	if len(values) > 1 {
		return "", invalidRequest(key + " must be a single value")
	}
	return values[0], nil
}

// extractActorToken pulls the actor_token + actor_token_type pair.
// Returns (raw, urn, nil) when both present, ("", "", nil) when both
// absent, or an error when only one is present.
func extractActorToken(form map[string][]string) (string, string, error) {
	rawValues, hasRaw := form["actor_token"]
	typeValues, hasType := form["actor_token_type"]
	if !hasRaw && !hasType {
		return "", "", nil
	}
	if hasRaw && !hasType {
		return "", "", invalidRequest("actor_token requires actor_token_type")
	}
	if !hasRaw && hasType {
		return "", "", invalidRequest("actor_token_type without actor_token")
	}
	if len(rawValues) != 1 || rawValues[0] == "" {
		return "", "", invalidRequest("actor_token must be a single non-empty value")
	}
	if len(typeValues) != 1 || typeValues[0] == "" {
		return "", "", invalidRequest("actor_token_type must be a single non-empty value")
	}
	if !knownTokenType(typeValues[0]) {
		return "", "", invalidRequest("actor_token_type is not recognised")
	}
	return rawValues[0], typeValues[0], nil
}

// knownTokenType reports whether urn names a token type the handler
// accepts.
func knownTokenType(urn string) bool {
	switch urn {
	case TokenTypeAccessToken, TokenTypeJWT, TokenTypeIDToken:
		return true
	default:
		return false
	}
}

// computeRequestedAudience folds the audience and resource form
// values together, normalises each per RFC 8707 §2, and de-duplicates.
// Falls back to the subject_token's audience (also normalised) when
// the request omits both parameters so downstream comparisons see a
// single canonical form.
func computeRequestedAudience(form map[string][]string, subject TokenView) []string {
	out := make([]string, 0, 4)
	for _, v := range form["audience"] {
		if v != "" {
			out = append(out, normaliseResource(v))
		}
	}
	for _, v := range form["resource"] {
		if v != "" {
			out = append(out, normaliseResource(v))
		}
	}
	if len(out) > 0 {
		return dedupe(out)
	}
	if len(subject.Audience) > 0 {
		fallback := make([]string, 0, len(subject.Audience))
		for _, v := range subject.Audience {
			fallback = append(fallback, normaliseResource(v))
		}
		return dedupe(fallback)
	}
	return nil
}

// applyDecision merges the policy decision over the OP defaults.
func applyDecision(d *Decision, requestedScope, requestedAudience []string, defaultIssueIDToken bool) (
	[]string, []string, time.Duration, bool, bool, map[string]any,
) {
	scope := append([]string(nil), requestedScope...)
	audience := append([]string(nil), requestedAudience...)
	var ttl time.Duration
	issueIDToken := defaultIssueIDToken
	issueRefresh := false
	var extras map[string]any
	if d == nil {
		return scope, audience, ttl, issueIDToken, issueRefresh, extras
	}
	if len(d.GrantedScope) > 0 {
		scope = append([]string(nil), d.GrantedScope...)
	}
	if len(d.GrantedAudience) > 0 {
		audience = append([]string(nil), d.GrantedAudience...)
	}
	if d.GrantedTTL > 0 {
		ttl = d.GrantedTTL
	}
	if d.IssueIDToken != nil {
		issueIDToken = *d.IssueIDToken
	}
	if d.IssueRefreshToken != nil {
		issueRefresh = *d.IssueRefreshToken
	}
	if len(d.ExtraClaims) > 0 {
		extras = make(map[string]any, len(d.ExtraClaims))
		for k, v := range d.ExtraClaims {
			extras[k] = v
		}
	}
	return scope, audience, ttl, issueIDToken, issueRefresh, extras
}

// audienceAllowed reports whether every entry of want appears in the
// client's Resources allowlist. Both sides are normalised per
// RFC 8707 §2 before the comparison so a client registering
// "https://api.example/" matches a request indicator
// "HTTPS://API.EXAMPLE/" — the canonical form is the equality test.
// An empty want vacuously passes; an empty client.Resources rejects
// every non-empty want (clients that want token-exchange-issuable
// audiences MUST register them explicitly).
func audienceAllowed(want []string, client *store.Client) bool {
	if len(want) == 0 {
		return true
	}
	if client == nil || len(client.Resources) == 0 {
		return false
	}
	idx := make(map[string]struct{}, len(client.Resources))
	for _, r := range client.Resources {
		idx[normaliseResource(r)] = struct{}{}
	}
	for _, v := range want {
		if _, ok := idx[normaliseResource(v)]; !ok {
			return false
		}
	}
	return true
}

// filterReservedClaims returns a fresh map carrying every entry of
// extras whose key is not in the reserved set.
func filterReservedClaims(extras map[string]any) map[string]any {
	out := make(map[string]any, len(extras))
	for k, v := range extras {
		if _, reserved := reservedClaims[k]; reserved {
			continue
		}
		out[k] = v
	}
	return out
}

// containsOpenID reports whether scope contains "openid".
func containsOpenID(scope []string) bool {
	for _, s := range scope {
		if s == "openid" {
			return true
		}
	}
	return false
}

// clientIDOf returns the client_id when client is non-nil; empty
// otherwise.
func clientIDOf(client *store.Client) string {
	if client == nil {
		return ""
	}
	return client.ID
}

// actorSubOf returns the actor's sub claim or empty when actor is
// nil. Threaded onto every audit event so SOC tooling can pivot
// between the subject and the actor without re-parsing extras.
func actorSubOf(actor *TokenView) string {
	if actor == nil {
		return ""
	}
	return actor.Subject
}

// oauthCoded is the structural interface the public op.Error type
// satisfies. Internal callers detect a typed wire error through this
// shape so the verbatim-preservation seam fires on every embedder
// error that carries an RFC 6749 §5.2 code without importing op/.
type oauthCoded interface {
	OAuthCode() string
}

// isOpError reports whether err satisfies [oauthCoded] with a
// non-empty code. The check rides on errors.As so a wrapper around
// the public op.Error keeps the verbatim path active.
func isOpError(err error) bool {
	if err == nil {
		return false
	}
	var coded oauthCoded
	if errors.As(err, &coded) {
		return coded.OAuthCode() != ""
	}
	return false
}
