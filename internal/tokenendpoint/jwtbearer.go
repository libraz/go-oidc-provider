package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/assertiongrant"
	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Audit event names for the jwt-bearer grant.
const (
	auditJWTBearerGranted  = string(auditevent.AuditJWTBearerGranted)
	auditJWTBearerRejected = string(auditevent.AuditJWTBearerRejected)
)

// Rejection reasons the token endpoint itself contributes to
// jwt_bearer.rejected, next to the verifier's stage names.
const (
	jwtBearerReasonPublicClient     = "public_client"
	jwtBearerReasonMissingAssertion = "missing_assertion"
	jwtBearerReasonClientNotAllowed = "client_not_allowed"
	jwtBearerReasonScope            = "scope"
	jwtBearerReasonResource         = "resource"
	jwtBearerReasonBinding          = "binding"
	jwtBearerReasonKeySource        = "key_source_unavailable" //nolint:gosec // G101: audit reason, not a credential.
	jwtBearerReasonVerifierFault    = "verifier_fault"         //nolint:gosec // G101: audit reason, not a credential.
	jwtBearerReasonUnknownSubject   = "unknown_subject"
	jwtBearerReasonResolverFault    = "resolver_fault"
	jwtBearerReasonSubjectNotLive   = "subject_not_live"
	jwtBearerReasonSubjectLookup    = "subject_lookup_fault"
	jwtBearerReasonIssuance         = "issuance_fault"
)

// jwtBearerRequest is the request state gathered before the assertion is
// verified. A request the client can fix never consumes the assertion's
// single-use jti: every such refusal runs before [assertiongrant.Verifier.Consume].
type jwtBearerRequest struct {
	client    *store.Client
	assertion string
	issuer    string
	requested []string
	resource  string
	binding   tokenBinding
}

// handleJWTBearer implements the RFC 7523 §2.1 jwt-bearer grant, with the
// ID-JAG profile enforced by the verifier per issuer. The access token is
// unbacked: no grant record, no refresh token, no id_token, the normal
// access-token TTL, and cnf stamped from the request's DPoP / mTLS binding.
func handleJWTBearer(w http.ResponseWriter, r *http.Request, deps Deps) {
	if deps.JWTBearer == nil || deps.ResolveAssertionSubject == nil || deps.JWTBearerAllowedClients == nil {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errUnsupportedGrantType,
			"grant_type is not supported")
		return
	}
	ctx := r.Context()
	req, ok := acceptJWTBearerRequest(ctx, w, r, deps)
	if !ok {
		return
	}
	result, ok := verifyJWTBearerAssertion(ctx, w, deps, req)
	if !ok {
		return
	}
	scope, resource, ok := narrowToAssertion(ctx, w, deps, req, result)
	if !ok {
		return
	}
	// Spent before the resolver runs, so a replay never reaches it.
	if err := deps.JWTBearer.Consume(ctx, result); err != nil {
		writeAssertionRejection(ctx, w, deps, req.client.ID, req.issuer, err)
		return
	}
	subject, ok := resolveJWTBearerSubject(ctx, w, deps, req, result)
	if !ok {
		return
	}
	issueJWTBearerResponse(ctx, w, deps, req, result, subject, scope, resource)
}

// acceptJWTBearerRequest runs every check that needs no verified assertion:
// client authentication and grant registration, the public-client refusal,
// the per-issuer client allow-list, the resource against the client's
// registration, and the request's sender constraint.
func acceptJWTBearerRequest(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
) (*jwtBearerRequest, bool) {
	dpopOut, client, ok := authenticateWithDPoP(ctx, w, r, deps, grantTypeJWTBearer)
	if !ok {
		return nil, false
	}
	// Same code as client_credentials' public-client refusal, so the wire
	// does not tell "public" apart from "not registered for the grant".
	if clientauth.IsPublicClient(client) {
		emitJWTBearerRejected(ctx, deps, client.ID, "", jwtBearerReasonPublicClient)
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errUnauthorizedClient,
			"client is not authorized for the jwt-bearer grant")
		return nil, false
	}
	raw := r.PostForm.Get("assertion")
	if raw == "" {
		emitJWTBearerRejected(ctx, deps, client.ID, "", jwtBearerReasonMissingAssertion)
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest, "assertion is required")
		return nil, false
	}
	issuer, ok := admitAssertionIssuer(ctx, w, deps, client, raw)
	if !ok {
		return nil, false
	}
	req := &jwtBearerRequest{client: client, assertion: raw, issuer: issuer}
	if !applyJWTBearerRequestScope(ctx, w, r, deps, req) {
		return nil, false
	}
	binding, _, ok := bindRequest(w, r, deps, client, dpopOut)
	if !ok {
		emitJWTBearerRejected(ctx, deps, client.ID, issuer, jwtBearerReasonBinding)
		return nil, false
	}
	req.binding = binding
	return req, true
}

// admitAssertionIssuer reads the assertion's unverified iss and applies the
// issuer's client allow-list before verification consumes the jti. An issuer
// without a list is not configured, which is an assertion defect
// (invalid_grant); a configured issuer that does not list the client is
// unauthorized_client.
func admitAssertionIssuer(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	raw string,
) (string, bool) {
	issuer, err := assertiongrant.PeekIssuer(raw)
	if err != nil {
		writeAssertionRejection(ctx, w, deps, client.ID, "", err)
		return "", false
	}
	allowed := deps.JWTBearerAllowedClients(issuer)
	if allowed == nil {
		emitJWTBearerRejected(ctx, deps, client.ID, issuer, string(assertiongrant.ReasonIssuer))
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant, "assertion is invalid")
		return "", false
	}
	if !slices.Contains(allowed, client.ID) {
		emitJWTBearerRejected(ctx, deps, client.ID, issuer, jwtBearerReasonClientNotAllowed)
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errUnauthorizedClient,
			"client is not authorized to redeem this issuer's assertions")
		return "", false
	}
	return issuer, true
}

// applyJWTBearerRequestScope parses the scope and resource parameters. A
// resource indicator must be registered for the client, and a requested
// scope must neither name "openid" (no id_token is issued) nor exceed the
// client's registered scopes; [narrowToAssertion] narrows the result once
// the assertion's own scope claim is known.
func applyJWTBearerRequestScope(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
	req *jwtBearerRequest,
) bool {
	requested, resource, ok := parseClientCredsRequest(w, r)
	if !ok {
		emitJWTBearerRejected(ctx, deps, req.client.ID, req.issuer, jwtBearerReasonResource)
		return false
	}
	if !validateClientCredsResource(w, req.client, resource) {
		emitJWTBearerRejected(ctx, deps, req.client.ID, req.issuer, jwtBearerReasonResource)
		return false
	}
	if oidcscope.ContainsOpenID(requested) {
		emitJWTBearerRejected(ctx, deps, req.client.ID, req.issuer, jwtBearerReasonScope)
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidScope,
			"openid scope is not permitted in the jwt-bearer grant")
		return false
	}
	if !requireRegisteredScopes(w, req.client, requested) {
		emitJWTBearerRejected(ctx, deps, req.client.ID, req.issuer, jwtBearerReasonScope)
		return false
	}
	req.requested, req.resource = requested, resource
	return true
}

// verifyJWTBearerAssertion runs the verifier, which leaves the jti unspent,
// and maps its outcome onto the wire: an assertion defect is invalid_grant, a transient issuer key-source
// outage is 503 as on the client_assertion path, anything else is
// server_error.
func verifyJWTBearerAssertion(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	req *jwtBearerRequest,
) (*assertiongrant.Result, bool) {
	result, err := deps.JWTBearer.Verify(ctx, req.assertion, assertiongrant.ClientContext{
		ID: req.client.ID,
		Binding: assertiongrant.Binding{
			DPoPJKT: req.binding.DPoPJKT,
			X5TS256: req.binding.MTLSThumbprint,
		},
		RequestedScopes: req.requested,
		Resources:       req.client.Resources,
	})
	if err != nil {
		writeAssertionRejection(ctx, w, deps, req.client.ID, req.issuer, err)
		return nil, false
	}
	return result, true
}

// writeAssertionRejection answers an error from [assertiongrant.PeekIssuer],
// [assertiongrant.Verifier.Verify] or [assertiongrant.Verifier.Consume].
func writeAssertionRejection(ctx context.Context, w http.ResponseWriter, deps Deps, clientID, issuer string, err error) {
	var rejected *assertiongrant.Error
	switch {
	case errors.As(err, &rejected):
		emitJWTBearerRejected(ctx, deps, clientID, issuer, string(rejected.Reason))
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant, "assertion is invalid")
	case errors.Is(err, assertiongrant.ErrKeySourceUnavailable):
		emitJWTBearerRejected(ctx, deps, clientID, issuer, jwtBearerReasonKeySource)
		endpointsupport.WriteOAuthError(w, http.StatusServiceUnavailable, errServerError,
			"assertion issuer keys are temporarily unavailable")
	default:
		emitJWTBearerRejected(ctx, deps, clientID, issuer, jwtBearerReasonVerifierFault)
		endpointsupport.WriteServerError(w)
	}
}

// resolveJWTBearerSubject maps the verified assertion subject onto a local
// subject through the embedder's resolver and confirms the user store still
// holds it. A subject with no provisioned account is access_denied
// (draft-06 §4.4.3): the assertion is valid, re-obtaining it would not help.
func resolveJWTBearerSubject(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	req *jwtBearerRequest,
	result *assertiongrant.Result,
) (string, bool) {
	clientID := req.client.ID
	subject, err := deps.ResolveAssertionSubject(ctx, result.Subject)
	switch {
	case errors.Is(err, assertiongrant.ErrUnknownSubject):
		emitJWTBearerRejected(ctx, deps, clientID, req.issuer, jwtBearerReasonUnknownSubject)
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errAccessDenied,
			"assertion subject has no account")
		return "", false
	case err != nil, subject == "":
		emitJWTBearerRejected(ctx, deps, clientID, req.issuer, jwtBearerReasonResolverFault)
		endpointsupport.WriteServerError(w)
		return "", false
	}
	if _, err := lookupLiveSubject(ctx, deps, subject); err != nil {
		if errors.Is(err, errSubjectDeprovisioned) {
			emitJWTBearerRejected(ctx, deps, clientID, req.issuer, jwtBearerReasonSubjectNotLive)
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errAccessDenied,
				"assertion subject has no account")
			return "", false
		}
		emitJWTBearerRejected(ctx, deps, clientID, req.issuer, jwtBearerReasonSubjectLookup)
		endpointsupport.WriteServerError(w)
		return "", false
	}
	return subject, true
}

// narrowToAssertion settles the issued scope and audience from the request,
// the client's registration and the verified assertion, and refuses what the
// client could fix by changing its request. It runs before the jti is spent.
//
// The scope is the requested set, or the registered set without "openid"
// when none was requested, narrowed to an ID-JAG scope claim; an empty
// result is invalid_scope. The verifier already holds a requested scope
// to the claim and every claimed resource, in canonical form, to the
// registration. With a resource parameter it must be one the claim names;
// without one the claim's resource becomes the audience, and a claim naming
// several needs the parameter to pick one (this endpoint issues a single
// audience). Returns false when a response has been written.
func narrowToAssertion(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	req *jwtBearerRequest,
	result *assertiongrant.Result,
) ([]string, string, bool) {
	scope := narrowJWTBearerScope(req.requested, req.client.Scopes, result.Scopes)
	if len(scope) == 0 {
		emitJWTBearerRejected(ctx, deps, req.client.ID, req.issuer, jwtBearerReasonScope)
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidScope,
			"no registered scope is granted by the assertion")
		return nil, "", false
	}
	if !checkTokenScopeAllowlist(w, deps, req.client.ID, scope) {
		emitJWTBearerRejected(ctx, deps, req.client.ID, req.issuer, jwtBearerReasonScope)
		return nil, "", false
	}
	resource := req.resource
	if len(result.Resources) == 0 {
		return scope, resource, true
	}
	switch {
	case resource != "":
		if !resourceindicator.Contains(result.Resources, resource) {
			emitJWTBearerRejected(ctx, deps, req.client.ID, req.issuer, jwtBearerReasonResource)
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidTarget,
				"resource indicator is not granted by the assertion")
			return nil, "", false
		}
	case len(result.Resources) == 1:
		resource = result.Resources[0]
	default:
		emitJWTBearerRejected(ctx, deps, req.client.ID, req.issuer, jwtBearerReasonResource)
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidTarget,
			"the assertion names several resources: a resource parameter must select one")
		return nil, "", false
	}
	return scope, resource, true
}

// narrowJWTBearerScope is the one place the jwt-bearer scope is narrowed:
// requested (or, when empty, registered without "openid") kept, when the
// assertion carries a scope claim, to what it grants. A non-empty requested
// set is already held to the registration by [applyJWTBearerRequestScope].
func narrowJWTBearerScope(requested, registered, claimed []string) []string {
	base := requested
	if len(base) == 0 {
		base = oidcscope.WithoutOpenID(registered)
	}
	return slices.DeleteFunc(slices.Clone(base), func(s string) bool {
		return claimed != nil && !slices.Contains(claimed, s)
	})
}

// issueJWTBearerResponse mints the access token and writes the success
// body. The token carries no grant id, so a subject revocation does not
// reach it; the resolver and the user-store check stop the next issuance.
func issueJWTBearerResponse(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	req *jwtBearerRequest,
	result *assertiongrant.Result,
	subject string,
	scope []string,
	resource string,
) {
	clientID := req.client.ID
	publicSubject, err := projectPublicSubject(ctx, deps, subject, req.client)
	if err != nil {
		emitJWTBearerRejected(ctx, deps, clientID, req.issuer, jwtBearerReasonIssuance)
		endpointsupport.WriteServerError(w)
		return
	}
	now := deps.now().UTC()
	accessToken, err := mintAccessToken(ctx, deps, subject, publicSubject, clientID, "", scope, resource, now, 0, req.binding, nil)
	if err != nil {
		emitJWTBearerRejected(ctx, deps, clientID, req.issuer, jwtBearerReasonIssuance)
		endpointsupport.WriteServerError(w)
		return
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditJWTBearerGranted,
		Level:    audit.LevelInfo,
		Message:  "jwt-bearer assertion redeemed",
		ActorID:  subject,
		ClientID: clientID,
		Extras: map[string]any{
			"issuer":  req.issuer,
			"profile": result.Profile.String(),
		},
	})
	writeSuccess(w, successResponse{
		AccessToken: accessToken,
		TokenType:   req.binding.tokenTypeFor(),
		ExpiresIn:   int64(deps.AccessTokenTTL.Seconds()),
		Scope:       oidcscope.Join(scope),
	})
}

// emitJWTBearerRejected records a refused redemption. issuer is empty when
// the request was refused before the assertion's iss was read.
func emitJWTBearerRejected(ctx context.Context, deps Deps, clientID, issuer, reason string) {
	extras := map[string]any{"reason": reason}
	if issuer != "" {
		extras["issuer"] = issuer
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditJWTBearerRejected,
		Level:    audit.LevelInfo,
		Message:  "jwt-bearer assertion rejected",
		ClientID: clientID,
		Extras:   extras,
	})
}
