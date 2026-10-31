package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// issueRefreshResponse mints the access token, optionally an id_token
// (only when the originating grant carried "openid"), and rotates the
// refresh token (mints a fresh one whose ParentID is the just-consumed
// id). Failure on any step writes a 500. The provider's transactional path
// rolls the staged Consume back; non-transactional embeddings cannot
// coordinate that rollback and rely on their substore atomicity contract.
//
// binding is the sender-constraint summary the rotated tokens inherit.
// For DPoP it is either the verified proof's thumbprint (request
// presented a proof) or the consumed record's bound thumbprint
// (chain was already bound and the proof simply matched); for mTLS
// it is always the consumed record's thumbprint (mTLS does not
// admit mid-chain upgrades). Both cases collapse to a single source
// of truth on the wire and on the persisted rotated record.
func issueRefreshResponse(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	exchanged *refresh.Exchanged,
	user *store.User,
	binding tokenBinding,
	authorizationDetails []map[string]any,
	transactional bool,
	rotation *rotationOutcome,
) {
	if exchanged.InGrace {
		serveGraceRetry(ctx, w, deps, client, exchanged, binding, transactional)
		return
	}
	now := deps.now().UTC()
	authCtx, err := refreshAuthContext(ctx, deps, exchanged)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	if err := requireAuthTimeForIDToken(client, exchanged.Scope, authCtx.AuthTime); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "required auth_time is unavailable")
		return
	}
	if !retirePriorOpaqueAccessTokens(ctx, w, deps, client, exchanged, transactional) {
		return
	}
	// Mint refusal under a tombstoned grant: under the
	// grant-tombstone strategy, refuse to mint a fresh access token when
	// the underlying grant has already been tombstoned. Without this
	// check a refresh racing a /end_session or code-replay cascade could
	// slip a fresh AT through ahead of the tombstone's observable effect
	// on resource-server lookups. The check surfaces as invalid_grant
	// per RFC 6749 §5.2 because the grant was legitimately revoked, the
	// refresh token is no longer usable, and the failure is a property
	// of the grant rather than of the request shape.
	if !enforceGrantTombstoneMintRefusal(ctx, w, deps, exchanged) {
		return
	}
	exchanged, err = withChainID(exchanged)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	publicSubject := exchanged.Subject
	if !exchanged.SubjectPublic {
		publicSubject, err = projectPublicSubject(ctx, deps, exchanged.Subject, client)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return
		}
	}
	accessToken, err := mintAccessToken(
		ctx,
		deps,
		exchanged.Subject,
		publicSubject,
		client.ID,
		exchanged.GrantID,
		exchanged.Scope,
		exchanged.Resource,
		now,
		authCtx.AuthTime,
		binding,
		authorizationDetails,
		accessTokenOverrides{
			Extra:         exchanged.AccessTokenExtra,
			ForceJWT:      refreshMintPinnedJWT(exchanged),
			Authorization: &authCtx,
			ChainID:       exchanged.ChainID,
		},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	idTokenExtra := idTokenExtraClaims(deps, user, exchanged.Scope, authCtx.Claims)
	idToken, err := maybeMintRefreshIDToken(deps, refreshIDTokenInput{
		Subject:  publicSubject,
		ClientID: client.ID,
		Scope:    refreshIDTokenScope(exchanged),
		Now:      now,
		AuthTime: authCtx.AuthTime,
		ACR:      authCtx.ACR,
		AMR:      authCtx.AMR,
		Claims:   authCtx.Claims,
		Nonce:    exchanged.Nonce,
		Extra:    idTokenExtra,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	if idToken != "" {
		idToken, err = maybeEncryptIDToken(ctx, deps, client, idToken)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return
		}
	}
	response := successResponse{
		AccessToken:          accessToken,
		TokenType:            binding.tokenTypeFor(),
		ExpiresIn:            int64(deps.AccessTokenTTL.Seconds()),
		IDToken:              idToken,
		Scope:                joinScope(exchanged.Scope),
		AuthorizationDetails: cloneAuthorizationDetails(authorizationDetails),
		GrantID:              chainGrantIDForResponse(deps, exchanged),
	}
	if err := rotateRefreshToken(ctx, deps, client, refreshExchangedForRotation(exchanged, authCtx, authorizationDetails), binding, &response, rotation); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	writeSuccess(w, response)
}

// refreshIDTokenInput collects the parameters
// [maybeMintRefreshIDToken] needs. It mirrors [mintIDTokenInput] but
// omits the at_hash / c_hash fields the refresh path does not populate.
type refreshIDTokenInput struct {
	Subject  string
	ClientID string
	Scope    []string
	Now      time.Time
	AuthTime int64
	ACR      string
	AMR      []string
	Claims   *authorize.ClaimsRequest

	// Nonce is the OIDC Core 1.0 §3.1.2.1 nonce captured at the
	// originating authorization request, threaded through the
	// persisted refresh-token chain. OIDC Core §12 requires the
	// rotated id_token to preserve it.
	Nonce string

	// Extra carries the OIDC Core 1.0 §5.5 "claims"-projected
	// id_token claims resolved from the originating grant. nil when
	// the grant carried no §5.5 payload or the projector returned
	// no values.
	Extra map[string]any
}

// refreshIDTokenScope is the scope the refresh id_token is minted under:
// none for a chain whose id_token a refresh cannot rebuild.
func refreshIDTokenScope(exchanged *refresh.Exchanged) []string {
	if exchangeChainWithholdsIDToken(exchanged) {
		return nil
	}
	return exchanged.Scope
}

// exchangeChainWithholdsIDToken reports a token-exchange chain: the
// exchange builds its id_token with the OP-computed act chain and cnf
// binding, which a refresh cannot rebuild, and may have withheld it
// altogether. Refreshing such a chain returns no id_token.
func exchangeChainWithholdsIDToken(exchanged *refresh.Exchanged) bool {
	if exchanged.Origin != store.RefreshOriginCustomGrant {
		return false
	}
	_, hasAct := exchanged.AccessTokenExtra["act"]
	return hasAct
}

// maybeMintRefreshIDToken signs an id_token only when the rotated grant
// carries the "openid" scope. The token omits at_hash / c_hash because
// the refresh-token id_token does not bind a fresh access token to a
// fresh authorization code, but it DOES carry the original nonce per
// OIDC Core 1.0 §12 ("if a nonce value was sent in the Authentication
// Request, a nonce Claim MUST be present"). acr / amr are copied from
// the originating authentication so the spec's "same as the original
// ID Token" requirement holds across rotations.
func maybeMintRefreshIDToken(deps Deps, in refreshIDTokenInput) (string, error) {
	if !oidcscope.ContainsOpenID(in.Scope) {
		return "", nil
	}
	claims := tokens.IDTokenClaims{
		Issuer:    deps.Issuer,
		Subject:   in.Subject,
		Audience:  []string{in.ClientID},
		IssuedAt:  in.Now.Unix(),
		ExpiresAt: tokens.ExpiresIn(in.Now, deps.IDTokenTTL),
		AuthTime:  in.AuthTime,
		Nonce:     in.Nonce,
		ACR:       idTokenACRForClaims(in.ACR, in.Claims),
		AMR:       append([]string(nil), in.AMR...),
		Extra:     in.Extra,
	}
	return tokens.SignIDToken(activeSigningKey(deps), claims)
}

// rotateRefreshToken mints the next-generation refresh token whose
// ParentID points at the just-consumed id. The library always rotates;
// returning the original token would defeat the §2.2.2 replay defence
// the exchanger already enforces. The binding is propagated onto the
// rotated record so the sender constraint (RFC 9449 §6.1 for DPoP,
// RFC 8705 §3.1 for mTLS) survives across the chain. The successor also
// keeps the consumed token's bound scope and TTL bucket (RFC 6749 §6): a
// narrowed request affects only the access token and id_token returned.
//
// DPoP rules per RFC 9449 §5.4: once the AS has bound a refresh token
// to a DPoP key the binding MUST persist across rotations. The
// "no-bind for confidential clients" policy therefore applies only
// when the consumed chain was NOT already bound: an opportunistic
// upgrade on the first refresh would lock subsequent refreshes to a
// single key, which contradicts the RFC 9449 §5 guidance for
// confidential clients.
func rotateRefreshToken(
	ctx context.Context,
	deps Deps,
	client *store.Client,
	exchanged *refresh.Exchanged,
	binding tokenBinding,
	response *successResponse,
	rotation *rotationOutcome,
) error {
	// Re-check eligibility at rotation, not only at chain start: a
	// client whose registration loses refresh_token (or a Provider
	// reconfigured to drop the grant) must not have the chain extended
	// by a successor. The consumed token is already spent, so the
	// chain simply ends here — no successor row is persisted.
	if !deps.refreshIssuanceEnabled(client) {
		return nil
	}
	issuer, err := refresh.NewIssuer(refresh.IssuerConfig{
		Store: deps.RefreshTokens,
		Clock: deps.clockFunc(),
		TTL:   pickRefreshTokenTTL(deps, exchanged.BoundScope),
	})
	if err != nil {
		return err
	}
	parent := exchanged.ConsumedID
	rotatedJKT := binding.DPoPJKT
	if exchanged.DPoPJKT == "" {
		// Chain was not previously bound: apply the issuance-time
		// policy (public clients bind, confidential clients leave
		// empty). When the chain is already bound, exchanged.DPoPJKT
		// equals binding.DPoPJKT (enforceDPoPRefreshBinding enforced
		// match) and we keep that value so the chain stays bound.
		rotatedJKT = refreshDPoPJKT(client, binding.DPoPJKT)
	}
	issue := refresh.IssueInput{
		ClientID:             client.ID,
		Subject:              exchanged.Subject,
		GrantID:              exchanged.GrantID,
		Scope:                append([]string(nil), exchanged.BoundScope...),
		Resource:             exchanged.Resource,
		ParentID:             &parent,
		DPoPJKT:              rotatedJKT,
		MTLSCertThumbprint:   binding.MTLSThumbprint,
		Nonce:                exchanged.Nonce,
		ChainID:              exchanged.ChainID,
		Origin:               exchanged.Origin,
		SubjectPublic:        exchanged.SubjectPublic,
		AuthTime:             exchanged.AuthTime,
		ACR:                  exchanged.ACR,
		AMR:                  append([]string(nil), exchanged.AMR...),
		AuthorizationDetails: cloneAuthorizationDetails(exchanged.AuthorizationDetails),
		AccessTokenExtra:     cloneClaimsMap(exchanged.AccessTokenExtra),
		Claims:               cloneClaimsMap(exchanged.Claims),

		AuthorizationRecorded: exchanged.AuthorizationRecorded,
	}
	if len(deps.RefreshRetryEncryptionKeys) == 0 {
		token, err := issuer.Issue(ctx, issue)
		if err != nil {
			return err
		}
		response.RefreshToken = token
	} else {
		retries, ok := deps.RefreshTokens.(store.RefreshRetryResponseStore)
		if !ok {
			return errors.New("tokenendpoint: refresh store does not support durable retry responses")
		}
		token, successor, err := issuer.Prepare(issue)
		if err != nil {
			return err
		}
		response.RefreshToken = token
		sealed, err := sealRefreshRetryResponse(deps.RefreshRetryEncryptionKeys, parent, *response)
		if err != nil {
			return err
		}
		if err := retries.SaveRotationWithRetry(ctx, successor, sealed); err != nil {
			return err
		}
	}
	rotation.record(audit.Event{
		Name:     auditTokenRefreshed,
		Level:    audit.LevelInfo,
		Message:  "refresh token rotated",
		ActorID:  exchanged.Subject,
		ClientID: client.ID,
		Extras: map[string]any{
			"grant_id":       exchanged.GrantID,
			"offline_access": oidcscope.ContainsOfflineAccess(exchanged.BoundScope),
			"ttl_bucket":     ttlBucketFor(deps, exchanged.BoundScope),
		},
	})
	return nil
}
