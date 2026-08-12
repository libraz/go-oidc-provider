// Package grantmgmtendpoint implements the OAuth 2.0 Grant Management
// draft's grant management endpoint: a confidential-client API for
// querying (GET) and revoking (DELETE) a previously established grant by
// its grant_id. Grant creation / replace / merge happen at the
// authorization endpoint; this endpoint owns the read and delete halves.
//
// Every request is authenticated as a confidential client: a client
// registered with token_endpoint_auth_method=none is refused with
// invalid_client even where the OP otherwise admits it, because its
// authentication proves nothing and the grant_id in the request path
// would become the sole credential. The target grant MUST belong to the
// authenticated client — a grant_id owned by a different client is
// reported as 404 (not 403) so the endpoint does not confirm the
// existence of another client's grant.
package grantmgmtendpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Clock is the structural wall-clock dependency.
type Clock interface {
	Now() time.Time
}

// Deps is the grant management endpoint's dependency set.
type Deps struct {
	// Clients is the read-only client registry for authentication.
	Clients store.ClientStore

	// Grants is the consent substore the endpoint reads (query) and
	// deletes (revoke).
	Grants store.GrantStore

	// RefreshTokens / OpaqueAccessTokens / AccessTokens / GrantRevocations
	// back the revoke cascade, mirroring the token endpoint's grant
	// teardown. Nil substores are skipped.
	RefreshTokens      store.RefreshTokenStore
	OpaqueAccessTokens store.OpaqueAccessTokenStore
	AccessTokens       store.AccessTokenRegistry
	GrantRevocations   store.GrantRevocationStore

	// RevocationStrategy selects how JWT access tokens are torn down
	// (tombstone vs per-JTI registry), matching the token endpoint.
	RevocationStrategy store.AccessTokenRevocationStrategy

	// AccessTokenTTL bounds the grant tombstone's retention window
	// (now + TTL + grace) so a verifier rejects every access token
	// issued before the revoke until the tombstone is collected.
	AccessTokenTTL time.Duration

	// Audit receives grant-management events. Nil collapses to a
	// no-op emitter so tests / embedders that do not opt in keep the
	// endpoint behaviour unchanged.
	Audit audit.Emitter

	// Client-authentication wiring, identical to the sibling endpoints.
	SecretVerifier           clientauth.SecretVerifier
	AssertionVerifier        clientauth.AssertionVerifier
	AllowedClientAuthMethods []clientauth.Method

	// QueryEnabled / RevokeEnabled gate the GET (query) and DELETE
	// (revoke) operations on the configured grant_management_actions set
	// (WithGrantManagement). An operation absent from the advertised set
	// is rejected with 405 so the endpoint never honours an action the OP
	// did not declare in grant_management_actions_supported.
	QueryEnabled  bool
	RevokeEnabled bool

	// Clock supplies the wall-clock reading; nil falls back to the
	// system clock.
	Clock Clock
}

const auditGrantManagementRevoked = string(auditevent.AuditGrantManagementRevoked)

func (d *Deps) now() time.Time {
	if d.Clock != nil {
		return d.Clock.Now()
	}
	return timex.Now()
}

func (d *Deps) audit() audit.Emitter {
	if d.Audit != nil {
		return d.Audit
	}
	return audit.Discard()
}

// queryResponse is the Grant Management draft query body. scopes is an
// array of scope objects (one entry carrying the space-delimited grant
// scope); authorization_details echoes the RFC 9396 grant details.
type queryResponse struct {
	Scopes               []scopeEntry     `json:"scopes,omitempty"`
	AuthorizationDetails []map[string]any `json:"authorization_details,omitempty"`
}

type scopeEntry struct {
	Scope string `json:"scope"`
}

// Handler returns the http.Handler for the grant management endpoint. It
// expects to be mounted at a pattern carrying a "{grant_id}" path value
// (for example "/oidc/grant_management/{grant_id}").
func Handler(deps Deps) http.Handler {
	if deps.SecretVerifier == nil {
		deps.SecretVerifier = &clientauth.Argon2id{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if !deps.QueryEnabled {
				rejectMethod(w, deps)
				return
			}
			serveQuery(w, r, deps)
		case http.MethodDelete:
			if !deps.RevokeEnabled {
				rejectMethod(w, deps)
				return
			}
			serveRevoke(w, r, deps)
		default:
			rejectMethod(w, deps)
		}
	})
}

// rejectMethod answers a request whose method maps to a grant_management
// action the OP did not advertise. The Allow header reflects only the
// enabled operations so a client can discover the supported set.
func rejectMethod(w http.ResponseWriter, deps Deps) {
	if allow := allowHeader(deps); allow != "" {
		w.Header().Set("Allow", allow)
	}
	stampNoStore(w)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func allowHeader(deps Deps) string {
	methods := make([]string, 0, 2)
	if deps.QueryEnabled {
		methods = append(methods, http.MethodGet)
	}
	if deps.RevokeEnabled {
		methods = append(methods, http.MethodDelete)
	}
	return strings.Join(methods, ", ")
}

// resolveOwnedGrant authenticates the client and resolves the grant named
// by the {grant_id} path value, enforcing client ownership. It writes the
// response and returns ok=false on any failure (auth failure already
// surfaced by the auth helper; a missing / foreign grant becomes 404).
func resolveOwnedGrant(w http.ResponseWriter, r *http.Request, deps Deps) (*store.Client, *store.Grant, bool) {
	// Reject a malformed query up front so the authenticator never sees
	// a half-parsed request: on a bodyless method the query string is
	// where private_key_jwt clients put their client_assertion (Basic /
	// mTLS auth flow through the request headers regardless). The body
	// is size-capped first (a GET / DELETE rarely carries one, but the
	// cap is cheap defence against memory exhaustion).
	endpointsupport.LimitFormBody(w, r)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed request")
		return nil, nil, false
	}
	client, _, ok := endpointsupport.AuthenticateClient(r.Context(), w, r,
		endpointsupport.AuthenticateOpts{
			Clients:           deps.Clients,
			SecretVerifier:    deps.SecretVerifier,
			AssertionVerifier: deps.AssertionVerifier,
			AllowedMethods:    deps.AllowedClientAuthMethods,
		}, nil)
	if !ok {
		return nil, nil, false
	}
	if client.PublicClient {
		// A public client proves nothing at authentication time: it
		// presents a client_id and no secret. That would leave the
		// grant_id in the request path as the endpoint's only
		// credential, and a path segment is not one — it reaches proxy
		// logs, browser history and Referer headers. Anyone who read
		// one there could enumerate what a user consented to and revoke
		// it. The endpoint therefore serves confidential clients only.
		writeError(w, http.StatusUnauthorized, "invalid_client",
			"grant management requires a confidential client")
		return nil, nil, false
	}
	grantID := strings.TrimSpace(r.PathValue("grant_id"))
	if grantID == "" {
		writeError(w, http.StatusNotFound, "invalid_request", "grant_id is required")
		return nil, nil, false
	}
	g, err := deps.Grants.Find(r.Context(), grantID)
	if err != nil || g == nil || g.ClientID != client.ID {
		// Ownership failure is reported as 404 so the endpoint does not
		// confirm that another client's grant exists.
		writeError(w, http.StatusNotFound, "invalid_request", "grant not found")
		return nil, nil, false
	}
	return client, g, true
}

func serveQuery(w http.ResponseWriter, r *http.Request, deps Deps) {
	_, g, ok := resolveOwnedGrant(w, r, deps)
	if !ok {
		return
	}
	body := queryResponse{AuthorizationDetails: g.AuthorizationDetails}
	if len(g.Scope) > 0 {
		body.Scopes = []scopeEntry{{Scope: strings.Join(g.Scope, " ")}}
	}
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

func serveRevoke(w http.ResponseWriter, r *http.Request, deps Deps) {
	client, g, ok := resolveOwnedGrant(w, r, deps)
	if !ok {
		return
	}
	revokedGrantIDs, err := revokeSubjectClientCascade(r.Context(), deps, g)
	if err != nil {
		// The grant record could not be deleted, so it is still live and
		// queryable; reporting 204 would be a false success. Surface a
		// server_error and let the client retry.
		writeError(w, http.StatusInternalServerError, "server_error", "could not revoke grant")
		return
	}
	deps.audit().Emit(r.Context(), audit.Event{
		Name:     auditGrantManagementRevoked,
		Level:    audit.LevelInfo,
		Message:  "grant management grant revoked",
		ActorID:  g.Subject,
		ClientID: client.ID,
		Extras: map[string]any{
			"grant_id":          g.ID,
			"revoked_grant_ids": revokedGrantIDs,
		},
	})
	stampNoStore(w)
	w.WriteHeader(http.StatusNoContent)
}

func revokeSubjectClientCascade(ctx context.Context, deps Deps, g *store.Grant) ([]string, error) {
	targets := map[string]struct{}{g.ID: {}}
	grants, err := deps.Grants.ListBySubject(ctx, g.Subject)
	if err != nil {
		return nil, err
	}
	for _, cand := range grants {
		if cand == nil || cand.Subject != g.Subject || cand.ClientID != g.ClientID {
			continue
		}
		targets[cand.ID] = struct{}{}
	}
	ids := make([]string, 0, len(targets))
	for id := range targets {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if err := revokeGrantCascade(ctx, deps, id); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// revokeGrantCascade tears the grant down: it tombstones / denylists the
// JWT access tokens, revokes the opaque access tokens and refresh tokens
// bound to the grant, then deletes the grant record so a subsequent query
// reports it gone. Mirrors the token endpoint's grant teardown. Every
// security-state write must succeed before deletion: otherwise the caller
// receives a server error and can retry while the grant remains queryable.
func revokeGrantCascade(ctx context.Context, deps Deps, grantID string) error {
	now := deps.now().UTC()
	if err := endpointsupport.RevokeJWTAccessTokensByGrant(ctx, endpointsupport.JWTGrantCascadeOpts{
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		RevocationStrategy: deps.RevocationStrategy,
	}, grantID, now, deps.AccessTokenTTL+5*time.Minute, "grant_management_revoke"); err != nil {
		return fmt.Errorf("grant management: revoke JWT access tokens: %w", err)
	}
	if deps.OpaqueAccessTokens != nil {
		if _, err := deps.OpaqueAccessTokens.RevokeByGrant(ctx, grantID); err != nil {
			return fmt.Errorf("grant management: revoke opaque access tokens: %w", err)
		}
	}
	if deps.RefreshTokens != nil {
		if err := deps.RefreshTokens.RevokeByGrant(ctx, grantID); err != nil {
			return fmt.Errorf("grant management: revoke refresh tokens: %w", err)
		}
	}
	return deps.Grants.Delete(ctx, grantID)
}

// stampNoStore sets the no-cache headers every grant management response
// carries: the body reflects mutable grant state and MUST NOT be cached.
func stampNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// writeError emits the RFC 6749 §5.2 JSON error envelope.
func writeError(w http.ResponseWriter, status int, code, description string) {
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}
