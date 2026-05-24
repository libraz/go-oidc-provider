// Package grantmgmtendpoint implements the OAuth 2.0 Grant Management
// draft's grant management endpoint: a confidential-client API for
// querying (GET) and revoking (DELETE) a previously established grant by
// its grant_id. Grant creation / replace / merge happen at the
// authorization endpoint; this endpoint owns the read and delete halves.
//
// Every request is authenticated as a confidential client and the target
// grant MUST belong to that client — a grant_id owned by a different
// client is reported as 404 (not 403) so the endpoint does not confirm the
// existence of another client's grant.
package grantmgmtendpoint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// maxGrantMgmtFormBytes caps the request body the endpoint parses for
// client-authentication parameters (client_assertion). The grant
// management endpoint is GET / DELETE and rarely carries a body; the cap
// mirrors the sibling endpoints' defence against memory exhaustion.
const maxGrantMgmtFormBytes = 64 * 1024

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

func (d *Deps) now() time.Time {
	if d.Clock != nil {
		return d.Clock.Now()
	}
	return timex.Now()
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
	// Parse the form so query-string client_assertion (private_key_jwt
	// on a GET / DELETE) is visible to the authenticator; Basic / mTLS
	// auth flow through the request headers regardless. The body is
	// size-capped first (a GET / DELETE rarely carries one, but the cap
	// is cheap defence against memory exhaustion).
	r.Body = http.MaxBytesReader(w, r.Body, maxGrantMgmtFormBytes)
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
	_, g, ok := resolveOwnedGrant(w, r, deps)
	if !ok {
		return
	}
	if err := revokeGrantCascade(r.Context(), deps, g.ID); err != nil {
		// The grant record could not be deleted, so it is still live and
		// queryable; reporting 204 would be a false success. Surface a
		// server_error and let the client retry.
		writeError(w, http.StatusInternalServerError, "server_error", "could not revoke grant")
		return
	}
	stampNoStore(w)
	w.WriteHeader(http.StatusNoContent)
}

// revokeGrantCascade tears the grant down: it tombstones / denylists the
// JWT access tokens, revokes the opaque access tokens and refresh tokens
// bound to the grant, then deletes the grant record so a subsequent query
// reports it gone. Mirrors the token endpoint's grant teardown. The
// token-substore steps are best-effort (the JWT tombstone alone already
// blocks token use), but a failure to delete the grant record is returned
// because the grant would otherwise remain live and the caller must not be
// told the revoke succeeded.
func revokeGrantCascade(ctx context.Context, deps Deps, grantID string) error {
	now := deps.now().UTC()
	_ = endpointsupport.RevokeJWTAccessTokensByGrant(ctx, endpointsupport.JWTGrantCascadeOpts{
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		RevocationStrategy: deps.RevocationStrategy,
	}, grantID, now, deps.AccessTokenTTL+5*time.Minute, "grant_management_revoke")
	if deps.OpaqueAccessTokens != nil {
		_, _ = deps.OpaqueAccessTokens.RevokeByGrant(ctx, grantID)
	}
	if deps.RefreshTokens != nil {
		_ = deps.RefreshTokens.RevokeByGrant(ctx, grantID)
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
