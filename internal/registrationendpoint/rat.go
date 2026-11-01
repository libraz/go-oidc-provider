package registrationendpoint

import (
	"context"
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// verifyRAT authenticates an RFC 7592 management request. It extracts
// the Bearer credential, looks up the client (returning the same
// invalid_token response on every failure path to defeat
// enumeration), and finally verifies the presented hash against the
// stored RAT.
//
// On success the function returns the resolved client and RAT record; on any
// failure it writes the response envelope and returns ok=false. The RAT record
// carries the immutable IAT scope ceiling used by management PUT rotations.
func verifyRAT(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
	clientID string,
) (*store.Client, *store.RegistrationAccessToken, bool) {
	bearer, ok := bearerFromHeader(r.Header.Get("Authorization"))
	if !ok {
		writeInvalidToken(w, deps.Issuer, "registration access token is required")
		return nil, nil, false
	}
	if clientID == "" {
		// Defence in depth: the router enforces the path parameter,
		// but a defensive check here means a refactor that loses the
		// {client_id} wildcard cannot exfiltrate RAT validity through
		// a 404.
		writeInvalidToken(w, deps.Issuer, "registration access token is invalid")
		return nil, nil, false
	}
	client, err := deps.Clients.GetClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			rejectRAT(ctx, w, deps, clientID, "client_not_found", "client not found")
			return nil, nil, false
		}
		deps.logger().Error("dcr.client.lookup_failed", "err", err, "client_id", clientID)
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, endpointsupport.ErrServerError, "")
		return nil, nil, false
	}
	if !sourceIsDynamic(client.Source) {
		rejectRAT(ctx, w, deps, clientID, "non_dynamic_client", "client is not dynamically registered")
		return nil, nil, false
	}
	stored, err := deps.RegistrationAccessTokens.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			rejectRAT(ctx, w, deps, clientID, "rat_missing", "registration access token not on file")
			return nil, nil, false
		}
		deps.logger().Error("dcr.rat.lookup_failed", "err", err, "client_id", clientID)
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, endpointsupport.ErrServerError, "")
		return nil, nil, false
	}
	if !patterns.ConstantTimeKeyMatch(stored.HashedValue, patterns.Digest(bearer)) {
		rejectRAT(ctx, w, deps, clientID, "hash_mismatch", "registration access token hash mismatch")
		return nil, nil, false
	}
	return client, stored, true
}

// rejectRAT logs and audits a failed management authentication, then
// writes the same invalid_token response for every reason so the wire
// reveals nothing about which check failed.
func rejectRAT(ctx context.Context, w http.ResponseWriter, deps Deps, clientID, reason, message string) {
	deps.logger().Warn("dcr.rat.invalid", "reason", reason, "client_id", clientID)
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditDCRRATInvalid,
		Level:    audit.LevelWarn,
		Message:  message,
		ClientID: clientID,
	})
	writeInvalidToken(w, deps.Issuer, "registration access token is invalid")
}

// sourceIsDynamic reports whether the client was registered via RFC
// 7591. The empty string is treated as static for backwards
// compatibility per [store.ClientSource]; an empty value therefore
// fails this check, which is the desired behaviour: only true dynamic
// clients may use RFC 7592.
func sourceIsDynamic(s store.ClientSource) bool {
	return s == store.ClientSourceDynamic
}
