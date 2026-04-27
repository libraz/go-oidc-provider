package registrationendpoint

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/op/store"
)

// verifyRAT authenticates an RFC 7592 management request. It extracts
// the Bearer credential, looks up the client (returning the same
// invalid_token response on every failure path to defeat
// enumeration), and finally verifies the presented hash against the
// stored RAT.
//
// On success the function returns the resolved client; on any failure
// it writes the response envelope and returns ok=false.
func verifyRAT(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
	clientID string,
) (*store.Client, bool) {
	bearer, ok := bearerFromHeader(r.Header.Get("Authorization"))
	if !ok {
		writeInvalidToken(w, deps.Issuer, "registration access token is required")
		return nil, false
	}
	if clientID == "" {
		// Defence in depth: the router enforces the path parameter,
		// but a defensive check here means a refactor that loses the
		// {client_id} wildcard cannot exfiltrate RAT validity through
		// a 404.
		writeInvalidToken(w, deps.Issuer, "registration access token is invalid")
		return nil, false
	}
	client, err := deps.Clients.GetClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			deps.logger().Warn("dcr.rat.invalid", "reason", "client_not_found", "client_id", clientID)
			deps.audit().Emit(ctx, audit.Event{
				Name:     auditDCRRATInvalid,
				Level:    audit.LevelWarn,
				Message:  "client not found",
				ClientID: clientID,
			})
			writeInvalidToken(w, deps.Issuer, "registration access token is invalid")
			return nil, false
		}
		deps.logger().Error("dcr.client.lookup_failed", "err", err, "client_id", clientID)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return nil, false
	}
	if !sourceIsDynamic(client.Source) {
		deps.logger().Warn("dcr.rat.invalid", "reason", "non_dynamic_client", "client_id", clientID)
		deps.audit().Emit(ctx, audit.Event{
			Name:     auditDCRRATInvalid,
			Level:    audit.LevelWarn,
			Message:  "client is not dynamically registered",
			ClientID: clientID,
		})
		writeInvalidToken(w, deps.Issuer, "registration access token is invalid")
		return nil, false
	}
	stored, err := deps.RegistrationAccessTokens.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			deps.logger().Warn("dcr.rat.invalid", "reason", "rat_missing", "client_id", clientID)
			deps.audit().Emit(ctx, audit.Event{
				Name:     auditDCRRATInvalid,
				Level:    audit.LevelWarn,
				Message:  "registration access token not on file",
				ClientID: clientID,
			})
			writeInvalidToken(w, deps.Issuer, "registration access token is invalid")
			return nil, false
		}
		deps.logger().Error("dcr.rat.lookup_failed", "err", err, "client_id", clientID)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return nil, false
	}
	if !constantTimeEqualString(hashSecret(bearer), stored.HashedValue) {
		deps.logger().Warn("dcr.rat.invalid", "reason", "hash_mismatch", "client_id", clientID)
		deps.audit().Emit(ctx, audit.Event{
			Name:     auditDCRRATInvalid,
			Level:    audit.LevelWarn,
			Message:  "registration access token hash mismatch",
			ClientID: clientID,
		})
		writeInvalidToken(w, deps.Issuer, "registration access token is invalid")
		return nil, false
	}
	return client, true
}

// sourceIsDynamic reports whether the client was registered via RFC
// 7591. The empty string is treated as static for backwards
// compatibility per [store.ClientSource]; an empty value therefore
// fails this check, which is the desired behaviour: only true dynamic
// clients may use RFC 7592.
func sourceIsDynamic(s store.ClientSource) bool {
	return s == store.ClientSourceDynamic
}

// constantTimeEqualString compares a and b in constant time relative
// to the longer of the two so the comparison cannot leak the stored
// hash through timing. crypto/subtle.ConstantTimeCompare returns 1
// when the inputs are byte-identical and equal length; we additionally
// short-circuit unequal lengths because the comparator runs in O(min)
// when lengths differ.
func constantTimeEqualString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
