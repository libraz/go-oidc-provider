package cibaendpoint

import (
	"context"
	"net/http"
	"net/url"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/op/store"
)

// consumeJARRequestObject inspects the form values for a "request"
// parameter. When present, it verifies the JWT against the
// authenticated client and merges the claims onto the form values
// per RFC 9101 §6.1 / FAPI-CIBA-ID1 §5.2.2. A nil [Deps.JAR] means
// the OP has not enabled JAR; the request is rejected with
// invalid_request (CIBA Core §13 does not list
// invalid_request_object as a BCA error code).
//
// When [Deps.RequireSignedAuthRequest] is true and "request" is
// missing, the request is rejected with invalid_request because
// FAPI-CIBA-ID1 §5.2.2 mandates a signed authentication request on
// every /bc-authorize POST.
//
// The returned bool is false when the function wrote the response;
// the caller then stops processing.
func consumeJARRequestObject(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	values url.Values,
) (url.Values, bool) {
	raw := values.Get("request")
	if raw == "" {
		if deps.RequireSignedAuthRequest {
			deps.auditEmitter().Emit(ctx, audit.Event{
				Name:     ciba.AuditAuthorizationRejected,
				Level:    audit.LevelWarn,
				Message:  "backchannel-authentication rejected: signed request object required",
				ClientID: client.ID,
				Extras: map[string]any{
					"reason": "request_object_required",
				},
			})
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
				"request object is required by the active profile")
			return nil, false
		}
		return values, true
	}
	if deps.JAR == nil {
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: request object not supported",
			ClientID: client.ID,
			Extras: map[string]any{
				"reason": "request_object_invalid",
			},
		})
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
			"request is not supported by this OP")
		return nil, false
	}
	obj, err := deps.JAR.VerifyCIBA(ctx, raw, client.ID, client)
	if err != nil {
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: request object verification failed",
			ClientID: client.ID,
			Extras: map[string]any{
				"reason": "request_object_invalid",
			},
		})
		writeJARError(w, err)
		return nil, false
	}
	// RFC 9101 §6.3: only the signed object's parameters are used here.
	merged, err := jar.Merge(values, obj, jar.MergeObjectOnly)
	if err != nil {
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: request object merge failed",
			ClientID: client.ID,
			Extras: map[string]any{
				"reason": "request_object_invalid",
			},
		})
		writeJARError(w, err)
		return nil, false
	}
	return merged, true
}

// writeJARError translates a [jar] sentinel into the CIBA wire
// envelope. CIBA Core §13 enumerates a closed set of BCA error
// codes that does NOT include "invalid_request_object" (unlike the
// /authorize endpoint, which does). Every client-side JAR failure
// therefore surfaces as "invalid_request" so OFCS' CIBA-13 negative
// tests see the spec-mandated code; the human-readable description
// carries the precise sentinel detail, drawn from the [jar.Description]
// catalogue the other JAR-consuming endpoints render from. A key-source
// fault on the OP's side is a 503 server_error, as on /authorize and
// /par.
func writeJARError(w http.ResponseWriter, err error) {
	status, code := jar.WireError(err)
	if code == jar.CodeInvalidRequestObject {
		code = errInvalidRequest
	}
	endpointsupport.WriteOAuthError(w, status, code, jar.Description(err))
}
