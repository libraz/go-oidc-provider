package cibaendpoint

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/op/store"
)

// FAPICIBAMaxExpiry caps the auth_req_id lifetime under the FAPI-CIBA
// profile. FAPI-CIBA-ID1 §5 inherits the FAPI 2.0 §3.1.9 ten-minute
// access-token lifetime cap and applies it to the backchannel-
// authentication TTL: any requested_expiry above 600s MUST be rejected
// (not silently clamped) so the wire response reflects the
// operator-mandated ceiling. op.New refuses a configured default or
// maximum above it, so the default path stays under the cap too.
const FAPICIBAMaxExpiry = 10 * time.Minute

// parsedRequestParams bundles the fields [parseRemainingParams] parses
// out of the tail of a CIBA request.
type parsedRequestParams struct {
	ACRValues      []string
	BindingMessage string
	ExpiresIn      time.Duration
	UserCode       string
}

// parseRemainingParams runs the parameter gates that follow scope and
// resource resolution in [serve]: acr_values, binding_message,
// requested_expiry, user_code and client_notification_token. See
// serve's doc comment for why this tail alone is factored out.
func parseRemainingParams(w http.ResponseWriter, deps Deps, merged url.Values) (parsedRequestParams, bool) {
	acrValues, ok := parseACRValues(w, merged.Get("acr_values"), deps)
	if !ok {
		return parsedRequestParams{}, false
	}
	bindingMessage, ok := parseBindingMessage(w, merged.Get("binding_message"))
	if !ok {
		return parsedRequestParams{}, false
	}
	expiresIn, ok := parseRequestedExpiry(w, merged.Get("requested_expiry"), deps)
	if !ok {
		return parsedRequestParams{}, false
	}
	userCode, ok := parseUserCode(w, merged.Get("user_code"))
	if !ok {
		return parsedRequestParams{}, false
	}
	if !parseClientNotificationToken(w, merged.Get("client_notification_token")) {
		return parsedRequestParams{}, false
	}
	return parsedRequestParams{
		ACRValues:      acrValues,
		BindingMessage: bindingMessage,
		ExpiresIn:      expiresIn,
		UserCode:       userCode,
	}, true
}

// parseScope dispatches to [ciba.ValidateScope] for the
// CIBA-specific "openid required" check, then validates the
// resulting subset against the client's registered Scopes.
func parseScope(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	form url.Values,
	client *store.Client,
) ([]string, bool) {
	scope, err := ciba.ValidateScope(form.Get("scope"))
	if err != nil {
		switch {
		case errors.Is(err, ciba.ErrMissingScope):
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
				"scope parameter is required")
		case errors.Is(err, ciba.ErrScopeMissingOpenID):
			emitRejected(ctx, deps, client.ID, "scope missing openid", "scope_missing_openid")
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidScope,
				"the openid scope value is required for ciba")
		default:
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
				"scope parameter is invalid")
		}
		return nil, false
	}
	if !oidcscope.Subset(scope, client.Scopes) {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidScope,
			"requested scope is not permitted for this client")
		return nil, false
	}
	for _, s := range scope {
		if !deps.Scopes.Allows(s, client.ID) {
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidScope,
				"scope is restricted to a different client")
			return nil, false
		}
	}
	return slices.Clone(scope), true
}

// parseACRValues splits the acr_values parameter on ASCII whitespace
// and validates every entry against the OP-advertised list. OIDC Core
// 1.0 §3.1.2.1 (acr_values handling) + CIBA Core 1.0 §7.1 require the
// OP to refuse client-requested ACR values it has not enrolled to
// recognise: silently accepting the request would let a client drive
// the issued id_token's `acr` claim to any string regardless of what
// the OP actually supports.
//
// The validation runs only when [Deps.ACRValuesSupported] is non-empty
// (the operator declared the allowlist in discovery); an empty list
// preserves the legacy "carry verbatim" posture so a deployment that
// did not opt into discovery advertisement is unaffected.
func parseACRValues(w http.ResponseWriter, raw string, deps Deps) ([]string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, true
	}
	values := strings.Fields(trimmed)
	if len(deps.ACRValuesSupported) == 0 {
		return values, true
	}
	for _, v := range values {
		if !slices.Contains(deps.ACRValuesSupported, v) {
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
				"acr_values entry "+v+" is not advertised in acr_values_supported")
			return nil, false
		}
	}
	return values, true
}

// parseBindingMessage dispatches to [ciba.ValidateBindingMessage]
// and maps the sentinel onto the wire response.
func parseBindingMessage(w http.ResponseWriter, raw string) (string, bool) {
	value, err := ciba.ValidateBindingMessage(raw)
	if err != nil {
		if errors.Is(err, ciba.ErrBindingMessageTooLong) {
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidBindingMessage,
				"binding_message exceeds the OP-supported length")
			return "", false
		}
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidBindingMessage,
			"binding_message is invalid")
		return "", false
	}
	return value, true
}

// parseRequestedExpiry dispatches to [ciba.ParseRequestedExpirySeconds] and
// maps the sentinel onto the wire response. A zero return value means
// the client did not supply requested_expiry; the caller substitutes
// [Deps.effectiveExpiresIn].
//
// Under FAPI-CIBA the helper additionally enforces the FAPI-CIBA-ID1
// §5 / FAPI 2.0 §3.1.9 ten-minute lifetime cap as a hard reject:
// requested_expiry above [FAPICIBAMaxExpiry] surfaces as
// invalid_request rather than being clamped silently. The
// non-FAPI-CIBA path keeps the legacy clamp posture so vanilla
// deployments still tolerate over-spec asks against
// [Deps.MaxExpiresIn].
func parseRequestedExpiry(
	w http.ResponseWriter,
	raw string,
	deps Deps,
) (time.Duration, bool) {
	seconds, err := ciba.ParseRequestedExpirySeconds(raw)
	if err != nil {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
			"requested_expiry must be a positive integer")
		return 0, false
	}
	if deps.FAPICIBAProfileActive && seconds > int64(FAPICIBAMaxExpiry.Seconds()) {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
			"requested_expiry exceeds FAPI-CIBA 10-minute cap")
		return 0, false
	}
	value := ciba.ExpiryFromSeconds(seconds, deps.MaxExpiresIn)
	if value == 0 {
		return deps.effectiveExpiresIn(), true
	}
	return value, true
}

// parseUserCode validates the user_code form parameter. The library
// does not advertise `backchannel_user_code_parameter_supported=true`
// in discovery (the option to flip the flag is reserved for a future
// release), and CIBA Core 1.0 §7.1 requires a client to refrain from
// sending parameters the OP has not advertised. The handler therefore
// rejects any non-empty user_code with invalid_request rather than
// silently stamping it onto the persisted record where it would have
// no downstream effect.
func parseUserCode(w http.ResponseWriter, raw string) (string, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", true
	}
	endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
		"user_code parameter is not supported")
	return "", false
}

func parseClientNotificationToken(w http.ResponseWriter, raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return true
	}
	endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
		"client_notification_token parameter is not supported")
	return false
}
