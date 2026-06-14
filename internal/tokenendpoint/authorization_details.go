package tokenendpoint

import (
	"errors"
	"net/http"
	"reflect"

	"github.com/libraz/go-oidc-provider/internal/authorizationdetails"
	"github.com/libraz/go-oidc-provider/op/store"
)

func parseTokenAuthorizationDetails(w http.ResponseWriter, r *http.Request, deps Deps, client *store.Client) ([]map[string]any, bool) {
	raw := r.PostForm.Get("authorization_details")
	if raw == "" || len(deps.AuthorizationDetailTypes) == 0 {
		return nil, true
	}
	details, err := authorizationdetails.Check(r.Context(), raw, client, deps.AuthorizationDetailTypes)
	if err != nil {
		code := errInvalidAuthzDetails
		if errors.Is(err, authorizationdetails.ErrTooLarge) {
			code = errInvalidRequest
		}
		writeError(w, http.StatusBadRequest, code, "authorization_details is not acceptable")
		return nil, false
	}
	return details, true
}

func reduceAuthorizationDetails(w http.ResponseWriter, requested, granted []map[string]any) ([]map[string]any, bool) {
	if len(requested) == 0 {
		return granted, true
	}
	for _, want := range requested {
		found := false
		for _, have := range granted {
			if reflect.DeepEqual(have, want) {
				found = true
				break
			}
		}
		if !found {
			writeError(w, http.StatusBadRequest, errInvalidAuthzDetails, "authorization_details exceeds the granted authorization")
			return nil, false
		}
	}
	return requested, true
}
