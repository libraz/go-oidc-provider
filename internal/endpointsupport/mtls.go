package endpointsupport

import (
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// ExtractMTLSThumbprint returns the SHA-256 thumbprint of the inbound mTLS
// leaf certificate. It returns ("", true) when v is nil or the request did
// not present a certificate at all; a certificate that was presented but
// unusable writes the wire error and returns ("", false), so the caller
// fails closed instead of silently treating the request as unbound.
func ExtractMTLSThumbprint(w http.ResponseWriter, r *http.Request, v *mtls.Verifier) (string, bool) {
	if v == nil {
		return "", true
	}
	thumb, err := v.ThumbprintFromRequest(r)
	if err != nil {
		if errors.Is(err, mtls.ErrNoClientCert) {
			return "", true
		}
		WriteMTLSError(w, err)
		return "", false
	}
	return thumb, true
}

// WriteMTLSError translates an mtls.Err* sentinel raised while reading the
// client certificate onto the wire: invalid_request for a certificate that
// could not be parsed, invalid_client (RFC 8705 §3) for one that failed
// chain validation against the configured trust anchors, and server_error
// otherwise.
func WriteMTLSError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, mtls.ErrCertMalformed):
		WriteOAuthError(w, http.StatusBadRequest, ErrInvalidRequest, "client certificate malformed")
	case errors.Is(err, mtls.ErrCertUntrusted):
		WriteInvalidClient(w, false, "client certificate is not trusted")
	default:
		WriteServerError(w)
	}
}
