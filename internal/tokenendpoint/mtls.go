package tokenendpoint

import (
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// mtlsOutcome is the result of [verifyTokenMTLS]: a (possibly empty)
// thumbprint plus a flag reporting whether a cert was actually
// presented. The split lets handler code distinguish "no cert,
// issue bearer token" from "cert present, bind to x5t#S256" without
// inspecting the verifier directly. The shape mirrors dpopOutcome so
// the authorization_code and refresh_token orchestration reads as a
// flat composition of two binding mechanisms.
type mtlsOutcome struct {
	// Thumbprint is the RFC 8705 §3.1 thumbprint of the leaf cert.
	// Empty when no cert was presented.
	Thumbprint string

	// Cert is the parsed leaf certificate the verifier extracted
	// from the request. Nil when no cert was presented. Exposed so
	// downstream consumers (e.g. custom-grant dispatch) can include
	// the certificate in audit emission without re-parsing the
	// request.
	Cert *x509.Certificate

	// Presented reports whether the request carried a client cert
	// at all. Useful for refresh-token enforcement: a chain bound
	// to a thumbprint requires a cert to be presented even if the
	// verifier is configured to issue bearer tokens by default.
	Presented bool
}

// verifyTokenMTLS extracts the leaf client certificate from the request
// when the feature is wired and a cert is present. The function emits
// an HTTP error and returns (nil, false) only on a malformed-cert
// payload (a header was supplied but did not parse); a missing cert is
// the bearer / DPoP path and yields (&mtlsOutcome{}, true).
//
// The dpopJKT parameter is retained for call-site symmetry with older
// releases; DPoP presence no longer suppresses mTLS extraction because an
// issued token may carry both cnf.jkt and cnf.x5t#S256.
func verifyTokenMTLS(w http.ResponseWriter, r *http.Request, deps Deps, _ string) (*mtlsOutcome, bool) {
	if deps.MTLS == nil {
		return &mtlsOutcome{}, true
	}
	cert, err := deps.MTLS.CertificateFromRequest(r)
	if err != nil {
		if errors.Is(err, mtls.ErrNoClientCert) {
			// Bearer path: the request did not present a cert and
			// did not opt into mTLS. Nothing to bind.
			return &mtlsOutcome{}, true
		}
		writeMTLSError(w, err)
		return nil, false
	}
	if cert == nil {
		return &mtlsOutcome{}, true
	}
	return &mtlsOutcome{Thumbprint: mtls.Thumbprint(cert), Cert: cert, Presented: true}, true
}

// requireMTLSMatch is the refresh-time variant of [verifyTokenMTLS].
// When boundThumbprint is non-empty (the consumed refresh token was
// mTLS-bound) the function REQUIRES a matching client cert on the
// request; when it is empty the function is a no-op and the caller
// continues with the bearer / DPoP path.
//
// Unlike DPoP — which permits an opportunistic upgrade from a bearer
// chain to a sender-constrained one on first refresh — mTLS does NOT
// auto-upgrade. RFC 8705 §3.1 ties the binding to issuance time, and
// mid-chain upgrades would require the resource server to re-check
// every cached token; the library's posture is "bind once, enforce
// always".
func requireMTLSMatch(w http.ResponseWriter, r *http.Request, deps Deps, boundThumbprint string) bool {
	if boundThumbprint == "" {
		return true
	}
	if deps.MTLS == nil {
		// Refresh chain claims a binding but the verifier is gone:
		// the OP was reconfigured between issuance and refresh. Fail
		// closed — admitting the request would silently downgrade a
		// sender-constrained chain to bearer.
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"refresh token is mTLS-bound but mTLS is not enabled")
		return false
	}
	if err := deps.MTLS.VerifyBoundRequest(r, boundThumbprint); err != nil {
		writeMTLSError(w, err)
		return false
	}
	return true
}

// writeMTLSError translates an [mtls.Err*] sentinel onto the wire
// form. The mapping keeps the same OAuth envelope codes the rest of
// the token endpoint uses: invalid_request for malformed or conflicting
// inputs, invalid_grant for a refresh whose binding does not satisfy,
// and invalid_client (RFC 8705 §3) for a client cert that fails chain
// validation against the configured trust anchors. The wrapped sentinel
// cause is dropped to avoid leaking timing-side-channel signal; logs
// retain it via [errors.Unwrap].
func writeMTLSError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, mtls.ErrNoClientCert):
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"client certificate required for mTLS-bound token")
	case errors.Is(err, mtls.ErrCertMalformed):
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"client certificate malformed")
	case errors.Is(err, mtls.ErrCertSourceConflict):
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"client certificate sources disagree")
	case errors.Is(err, mtls.ErrCertUntrusted):
		endpointsupport.WriteInvalidClient(w, false, "client certificate is not trusted")
	case errors.Is(err, mtls.ErrThumbprintMismatch):
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"client certificate does not match the bound thumbprint")
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
	}
}
