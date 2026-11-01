package parendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/op/store"
)

// successResponse is the §2.2 PAR response body. The library always emits
// the request_uri and expires_in members; per the RFC there is no other
// optional field, so a fixed-shape struct suffices.
type successResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

// serve is the request-scoped entry point. It validates the request shape,
// authenticates the client, parses the carried authorization parameters,
// validates them against the registered client, and persists the resulting
// PAR record. Decomposing the body keeps the function under cyclop's
// max-complexity gate while remaining readable.
func serve(w http.ResponseWriter, r *http.Request, deps Deps) {
	if !httpx.EnforceMethod(w, r, http.MethodPost) {
		return
	}
	if !endpointsupport.IsFormContent(r.Header.Get("Content-Type")) {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
			"content-type must be application/x-www-form-urlencoded")
		return
	}
	endpointsupport.LimitFormBody(w, r)
	if err := r.ParseForm(); err != nil {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest, "malformed form body")
		return
	}
	dpopJKT, client, ok := authenticateWithDPoP(w, r, deps)
	if !ok {
		return
	}
	values := stripAuthFields(r.PostForm)
	// RFC 9126 §3 forbids "request_uri" inside a /par body — the
	// endpoint is the *issuer* of those URIs. The check runs before
	// JAR consumption because [jar.Merge] silently strips the form
	// "request_uri" key, which would otherwise let a request that
	// pairs a signed "request" with a forbidden "request_uri" survive
	// to the parser unscathed.
	if values.Get("request_uri") != "" {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
			"request_uri is not permitted in a /par request")
		return
	}
	values, ok = consumeJARRequestObject(r.Context(), w, deps, client, values)
	if !ok {
		return
	}
	values, ok = applyDPoPJKT(w, values, dpopJKT)
	if !ok {
		return
	}
	req, ok := parseAuthorizeRequest(w, values, client.ID)
	if !ok {
		return
	}
	applyClaimsToggle(req, deps.ClaimsParameterEnabled)
	// RFC 9126 §2.1 has the AS validate the pushed parameters here, so
	// /par admits exactly the effective request /authorize would.
	if err := req.ValidateEffectiveRequest(client, deps.Scopes, deps.RequestPolicy, deps.ACRValuesSupported); err != nil {
		writeAuthorizeError(w, err)
		return
	}
	if !validateRequestExtensions(w, r, deps, req, client) {
		return
	}
	persist(r.Context(), w, deps, req)
}

// validateRequestExtensions runs the RFC 9396 authorization_details, Grant
// Management draft, and RFC 9449 §10.1 "dpop_jkt" gates at push time.
//
// The rules live in [authorize.Request.ValidateExtensions] and the policy
// in [Deps.ExtensionPolicy], both shared with the authorization endpoint
// rather than reassembled here. That sharing is the point: /par and
// /authorize are consecutive gates on the same request, and a rule that
// fires at only one of them mints a request_uri whose one-time value the RP
// spends on a request the next gate refuses, stranding the user with no way
// forward. This function only renders — per RFC 9126 §2.3 the PAR response
// is always a JSON envelope, because the redirect_uri may not be trusted (or
// even known) by the time the call arrives.
//
// The gates run after [authorize.Request.Validate] so a malformed request is
// faulted on its shape before it is faulted on an extension, matching the
// order /authorize applies.
//
// Returns false when it wrote an error response.
func validateRequestExtensions(
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
	req *authorize.Request,
	client *store.Client,
) bool {
	rejection := req.ValidateExtensions(r.Context(), client, deps.ExtensionPolicy)
	if rejection == nil {
		return true
	}
	endpointsupport.WriteOAuthError(w, http.StatusBadRequest, rejection.Code, rejection.Description)
	return false
}

// consumeJARRequestObject inspects the (post-strip) PAR form values for
// a "request" parameter. When present it verifies the JWT against the
// authenticated client and merges the claims onto the form values per
// RFC 9101 §6.1. A nil [Deps.JAR] means the OP has not enabled JAR; the
// request is rejected with invalid_request_object.
//
// "request_uri" inside a /par body is forbidden by RFC 9126 §3; [serve]
// rejects it before this function runs, and [jar.Merge] never carries
// one onto the merged values.
//
// The returned bool is false when the function wrote the response; the
// caller then stops processing.
func consumeJARRequestObject(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	values url.Values,
) (url.Values, bool) {
	raw := values.Get("request")
	if raw == "" {
		if deps.RequireSignedRequestObject {
			// No JWT was supplied at all, so RFC 9101 §6.1's
			// invalid_request_object code does not apply (there is
			// no request object to fault). FAPI 2.0 Message Signing
			// §5.6 leaves the code unspecified, and the OFCS PAR-2.3
			// expectation is the generic invalid_request — a
			// missing required parameter is the canonical
			// invalid_request shape per RFC 6749 §5.2.
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
				"request object is required by the active profile")
			return nil, false
		}
		return values, true
	}
	if deps.JAR == nil {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequestObject,
			"request is not supported by this OP")
		return nil, false
	}
	obj, err := deps.JAR.Verify(ctx, raw, client.ID, client)
	if err != nil {
		writeJARError(w, err)
		return nil, false
	}
	// RFC 9101 §6.3: only the signed object's parameters are used here.
	merged, err := jar.Merge(values, obj, jar.MergeObjectOnly)
	if err != nil {
		writeJARError(w, err)
		return nil, false
	}
	return merged, true
}

// writeJARError translates a [jar] sentinel into the OAuth wire
// envelope. The taxonomy mirrors the authorize endpoint (alg /
// signature / claim failures map to invalid_request_object;
// client_id mismatches map to invalid_request, a key-source fault on
// the OP's side to 503 server_error) so embedders see a uniform shape
// across the two surfaces. The description comes from
// [jar.Description] so the two surfaces cannot disagree about the
// wording either.
func writeJARError(w http.ResponseWriter, err error) {
	status, code := jar.WireError(err)
	endpointsupport.WriteOAuthError(w, status, code, jar.Description(err))
}

// authenticateWithDPoP runs DPoP proof verification and client
// authentication through [endpointsupport.AuthenticateWithDPoP] and
// returns the proof's RFC 7638 thumbprint ("" when no proof was
// presented) alongside the authenticated client.
//
// Two /par-specific consequences of the shared gate's ordering are
// worth naming: the RFC 9449 §8 nonce challenge fires before JAR
// consumption as well as before client authentication, and the
// deferred replay commit keeps an endpoint that is reachable without a
// credential from turning an unauthenticated request rate into storage
// cost. A nil [Deps.DPoP] admits every request without a proof, which
// is what RFC 9449 §10.1 asks of /par: the header is optional there
// even when the feature is wired.
//
// The §10 commitment check against the request's "dpop_jkt" parameter
// (form or merged JAR claim) is separate: it lives in [applyDPoPJKT],
// which runs after JAR merging so the comparison sees the post-merge
// value.
//
// The function writes the response on every failure path; the caller
// only checks the bool.
func authenticateWithDPoP(w http.ResponseWriter, r *http.Request, deps Deps) (string, *store.Client, bool) {
	return endpointsupport.AuthenticateWithDPoP(w, r,
		dpop.Gate{Verifier: deps.DPoP, Nonces: deps.DPoPNonces},
		endpointsupport.AuthenticateOpts{
			Clients:           deps.Clients,
			SecretVerifier:    deps.SecretVerifier,
			AssertionVerifier: deps.AssertionVerifier,
			AllowedMethods:    deps.AllowedClientAuthMethods,
			Now:               deps.now(),
			Audit:             deps.auditEmitter(),
		},
		"client authentication failed at PAR endpoint",
	)
}

// applyDPoPJKT reconciles the proof's thumbprint (from
// [authenticateWithDPoP]) with any "dpop_jkt" already present in values
// (form parameter or merged JAR claim) and stamps the verified value
// onto the snapshot. The split keeps the §8 nonce challenge ahead of
// authentication while still applying RFC 9449 §10:
//
//   - jkt empty (no DPoP header / DPoP off): no-op.
//   - jkt set, values has no dpop_jkt: stamp it so /authorize → /token
//     inherits the binding without the client committing twice.
//   - jkt set, values has dpop_jkt: the two MUST match — a divergence
//     means the client signed a different key than it just committed
//     to, and §10 mandates rejection.
//
// The returned bool is false when the function wrote the response;
// the caller then stops processing.
func applyDPoPJKT(w http.ResponseWriter, values url.Values, jkt string) (url.Values, bool) {
	if jkt == "" {
		return values, true
	}
	committed := values.Get("dpop_jkt")
	if committed != "" && committed != jkt {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
			"DPoP proof key does not match the dpop_jkt commitment")
		return nil, false
	}
	out := jar.CloneValues(values)
	out.Set("dpop_jkt", jkt)
	return out, true
}

// stripAuthFields returns a copy of in with the credential-bearing keys
// removed. Per RFC 9126 §2.1 the PAR endpoint MUST NOT redeliver client
// authentication material in the persisted authorization parameters,
// because the token endpoint will authenticate the client again from a
// fresh request.
//
// client_id is intentionally preserved so [parseAuthorizeRequest] can
// enforce the §2.1 single-id rule (a body client_id that disagrees with
// the authenticated identity is rejected). The authenticated client_id
// supersedes the parsed value before the snapshot is persisted, so the
// stored RawParams still reflect a single coherent identity.
func stripAuthFields(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, v := range in {
		switch k {
		case "client_secret", "client_assertion", "client_assertion_type":
			continue
		default:
			out[k] = append([]string(nil), v...)
		}
	}
	return out
}

// parseAuthorizeRequest parses the post-strip form values via
// [authorize.ParseValues] and verifies that the parsed client_id, when
// present, agrees with the authenticated client. Per RFC 9126 §2.1 the
// authenticated client_id is authoritative; a body that disagrees signals
// a malformed request rather than a credential mismatch.
//
// On any failure the function writes the error envelope and returns
// ok=false. On success the parsed request's ClientID is normalised to the
// authenticated client_id so downstream code does not need to repeat the
// reconciliation.
func parseAuthorizeRequest(w http.ResponseWriter, values url.Values, authenticatedID string) (*authorize.Request, bool) {
	req, err := authorize.ParseValues(values)
	if err != nil {
		writeAuthorizeError(w, err)
		return nil, false
	}
	if req.ClientID != "" && req.ClientID != authenticatedID {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest,
			"client_id does not match the authenticated client")
		return nil, false
	}
	// RFC 9126 §2.1: when the body omits client_id the authenticated
	// client identity stands in for it. Filling the value here keeps the
	// downstream Validate path uniform with /authorize.
	req.ClientID = authenticatedID
	return req, true
}

// applyClaimsToggle enforces op.WithClaimsParameterSupported(false) at
// the /par boundary by clearing any parsed §5.5 payload before the
// snapshot is persisted. The function is a no-op when the toggle is
// on (the wire payload survives onto the snapshot intact) so callers
// can invoke it unconditionally.
func applyClaimsToggle(req *authorize.Request, enabled bool) {
	if enabled {
		return
	}
	req.Claims = nil
}

// writeAuthorizeError translates an [authorize.Error] (or any other error
// returned by parsing / Validate) into the RFC 6749 §5.2 envelope. The PAR
// endpoint never redirects: per RFC 9126 §2.3 the response is always a
// JSON envelope because the redirect_uri may not yet be trusted (or even
// known) by the time the call arrives.
func writeAuthorizeError(w http.ResponseWriter, err error) {
	var ae *authorize.Error
	if errors.As(err, &ae) {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, ae.Code, ae.Description)
		return
	}
	endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest, "request could not be parsed")
}

// persist marshals a [authorize.RequestSnapshot] into the PAR record and
// writes the success envelope. The function performs a single Save call;
// retries on randomness collisions are NOT attempted because a 32-byte
// crypto/rand collision is well below the birthday bound for any
// realistic deployment lifetime.
func persist(ctx context.Context, w http.ResponseWriter, deps Deps, req *authorize.Request) {
	now := deps.now().UTC()
	snapshot := authorize.SnapshotFrom(req, now)
	raw, err := json.Marshal(snapshot)
	if err != nil {
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "could not marshal request snapshot")
		return
	}
	uri, err := newRequestURI()
	if err != nil {
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "could not allocate request_uri")
		return
	}
	expiresAt := now.Add(deps.TTL)
	rec := &store.PushedAuthRequest{
		URI:       uri,
		ClientID:  req.ClientID,
		RawParams: raw,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}
	if err := deps.PARs.Save(ctx, rec); err != nil {
		// ErrAlreadyExists here means a 32-byte collision under
		// crypto/rand — fatal randomness fault. Surface server_error so
		// the operator sees the alarm bell rather than a silent retry.
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "could not persist pushed authorization request")
		return
	}
	writeSuccess(w, successResponse{
		RequestURI: uri,
		ExpiresIn:  int64(deps.TTL.Seconds()),
	})
}

// writeSuccess marshals body and writes it with the cache-control and
// content-type headers RFC 9126 §2.2 owes every successful response. The
// status is 201 Created per the RFC; PAR is a record-creating operation
// so the generic 200 used elsewhere in the library would understate the
// state change.
func writeSuccess(w http.ResponseWriter, body successResponse) {
	httpx.StampNoStore(w)
	_ = httpx.WriteJSON(w, http.StatusCreated, body)
}

// newRequestURI returns a freshly generated PAR URI. The body is
// [uriByteLength] random bytes encoded in base64url-no-pad, giving 256
// bits of entropy (well above the §2.2 "guessing infeasible"
// requirement).
func newRequestURI() (string, error) {
	id, err := keys.RandomBase64URL(uriByteLength)
	if err != nil {
		return "", err
	}
	return authorize.PARRequestURIPrefix + id, nil
}
