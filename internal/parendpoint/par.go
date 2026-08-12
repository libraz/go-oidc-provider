package parendpoint

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/clientauth/clientauthhttp"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/jar"
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
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		stampNoStore(w)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isFormContent(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"content-type must be application/x-www-form-urlencoded")
		return
	}
	endpointsupport.LimitFormBody(w, r)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "malformed form body")
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
		writeError(w, http.StatusBadRequest, errInvalidRequest,
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
	if err := req.Validate(client, deps.Scopes, deps.RequestPolicy); err != nil {
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
	writeError(w, http.StatusBadRequest, rejection.Code, rejection.Description)
	return false
}

// consumeJARRequestObject inspects the (post-strip) PAR form values for
// a "request" parameter. When present it verifies the JWT against the
// authenticated client and merges the claims onto the form values per
// RFC 9101 §6.1. A nil [Deps.JAR] means the OP has not enabled JAR; the
// request is rejected with invalid_request_object.
//
// "request_uri" inside a /par body is forbidden by RFC 9126 §3 — the
// downstream parser ([parseAuthorizeRequest]) enforces that rule, so
// this function does not need to repeat it.
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
			writeError(w, http.StatusBadRequest, errInvalidRequest,
				"request object is required by the active profile")
			return nil, false
		}
		return values, true
	}
	if deps.JAR == nil {
		writeError(w, http.StatusBadRequest, errInvalidRequestObject,
			"request is not supported by this OP")
		return nil, false
	}
	obj, err := deps.JAR.Verify(ctx, raw, client.ID, client)
	if err != nil {
		writeJARError(w, err)
		return nil, false
	}
	merged, err := jar.Merge(values, obj)
	if err != nil {
		writeJARError(w, err)
		return nil, false
	}
	return merged, true
}

// writeJARError translates a [jar] sentinel into the OAuth wire
// envelope. The taxonomy mirrors the authorize endpoint (alg /
// signature / claim failures map to invalid_request_object;
// client_id mismatches map to invalid_request) so embedders see a
// uniform shape across the two surfaces. The description comes from
// [jar.Description] so the two surfaces cannot disagree about the
// wording either.
func writeJARError(w http.ResponseWriter, err error) {
	if errors.Is(err, jar.ErrClientIDMismatch) {
		writeError(w, http.StatusBadRequest, errInvalidRequest, jar.Description(err))
		return
	}
	writeError(w, http.StatusBadRequest, errInvalidRequestObject, jar.Description(err))
}

// authenticateWithDPoP runs DPoP proof verification and client
// authentication in the one order that satisfies both of the
// constraints the two mechanisms impose, and returns the proof's RFC
// 7638 thumbprint ("" when no proof was presented) alongside the
// authenticated client.
//
// Proof verification runs FIRST so the RFC 9449 §8 `use_dpop_nonce`
// challenge fires before any client_assertion jti is consumed: §8
// contemplates a verbatim retry of the client-side request body with
// only the proof refreshed, and RP libraries (OFCS included) rebuild
// only the DPoP header, reusing the original client_assertion. Marking
// the assertion's jti on the first attempt would surface on the retry
// as invalid_client / ErrAssertionReplayed. Nothing in the verification
// depends on the resolved client identity — the proof is bound to the
// request and to its own key, never to the client's credential.
//
// The proof's replay marker is written LAST, after authentication
// succeeds. /par is reachable without a credential, so that write is
// the one place where an unauthenticated request rate would translate
// into storage cost. Deferring it weakens nothing: the marker still
// lands before the endpoint acts on the request, and a proof replayed
// on a request that cannot authenticate is refused on the credential
// instead. The token endpoint applies the identical ordering.
//
// The function writes the response on every failure path; the caller
// only checks the bool.
func authenticateWithDPoP(w http.ResponseWriter, r *http.Request, deps Deps) (string, *store.Client, bool) {
	checked, ok := verifyDPoPProof(r, w, deps)
	if !ok {
		return "", nil, false
	}
	client, _, ok := authenticate(r.Context(), w, r, deps)
	if !ok {
		return "", nil, false
	}
	if !commitDPoPProof(r.Context(), w, deps, checked) {
		return "", nil, false
	}
	return checkedJKT(checked), client, true
}

// verifyDPoPProof runs the stateless RFC 9449 §4.3 gates over the
// optional DPoP header on the /par request and returns the accepted
// proof when one was presented. The function runs ahead of client
// authentication and JAR consumption so the §8 nonce challenge can
// fire before any jti-bearing credential is consumed; the §10
// commitment check against the request's "dpop_jkt" parameter (form or
// merged JAR claim) lives in [applyDPoPJKT], which runs after JAR
// merging so the comparison sees the post-merge value.
//
// The proof is not single-use until [commitDPoPProof] has run; see
// [authenticateWithDPoP] for why the two phases are kept apart.
//
// A nil [Deps.DPoP] disables verification; a missing DPoP header is
// always tolerated because RFC 9449 §10.1 makes the header optional
// at /par. Errors emit the response body and the function returns
// ok=false so the caller stops.
func verifyDPoPProof(r *http.Request, w http.ResponseWriter, deps Deps) (*dpop.Checked, bool) {
	if deps.DPoP == nil {
		return nil, true
	}
	if r.Header.Get("DPoP") == "" {
		return nil, true
	}
	checked, err := deps.DPoP.CheckHTTPRequest(r.Context(), r, "")
	if err != nil {
		writeDPoPError(w, deps, err)
		return nil, false
	}
	return checked, true
}

// commitDPoPProof writes the replay marker for the proof
// [verifyDPoPProof] accepted, making it single-use. It is a no-op when
// no proof was presented. The function emits the response and returns
// false on failure; a repeated or concurrent use of the same proof
// surfaces through the same [dpop.WriteError] mapping the single-phase
// verifier produced.
func commitDPoPProof(ctx context.Context, w http.ResponseWriter, deps Deps, checked *dpop.Checked) bool {
	if checked == nil {
		return true
	}
	if err := deps.DPoP.Commit(ctx, checked); err != nil {
		writeDPoPError(w, deps, err)
		return false
	}
	return true
}

// checkedJKT returns the proof's RFC 7638 thumbprint, or "" when no
// proof was presented. The helper keeps the nil handling out of
// [serve].
func checkedJKT(checked *dpop.Checked) string {
	if checked == nil {
		return ""
	}
	return checked.JKT
}

// applyDPoPJKT reconciles the proof's thumbprint (from
// [verifyDPoPProof]) with any "dpop_jkt" already present in values
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
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"DPoP proof key does not match the dpop_jkt commitment")
		return nil, false
	}
	out := cloneValues(values)
	out.Set("dpop_jkt", jkt)
	return out, true
}

// cloneValues returns a deep copy of in so [bindDPoPProof] can mutate
// the returned value without aliasing the caller's slice headers.
func cloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// writeDPoPError translates a dpop.Err* sentinel onto the wire form.
// The package-local helper is a thin wrapper over [dpop.WriteError]
// so the token / PAR / future endpoints share an identical
// boundary mapping; see the godoc on [dpop.WriteError] for the wire
// taxonomy. The PAR-specific default branch ("DPoP proof verification
// failed") is intentionally collapsed onto the shared 500 server_error
// fallback — an unknown sentinel is a programmer bug, not a wire
// condition the client can act on.
func writeDPoPError(w http.ResponseWriter, deps Deps, err error) {
	dpop.WriteError(context.Background(), w, err, dpop.NonceSourceFromIssuer(deps.DPoPNonces))
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
	// RFC 9126 §2.3 forbids request_uri inside a /par body — the endpoint
	// is the *issuer* of those URIs, so accepting one in the post body
	// would invite recursive lookups. Reject before parsing so the error
	// message stays specific.
	if values.Get("request_uri") != "" {
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"request_uri is not permitted in a /par request")
		return nil, false
	}
	req, err := authorize.ParseValues(values)
	if err != nil {
		writeAuthorizeError(w, err)
		return nil, false
	}
	if req.ClientID != "" && req.ClientID != authenticatedID {
		writeError(w, http.StatusBadRequest, errInvalidRequest,
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
		writeError(w, http.StatusBadRequest, ae.Code, ae.Description)
		return
	}
	writeError(w, http.StatusBadRequest, errInvalidRequest, "request could not be parsed")
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
		writeError(w, http.StatusInternalServerError, errServerError, "could not marshal request snapshot")
		return
	}
	uri, err := newRequestURI()
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "could not allocate request_uri")
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
		writeError(w, http.StatusInternalServerError, errServerError, "could not persist pushed authorization request")
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
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(body)
}

// authenticate resolves the client credentials carried by the request,
// looks the client up in the registry, and verifies the credentials. The
// helper delegates to a per-request [clientauthhttp.Authenticator] so
// /par and /token share an identical authentication contract.
//
// The function emits its own response on every failure path so the caller
// only checks the bool: false means "stop, response written". Each
// failure path also raises a "client_authn.failure" audit event so SOC
// tooling can spot probing for a known client_id even though RFC 6749
// §5.2 mandates the wire response stays at the generic "invalid_client"
// code.
func authenticate(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
) (*store.Client, *clientauth.Credentials, bool) {
	authenticator := clientauthhttp.Authenticator{
		Clients:           deps.Clients,
		SecretVerifier:    deps.SecretVerifier,
		AssertionVerifier: deps.AssertionVerifier,
		AllowedMethods:    deps.AllowedClientAuthMethods,
		Audit:             deps.auditEmitter(),
		AuditEventName:    auditClientAuthnFailure,
		AuditMessage:      "client authentication failed at PAR endpoint",
	}
	return authenticator.Authenticate(ctx, w, r)
}

// newRequestURI returns a freshly generated PAR URI. The body is 32 bytes
// of crypto/rand encoded in base64url-no-pad, giving 256 bits of entropy
// (well above the §2.2 "guessing infeasible" requirement).
func newRequestURI() (string, error) {
	buf := make([]byte, uriByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("parendpoint: read random: %w", err)
	}
	return authorize.PARRequestURIPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}
