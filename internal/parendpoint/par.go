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

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
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
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "malformed form body")
		return
	}
	client, _, ok := authenticate(r.Context(), w, r, deps)
	if !ok {
		return
	}
	values := stripAuthFields(r.PostForm)
	req, ok := parseAuthorizeRequest(w, values, client.ID)
	if !ok {
		return
	}
	if err := req.Validate(client, deps.Scopes); err != nil {
		writeAuthorizeError(w, err)
		return
	}
	persist(r.Context(), w, deps, req)
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
// looks the client up in the registry, and verifies the credentials. It
// mirrors the token endpoint's helper so the two surfaces share an
// identical authentication contract.
//
// The function emits its own response on every failure path so the caller
// only checks the bool: false means "stop, response written".
func authenticate(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
) (*store.Client, *authn.Credentials, bool) {
	creds, err := authn.Parse(r)
	usedBasic := r.Header.Get("Authorization") != ""
	if err != nil {
		writeAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	if creds.Method == authn.MethodPrivateKeyJWT && deps.AssertionVerifier == nil {
		writeInvalidClient(w, usedBasic, "private_key_jwt is not enabled")
		return nil, nil, false
	}
	client, err := lookupClient(ctx, deps.Clients, creds.ClientID)
	if err != nil {
		writeAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	if _, err := authn.VerifyClient(ctx, creds, client, authn.VerifyOpts{
		SecretVerifier:    deps.SecretVerifier,
		AssertionVerifier: deps.AssertionVerifier,
	}); err != nil {
		writeAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	return client, creds, true
}

// lookupClient resolves the registered client for id, mapping
// [store.ErrNotFound] to [authn.ErrCredentialsInvalid] so the caller
// cannot tell "unknown client" apart from "wrong secret" through the
// error surface.
func lookupClient(ctx context.Context, clients store.ClientStore, id string) (*store.Client, error) {
	if id == "" {
		return nil, authn.ErrCredentialsInvalid
	}
	c, err := clients.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, authn.ErrCredentialsInvalid
		}
		return nil, err
	}
	return c, nil
}

// writeAuthnError maps an authentication error onto the wire response.
// The mapping is the canonical RFC 6749 §5.2 table augmented by this
// library's sentinel discrimination, identical to the token endpoint.
func writeAuthnError(w http.ResponseWriter, err error, usedBasic bool) {
	switch {
	case errors.Is(err, authn.ErrNoCredentials):
		writeInvalidClient(w, usedBasic, "client authentication required")
	case errors.Is(err, authn.ErrAmbiguousCredentials),
		errors.Is(err, authn.ErrUnsupportedMethod):
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"client authentication parameters are malformed")
	case errors.Is(err, authn.ErrClientMismatch),
		errors.Is(err, authn.ErrCredentialsInvalid),
		errors.Is(err, authn.ErrAssertionMalformed),
		errors.Is(err, authn.ErrAssertionReplayed):
		writeInvalidClient(w, usedBasic, "client authentication failed")
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
	}
}

// newRequestURI returns a freshly generated PAR URI. The body is 32 bytes
// of crypto/rand encoded in base64url-no-pad, giving 256 bits of entropy
// (well above the §2.2 "guessing infeasible" requirement).
func newRequestURI() (string, error) {
	buf := make([]byte, uriByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("parendpoint: read random: %w", err)
	}
	return uriPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}
