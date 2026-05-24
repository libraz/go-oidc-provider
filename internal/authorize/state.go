package authorize

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// RequestSnapshot is a JSON-serialisable view of a validated [Request]. It is
// the shape the HTTP layer persists in [op/store.Interaction.RawState] across
// the redirects between /authorize and /interaction/{uid}: the cookie carries
// the UID, the store carries the snapshot, and the snapshot is enough to
// recover a [Request] without re-parsing the original wire form.
//
// Only fields that materially affect the authorize-endpoint decision are
// captured. Fields that only matter pre-validation (e.g. duplicate-parameter
// detection) are not round-tripped because the snapshot is taken after a
// successful Validate.
type RequestSnapshot struct {
	// ClientID mirrors [Request.ClientID].
	ClientID string `json:"client_id"`

	// ResponseType mirrors [Request.ResponseType].
	ResponseType string `json:"response_type"`

	// RedirectURI mirrors [Request.RedirectURI].
	RedirectURI string `json:"redirect_uri"`

	// State mirrors [Request.State].
	State string `json:"state"`

	// Nonce mirrors [Request.Nonce].
	Nonce string `json:"nonce"`

	// CodeChallenge mirrors [Request.CodeChallenge].
	CodeChallenge string `json:"code_challenge"`

	// CodeChallengeMethod mirrors [Request.CodeChallengeMethod].
	CodeChallengeMethod string `json:"code_challenge_method"`

	// Scope mirrors [Request.Scope].
	Scope []string `json:"scope,omitempty"`

	// Resource mirrors [Request.Resource].
	Resource string `json:"resource,omitempty"`

	// Prompt mirrors [Request.Prompt].
	Prompt []string `json:"prompt,omitempty"`

	// ACRValues mirrors [Request.ACRValues].
	ACRValues []string `json:"acr_values,omitempty"`

	// UILocales mirrors [Request.UILocales].
	UILocales []string `json:"ui_locales,omitempty"`

	// MaxAge mirrors [Request.MaxAge]. The pointer survives the round-trip
	// so callers can still distinguish "absent" from a literal "0".
	MaxAge *int64 `json:"max_age,omitempty"`

	// LoginHint mirrors [Request.LoginHint].
	LoginHint string `json:"login_hint,omitempty"`

	// ResponseMode mirrors [Request.ResponseMode]. The field round-trips
	// across the interaction redirect so the post-interaction success /
	// error emitter can dispatch JARM as the original request asked.
	ResponseMode string `json:"response_mode,omitempty"`

	// DPoPJKT mirrors [Request.DPoPJKT]. The snapshot carries it across
	// the interaction redirect so the eventual authorization_code can
	// be bound to the same DPoP key the client committed to at the
	// authorization endpoint.
	DPoPJKT string `json:"dpop_jkt,omitempty"`

	// PARRequestURI mirrors [Request.PARRequestURI]. The snapshot
	// carries it across the interaction redirect so the eventual code
	// emission can mark the PAR record one-time-used (RFC 9126 §2.2).
	// Empty when the request did not arrive via /par.
	PARRequestURI string `json:"par_request_uri,omitempty"`

	// Claims mirrors [Request.Claims]. The snapshot persists the
	// parsed OIDC Core 1.0 §5.5 "claims" parameter so the token
	// endpoint and userinfo endpoint can project the requested
	// claims without re-parsing the wire form.
	Claims *ClaimsRequest `json:"claims,omitempty"`

	// AuthorizationDetails mirrors [Request.AuthorizationDetails]. The
	// snapshot persists the validated RFC 9396 authorization_details
	// across the interaction redirect so the grant emission path can
	// store them and the token endpoint can echo them.
	AuthorizationDetails []map[string]any `json:"authorization_details,omitempty"`

	// GrantManagementAction / GrantID mirror the Grant Management draft
	// request parameters across the interaction redirect so the grant
	// emission path can apply create / replace / merge to the right
	// target after authentication completes.
	GrantManagementAction string `json:"grant_management_action,omitempty"`
	GrantID               string `json:"grant_id,omitempty"`

	// CreatedUnix is the unix-seconds timestamp at which the snapshot was
	// taken. The HTTP layer uses it for diagnostic logging; the field is
	// not consumed by [RequestSnapshot.ToRequest].
	CreatedUnix int64 `json:"created_unix"`
}

// SnapshotFrom captures the validated [Request] into a serialisable shape.
// The supplied now is recorded verbatim into [RequestSnapshot.CreatedUnix]
// so the caller controls the wall-clock reading (no implicit time.Now()).
//
// SnapshotFrom does not validate req — the caller is expected to have run
// [Request.Validate] first. A nil req returns the zero snapshot, which the
// caller can detect by [RequestSnapshot.ClientID] being empty.
func SnapshotFrom(req *Request, now time.Time) RequestSnapshot {
	if req == nil {
		return RequestSnapshot{CreatedUnix: now.UTC().Unix()}
	}
	var maxAge *int64
	if req.MaxAge != nil {
		v := *req.MaxAge
		maxAge = &v
	}
	return RequestSnapshot{
		ClientID:              req.ClientID,
		ResponseType:          req.ResponseType,
		RedirectURI:           req.RedirectURI,
		State:                 req.State,
		Nonce:                 req.Nonce,
		CodeChallenge:         req.CodeChallenge,
		CodeChallengeMethod:   req.CodeChallengeMethod,
		Scope:                 slices.Clone(req.Scope),
		Resource:              req.Resource,
		Prompt:                slices.Clone(req.Prompt),
		ACRValues:             slices.Clone(req.ACRValues),
		UILocales:             slices.Clone(req.UILocales),
		MaxAge:                maxAge,
		LoginHint:             req.LoginHint,
		ResponseMode:          req.ResponseMode,
		DPoPJKT:               req.DPoPJKT,
		PARRequestURI:         req.PARRequestURI,
		Claims:                CloneClaimsRequest(req.Claims),
		AuthorizationDetails:  cloneAuthorizationDetails(req.AuthorizationDetails),
		GrantManagementAction: req.GrantManagementAction,
		GrantID:               req.GrantID,
		CreatedUnix:           now.UTC().Unix(),
	}
}

// ToRequest reverses [SnapshotFrom]. The returned [*Request] is a fresh
// allocation suitable for handing to downstream code that consumes the
// validated request shape (token issuance, audit logging).
func (s RequestSnapshot) ToRequest() *Request {
	var maxAge *int64
	if s.MaxAge != nil {
		v := *s.MaxAge
		maxAge = &v
	}
	return &Request{
		ClientID:              s.ClientID,
		ResponseType:          s.ResponseType,
		RedirectURI:           s.RedirectURI,
		State:                 s.State,
		Nonce:                 s.Nonce,
		CodeChallenge:         s.CodeChallenge,
		CodeChallengeMethod:   s.CodeChallengeMethod,
		Scope:                 slices.Clone(s.Scope),
		Resource:              s.Resource,
		Prompt:                slices.Clone(s.Prompt),
		ACRValues:             slices.Clone(s.ACRValues),
		UILocales:             slices.Clone(s.UILocales),
		MaxAge:                maxAge,
		LoginHint:             s.LoginHint,
		ResponseMode:          s.ResponseMode,
		DPoPJKT:               s.DPoPJKT,
		PARRequestURI:         s.PARRequestURI,
		Claims:                CloneClaimsRequest(s.Claims),
		AuthorizationDetails:  cloneAuthorizationDetails(s.AuthorizationDetails),
		GrantManagementAction: s.GrantManagementAction,
		GrantID:               s.GrantID,
	}
}

// cloneAuthorizationDetails deep-copies the authorization_details slice so
// the snapshot and the restored request do not alias the same maps. A nil
// or empty slice round-trips as nil so the json:omitempty tag drops it.
func cloneAuthorizationDetails(in []map[string]any) []map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make([]map[string]any, len(in))
	for i, el := range in {
		if el == nil {
			continue
		}
		cp := make(map[string]any, len(el))
		for k, v := range el {
			cp[k] = v
		}
		out[i] = cp
	}
	return out
}

// RequestState is the on-disk shape persisted in [op/store.Interaction.RawState].
// It composes the library snapshot with the orchestrator's chain state so
// the two halves can be loaded together on every /interaction request.
//
// The Authn field is intentionally a raw JSON blob from this package's
// perspective: the orchestrator owns its own [authn.State] schema and
// the authorizeendpoint encodes / decodes it through that package.
// Keeping the encoding hidden behind a [json.RawMessage] avoids an
// import cycle (authorize → authn → op → authorizeendpoint → authorize)
// while still letting the HTTP layer round-trip the structured state.
type RequestState struct {
	// Library is the validated authorization request the OP needs to mint
	// the eventual code. The HTTP layer never mutates this field after the
	// initial snapshot — it is the trusted view of the original request.
	Library RequestSnapshot `json:"library"`

	// Authn is the orchestrator chain state encoded as JSON. The library
	// round-trips it verbatim across Save / Find calls; only the
	// authorizeendpoint package decodes it through internal/authn.
	Authn json.RawMessage `json:"authn,omitempty"`
}

// MarshalState serialises s for storage. The function is a thin wrapper over
// [json.Marshal]; it exists so callers do not need to know the encoding.
func MarshalState(s RequestState) ([]byte, error) {
	out, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("authorize: marshal state: %w", err)
	}
	return out, nil
}

// UnmarshalState parses a previously-marshalled [RequestState]. A malformed
// blob produces a wrapped JSON error so the caller can distinguish "library
// bug" from "store corruption".
func UnmarshalState(b []byte) (RequestState, error) {
	var out RequestState
	if err := json.Unmarshal(b, &out); err != nil {
		return RequestState{}, fmt.Errorf("authorize: unmarshal state: %w", err)
	}
	return out, nil
}
