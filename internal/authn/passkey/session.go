package passkey

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Session is the per-ceremony state the library emits at BeginRegistration
// / BeginLogin and consumes at the matching Finish call. The interaction
// layer ferries it through an encrypted cookie or, for SSR-driven flows,
// through an [github.com/libraz/go-oidc-provider/op/store.Interaction]
// row. The shape is deliberately small so it fits comfortably inside a
// 4 KiB cookie even under base64+encryption overhead.
//
// The session is NOT the persistent credential record: it carries the
// challenge bytes and (for assertions) the allow-list of credential IDs
// the authenticator may speak back, and it expires within minutes.
// Callers MUST drop the session as soon as the matching Finish call
// returns (success or error) — replaying it would let an attacker reuse
// the same challenge, defeating the WebAuthn replay defence.
type Session struct {
	// Challenge is the base64url-encoded challenge the SPA echoes
	// back inside the authenticator response. The library's
	// [webauthn.SessionData] keeps it as a string; we round-trip the
	// same encoding so the JSON form is interoperable with anyone
	// reading the upstream session shape.
	Challenge string `json:"challenge"`

	// UserID is the WebAuthn user handle (i.e. the OP subject as
	// UTF-8 bytes — see [webauthnUser]). It is bound into the
	// CredentialCreationOptions so the authenticator's resident-key
	// store can de-duplicate and so the FinishRegistration check can
	// match the response to the issuing user. Empty for discoverable
	// (passkey) login sessions; v1.0 does not emit such sessions but
	// the field is preserved for forward compatibility with v1.x.
	UserID []byte `json:"user_id,omitempty"`

	// AllowedCredentialIDs is populated for assertion sessions and
	// constrains which credentials the user agent may surface. It is
	// always nil for registration sessions.
	AllowedCredentialIDs [][]byte `json:"allowed_credential_ids,omitempty"`

	// Expires is the absolute wall-clock instant after which the
	// session is treated as stale. The verifier checks it against
	// its [timex.Clock] reading and rejects expired sessions with
	// [ErrChallengeExpired]. Always serialised in UTC so the JSON
	// form is timezone-agnostic.
	Expires time.Time `json:"expires"`

	// UserVerification mirrors [webauthn.SessionData.UserVerification]
	// and is one of "required", "preferred", "discouraged", or empty.
	// The library round-trips it through the cookie so the policy
	// observed at the matching Finish call is exactly the one
	// declared at Begin.
	UserVerification string `json:"user_verification,omitempty"`
}

// MarshalJSON renders the session as a stable JSON object. The output
// is deterministic for a given Session value (modulo Go's map ordering,
// which the struct-based encoder does not exercise) so cookie payloads
// are stable across library versions.
func (s Session) MarshalJSON() ([]byte, error) {
	type wire struct {
		Challenge            string    `json:"challenge"`
		UserID               []byte    `json:"user_id,omitempty"`
		AllowedCredentialIDs [][]byte  `json:"allowed_credential_ids,omitempty"`
		Expires              time.Time `json:"expires"`
		UserVerification     string    `json:"user_verification,omitempty"`
	}
	w := wire{
		Challenge:            s.Challenge,
		UserID:               s.UserID,
		AllowedCredentialIDs: s.AllowedCredentialIDs,
		Expires:              s.Expires.UTC(),
		UserVerification:     s.UserVerification,
	}
	return json.Marshal(w)
}

// UnmarshalJSON is the inverse of [Session.MarshalJSON]. It rehydrates
// a session that was previously encoded to a cookie payload. The
// timestamps are parsed in UTC; callers should not assume the original
// timezone survived the round-trip.
func (s *Session) UnmarshalJSON(data []byte) error {
	type wire struct {
		Challenge            string    `json:"challenge"`
		UserID               []byte    `json:"user_id,omitempty"`
		AllowedCredentialIDs [][]byte  `json:"allowed_credential_ids,omitempty"`
		Expires              time.Time `json:"expires"`
		UserVerification     string    `json:"user_verification,omitempty"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	s.Challenge = w.Challenge
	s.UserID = w.UserID
	s.AllowedCredentialIDs = w.AllowedCredentialIDs
	s.Expires = w.Expires.UTC()
	s.UserVerification = w.UserVerification
	return nil
}

// encodeSession projects a [webauthn.SessionData] onto the package's
// [Session] shape. It drops fields the library populates but the OP
// does not need to ferry through cookies (Extensions, CredParams,
// Mediation, RelyingPartyID — the verifier reconstructs the latter from
// [Config] on the way back). Any future fields the library adds will be
// preserved across the round-trip only if they appear in [Session].
func encodeSession(sd webauthn.SessionData) Session {
	return Session{
		Challenge:            sd.Challenge,
		UserID:               slices.Clone(sd.UserID),
		AllowedCredentialIDs: cloneByteSlices(sd.AllowedCredentialIDs),
		Expires:              sd.Expires.UTC(),
		UserVerification:     string(sd.UserVerification),
	}
}

// decodeSession is the inverse of [encodeSession]. The RelyingPartyID
// is intentionally NOT populated from the session: the library
// validates the assertion against [webauthn.Config.RPID] instead, and
// allowing a cookie-supplied RPID would let an attacker steer the check
// to a different domain.
func decodeSession(s Session) webauthn.SessionData {
	return webauthn.SessionData{
		Challenge:            s.Challenge,
		UserID:               slices.Clone(s.UserID),
		AllowedCredentialIDs: cloneByteSlices(s.AllowedCredentialIDs),
		Expires:              s.Expires.UTC(),
		UserVerification:     protocol.UserVerificationRequirement(s.UserVerification),
	}
}

// cloneByteSlices defensively clones a slice-of-byte-slices so the
// caller cannot mutate the underlying buffers after handing them off.
func cloneByteSlices(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i, b := range in {
		out[i] = slices.Clone(b)
	}
	return out
}
