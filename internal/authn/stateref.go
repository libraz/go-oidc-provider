package authn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// stateRefKeyLen is the byte length the orchestrator requires for the
// HMAC-SHA256 key that signs [Prompt.StateRef] continuation tokens. The
// constant is the secret-strength minimum the rest of the codebase uses
// for AES-256-GCM and HMAC-SHA256 keys; treating "32 bytes" as a single
// rule keeps deployments from accidentally choosing a weaker key for
// the orchestrator alone.
const stateRefKeyLen = 32

// stateRefNonceLen is the random-nonce byte length embedded in every
// signed payload. 16 bytes is the standard "uniqueness" budget for
// short-lived tokens — any cross-request collision is computationally
// infeasible — and matches the entropy the cookie codec uses for its
// own nonce field.
const stateRefNonceLen = 16

// ErrStateRefKeyLength is returned by [NewStateRefSigner] when the
// supplied key is not exactly [stateRefKeyLen] bytes. The orchestrator
// surfaces it at construction time so a misconfiguration cannot weaken
// the signer at runtime.
var ErrStateRefKeyLength = errors.New("authn: stateref key must be 32 bytes")

// ErrStateRefMalformed is returned by [StateRefSigner.Verify] when the
// supplied token does not parse as `<payload>.<mac>` base64url segments
// or the embedded JSON is invalid. The error is intentionally opaque
// to the SPA: the orchestrator collapses every failure mode to the
// same response shape so the relying party cannot probe the format.
var ErrStateRefMalformed = errors.New("authn: stateref malformed")

// ErrStateRefSignature is returned when the HMAC tag does not match
// the payload bytes. It signals tampering or a key roll; both cases
// are indistinguishable from the caller's perspective.
var ErrStateRefSignature = errors.New("authn: stateref signature mismatch")

// ErrStateRefUIDMismatch is returned when the token's interaction UID
// does not match the orchestrator's expected UID. Cross-interaction
// replay is the principal threat this guards against.
var ErrStateRefUIDMismatch = errors.New("authn: stateref interaction uid mismatch")

// ErrStateRefStepMismatch is returned when the token's monotonic step
// counter does not match the orchestrator's expected step. Successful
// step transitions invalidate every prior token; replaying a stale
// token after the chain advanced therefore fails here.
var ErrStateRefStepMismatch = errors.New("authn: stateref step counter mismatch")

// ErrStateRefExpired is returned when the token's exp claim is in the
// past relative to the caller's clock.
var ErrStateRefExpired = errors.New("authn: stateref expired")

// StateRefPayload is the JSON envelope the orchestrator signs into a
// [interaction.Prompt.StateRef]. Callers receive a populated payload from
// [StateRefSigner.Verify] so they can read the routing tag without
// re-parsing the token. Field names are short to keep the encoded
// token compact (cookie / header space matters at the edge); the
// schema is observed only by orchestrator internals and never by RPs.
type StateRefPayload struct {
	// UID is the interaction identifier the token is bound to.
	UID string `json:"uid"`

	// Tag is the routing tag the orchestrator dispatches on
	// ("auth:<factor>", "captcha", "interaction:<name>").
	Tag string `json:"tag"`

	// StepCounter is the per-attempt monotonic step the token was
	// issued at; replaying a stale token after the chain advanced
	// fails [StateRefSigner.Verify].
	StepCounter int `json:"step"`

	// ExpiresAt is the Unix-seconds expiry of the token. Shorter
	// than the interaction lifetime so a long-tail replay is closed
	// independently of the interaction TTL.
	ExpiresAt int64 `json:"exp"`

	// Nonce is the 16-byte hex-encoded random per-token nonce so two
	// tokens emitted at the same step never share bytes.
	Nonce string `json:"nonce"`
}

// StateRefSigner produces and verifies the opaque continuation tokens
// the orchestrator hands to the SPA on every [interaction.Prompt.StateRef]. The
// signer is HMAC-SHA256 over a JSON envelope; the encoded form is
// `base64url(payload).base64url(mac)`. The token binds the
// interaction UID, the per-attempt monotonic step counter, a routing
// tag, an expiry timestamp, and a 16-byte random nonce so two tokens
// emitted at the same step never share bytes (defends against a SPA
// that caches the token alongside other request state).
//
// StateRefSigner is immutable after construction and safe for
// concurrent use by multiple goroutines.
//
// See docs/plans/002-product-design.md §E.2.1 for the security
// requirements StateRef satisfies (no plaintext secrets, single-use,
// short TTL, cross-interaction-replay rejection).
type StateRefSigner struct {
	key []byte
}

// NewStateRefSigner constructs a [StateRefSigner] from the supplied
// 32-byte HMAC key. The key MUST be the output of a CSPRNG. Returns
// [ErrStateRefKeyLength] when len(key) != 32.
func NewStateRefSigner(key []byte) (*StateRefSigner, error) {
	if len(key) != stateRefKeyLen {
		return nil, ErrStateRefKeyLength
	}
	cp := make([]byte, stateRefKeyLen)
	copy(cp, key)
	return &StateRefSigner{key: cp}, nil
}

// Issue signs an [interaction.Prompt.StateRef] for the supplied attempt
// context. The orchestrator calls Issue exactly once per Prompt; the
// returned token is opaque to the SPA. The nonce is generated through
// crypto/rand so a re-emit at the same step never collides with an
// earlier token.
func (s *StateRefSigner) Issue(uid, tag string, step int, expiresAt time.Time) (string, error) {
	nonceBytes := make([]byte, stateRefNonceLen)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", err
	}
	p := StateRefPayload{
		UID:         uid,
		Tag:         tag,
		StepCounter: step,
		ExpiresAt:   expiresAt.Unix(),
		Nonce:       hex.EncodeToString(nonceBytes),
	}
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return s.encode(body), nil
}

// Verify decodes token, checks the HMAC tag, and enforces the
// orchestrator's routing invariants: the UID must match the active
// interaction, the step counter must equal the orchestrator's current
// step, and the expiry must be in the future relative to now. On
// success the embedded payload is returned so the caller can read the
// routing tag without re-parsing.
func (s *StateRefSigner) Verify(token, expectedUID string, expectedStep int, now time.Time) (StateRefPayload, error) {
	body, err := s.verifyEnvelope(token)
	if err != nil {
		return StateRefPayload{}, err
	}
	var p StateRefPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return StateRefPayload{}, ErrStateRefMalformed
	}
	if p.UID != expectedUID {
		return StateRefPayload{}, ErrStateRefUIDMismatch
	}
	if p.StepCounter != expectedStep {
		return StateRefPayload{}, ErrStateRefStepMismatch
	}
	if now.Unix() >= p.ExpiresAt {
		return StateRefPayload{}, ErrStateRefExpired
	}
	return p, nil
}

// encode formats the payload bytes plus the HMAC tag into the wire
// `<payload>.<mac>` shape.
func (s *StateRefSigner) encode(body []byte) string {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(body)
	tag := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(tag)
}

// verifyEnvelope splits the token, validates the HMAC, and returns the
// decoded payload bytes. Every failure mode collapses to an opaque
// [ErrStateRefMalformed] / [ErrStateRefSignature] so a SPA cannot
// distinguish them.
func (s *StateRefSigner) verifyEnvelope(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, ErrStateRefMalformed
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrStateRefMalformed
	}
	gotTag, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrStateRefMalformed
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(body)
	want := mac.Sum(nil)
	if !hmac.Equal(gotTag, want) {
		return nil, ErrStateRefSignature
	}
	return body, nil
}
