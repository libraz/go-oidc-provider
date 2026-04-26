// Package sessions implements the chooser-group session manager described in
// docs/plans/002-product-design.md §A.9 / §F.1. It owns the encrypted
// __Host-oidc_session cookie payload and orchestrates the SessionStore
// operations that maintain the multi-account chooser group.
//
// The package treats the chooser group as the stable browsing context: a
// single browser holds at most one chooser_group_id for the lifetime of the
// cookie, and individual accounts inside the group come and go via the
// add / switch / remove / logout primitives. The cookie itself never grows;
// it always carries exactly (chooser_group_id, current_session_id, iat).
package sessions

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
)

// cookieAAD is the additional-authenticated-data tag bound into every
// session cookie ciphertext. It prevents a payload encrypted for the
// session cookie from authenticating against the interaction cookie even
// though both cookies share the same AES key (cookie name pinning).
//
// The value is intentionally short: AEAD AAD does not need to be human-
// readable, only stable across encryptions and across deployments.
const cookieAAD = "oidc-session"

// Payload is the cleartext shape of the session cookie before encryption.
// It is JSON-encoded so future additions (e.g. a feature flag or schema
// version) can be made backward-compatible by adding optional fields.
type Payload struct {
	// ChooserGroupID identifies the browser-side multi-account group.
	// Stable across account add / switch operations; rotated only on
	// full logout.
	ChooserGroupID string `json:"cg"`

	// CurrentSessionID is the SessionStore identifier of the account
	// the user is currently acting as. Switching accounts updates this
	// field without changing ChooserGroupID.
	CurrentSessionID string `json:"sid"`

	// IssuedAt is the unix-seconds timestamp at which the cookie value
	// was minted. Used by the resolver to detect cookies that survived
	// past the absolute lifetime even though the session record is
	// still valid (clock drift, edge-cache staleness, etc.).
	IssuedAt int64 `json:"iat"`
}

// Codec encrypts and decrypts [Payload] values for transport in the
// __Host-oidc_session cookie. It wraps a generic [*cookie.Codec] with the
// fixed JSON encoding and AAD policy required for session cookies.
type Codec struct {
	inner *cookie.Codec
}

// NewCodec constructs a [Codec] from the underlying cookie codec. Callers
// pass the same codec they use for the interaction / other __Host- cookies;
// the AAD distinguishes the audiences.
func NewCodec(inner *cookie.Codec) (*Codec, error) {
	if inner == nil {
		return nil, errors.New("sessions: cookie codec must not be nil")
	}
	return &Codec{inner: inner}, nil
}

// Encode marshals p to its on-the-wire form and encrypts it under the
// session AAD. The returned string is the value to place in the
// __Host-oidc_session cookie.
//
// Encode rejects empty ChooserGroupID / CurrentSessionID because those are
// programming errors — the manager always populates both fields before
// calling Encode.
func (c *Codec) Encode(p Payload) (string, error) {
	if p.ChooserGroupID == "" || p.CurrentSessionID == "" {
		return "", errors.New("sessions: payload must include chooser_group_id and current_session_id")
	}
	if p.IssuedAt == 0 {
		return "", errors.New("sessions: payload must include IssuedAt")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("sessions: marshal payload: %w", err)
	}
	return c.inner.Seal(raw, []byte(cookieAAD))
}

// Decode reverses [Codec.Encode]. It returns an opaque [ErrCookieInvalid]
// for every failure mode (parse error, AAD mismatch, AEAD failure) so the
// resolver cannot be used as an oracle.
func (c *Codec) Decode(value string) (Payload, error) {
	raw, err := c.inner.Open(value, []byte(cookieAAD))
	if err != nil {
		return Payload{}, ErrCookieInvalid
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Payload{}, ErrCookieInvalid
	}
	if p.ChooserGroupID == "" || p.CurrentSessionID == "" || p.IssuedAt == 0 {
		return Payload{}, ErrCookieInvalid
	}
	return p, nil
}

// IssuedAtTime returns the [time.Time] form of [Payload.IssuedAt].
func (p Payload) IssuedAtTime() time.Time {
	return time.Unix(p.IssuedAt, 0).UTC()
}

// ErrCookieInvalid is returned by [Codec.Decode] for every failure mode.
// The error is intentionally opaque to avoid leaking which subsystem
// rejected the cookie — that distinction belongs in audit logs.
var ErrCookieInvalid = errors.New("sessions: cookie invalid")
