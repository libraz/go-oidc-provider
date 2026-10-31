package ssf

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// TokenType is the JWS typ header of every SET (RFC 8417 §2.3).
//
//nolint:gosec // G101 false positive: this is a JWT typ header, not a credential.
const TokenType = "secevent+jwt"

// idLength is the random byte length behind jti and txn (128 bits).
const idLength = 16

// SigningKey is the active OP signing key a SET is signed with.
type SigningKey = tokens.SigningKey

// ErrInvalidClaims reports a claim set that is not a well-formed SET.
var ErrInvalidClaims = errors.New("ssf: invalid SET claims")

// Claims is the input of [BuildClaims].
type Claims struct {
	// Issuer is the OP issuer. Required.
	Issuer string

	// Audience is the receiver's client_id. Required.
	Audience string

	// IssuedAt stamps iat. Required.
	IssuedAt time.Time

	// JTI is the SET identifier. Required; [NewID] mints one.
	JTI string

	// TxN is the txn shared by every SET of one occurrence; omitted when
	// empty.
	TxN string

	// SubjectID is the top-level sub_id. Required; see [IssSubSubject]
	// and [StreamSubject].
	SubjectID map[string]string

	// Event is the single events member's key. Required.
	Event EventType

	// Payload is the single events member's value. Nil encodes as {}.
	Payload map[string]any
}

// NewID mints a random identifier for jti or txn.
func NewID() (string, error) {
	id, err := keys.RandomBase64URL(idLength)
	if err != nil {
		return "", fmt.Errorf("ssf: %w", err)
	}
	return id, nil
}

// IssSubSubject is the iss_sub subject identifier (RFC 9493).
func IssSubSubject(issuer, sub string) map[string]string {
	return map[string]string{"format": "iss_sub", "iss": issuer, "sub": sub}
}

// StreamSubject is the opaque subject identifier a control event names
// its stream with (SSF 1.0 §8.1.4, §8.1.5).
func StreamSubject(streamID string) map[string]string {
	return map[string]string{"format": "opaque", "id": streamID}
}

// BuildClaims serialises c as SET claims JSON. A SET carries no sub and
// no exp (SSF 1.0).
func BuildClaims(c Claims) ([]byte, error) {
	switch {
	case c.Issuer == "", c.Audience == "", c.JTI == "", c.Event == "":
		return nil, fmt.Errorf("%w: iss, aud, jti and the event type are required", ErrInvalidClaims)
	case c.IssuedAt.IsZero():
		return nil, fmt.Errorf("%w: iat is required", ErrInvalidClaims)
	case len(c.SubjectID) == 0 || c.SubjectID["format"] == "":
		return nil, fmt.Errorf("%w: sub_id with a format is required", ErrInvalidClaims)
	}
	payload := c.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	out := map[string]any{
		"iss":    c.Issuer,
		"aud":    c.Audience,
		"iat":    c.IssuedAt.Unix(),
		"jti":    c.JTI,
		"sub_id": c.SubjectID,
		"events": map[string]any{string(c.Event): payload},
	}
	if c.TxN != "" {
		out["txn"] = c.TxN
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("ssf: marshal SET claims: %w", err)
	}
	return b, nil
}

// Sign signs stored claims JSON as a compact JWS with typ secevent+jwt.
// The claims bytes are signed verbatim after a shape check, since they
// come back from a storage backend.
func Sign(claims []byte, key SigningKey) (string, error) {
	if key.Signer == nil {
		return "", errors.New("ssf: signing key has nil Signer")
	}
	if err := checkClaims(claims); err != nil {
		return "", err
	}
	signer, err := tokens.NewSigner(key, TokenType)
	if err != nil {
		return "", fmt.Errorf("ssf: %w", err)
	}
	jws, err := signer.Sign(claims)
	if err != nil {
		return "", fmt.Errorf("ssf: sign SET: %w", err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("ssf: serialise SET: %w", err)
	}
	return out, nil
}

// checkClaims rejects claims JSON that is not a single-event SET.
func checkClaims(claims []byte) error {
	var parsed struct {
		Iss    string                     `json:"iss"`
		Jti    string                     `json:"jti"`
		Aud    string                     `json:"aud"`
		Sub    *json.RawMessage           `json:"sub"`
		Exp    *json.RawMessage           `json:"exp"`
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(claims, &parsed); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidClaims, err)
	}
	switch {
	case parsed.Iss == "", parsed.Jti == "", parsed.Aud == "":
		return fmt.Errorf("%w: iss, jti and aud are required", ErrInvalidClaims)
	case parsed.Sub != nil, parsed.Exp != nil:
		return fmt.Errorf("%w: sub and exp are not allowed", ErrInvalidClaims)
	case len(parsed.Events) != 1:
		return fmt.Errorf("%w: events must have exactly one member", ErrInvalidClaims)
	}
	return nil
}
