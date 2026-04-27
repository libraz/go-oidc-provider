package endsession

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/keys"
)

// Sentinel errors returned by [verifyIDTokenHint]. The handler maps
// both onto the same wire response (a 400 page with descIDTokenInvalid)
// so the wire surface is not an oracle for the sub-cause; the
// distinction is preserved here so log analysis can tell them apart.
var (
	// errIDTokenMalformed signals that the input is not a syntactically
	// valid compact-serialised JWS, that its alg is not in the project
	// allow-list, or that its payload is not a JSON object containing
	// an "aud" claim of the expected shape.
	errIDTokenMalformed = errors.New("endsession: id_token_hint malformed")

	// errIDTokenSignature signals that signature verification failed,
	// the kid header is missing, or the kid does not match any entry
	// in the OP keyset.
	errIDTokenSignature = errors.New("endsession: id_token_hint signature invalid")
)

// verifyIDTokenHint parses raw, verifies the signature against the OP
// keyset, and returns the audience claim (the client_id the token was
// issued to). The function intentionally does not enforce exp or iat:
// RP-Initiated Logout 1.0 lets the user log out from a stale tab, and
// the spec does not require freshness for id_token_hint. Audience and
// signature are sufficient to identify the requesting client without
// admitting cross-OP forgery.
func verifyIDTokenHint(set *keys.Set, raw string) (string, error) {
	jws, _, err := jose.ParseSigned(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errIDTokenMalformed, err)
	}
	kid := jws.Signatures[0].Header.KeyID
	if kid == "" {
		return "", errIDTokenSignature
	}
	entry, ok := set.Find(kid)
	if !ok {
		return "", errIDTokenSignature
	}
	payload, err := jws.Verify(entry.Signer.Public())
	if err != nil {
		return "", fmt.Errorf("%w: %w", errIDTokenSignature, err)
	}
	var wire struct {
		Audience json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payload, &wire); err != nil {
		return "", fmt.Errorf("%w: %w", errIDTokenMalformed, err)
	}
	return decodeAudienceFirst(wire.Audience)
}

// decodeAudienceFirst returns the first audience value from a JWT aud
// claim that may be either a bare string or a JSON array of strings
// per RFC 7519 §4.1.3. Empty arrays / a missing claim / an empty
// string yield [errIDTokenMalformed] — the OP cannot identify the
// requesting client from a tokenless audience.
func decodeAudienceFirst(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", errIDTokenMalformed
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return "", errIDTokenMalformed
		}
		return single, nil
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err != nil {
		return "", fmt.Errorf("%w: %w", errIDTokenMalformed, err)
	}
	if len(multi) == 0 || multi[0] == "" {
		return "", errIDTokenMalformed
	}
	return multi[0], nil
}
