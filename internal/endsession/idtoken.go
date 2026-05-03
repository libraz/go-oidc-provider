package endsession

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

// Sentinel errors returned by [verifyIDTokenHint]. The handler maps
// all onto the same wire response (a 400 page with descIDTokenInvalid)
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

	// errIDTokenIssuer signals that the payload's iss claim is missing
	// or does not equal the OP issuer. The check defends against a
	// signed id_token forged by a different OP being replayed at this
	// /end_session — without it the kid match alone could admit any
	// token the OP signed for any tenant or release.
	errIDTokenIssuer = errors.New("endsession: id_token_hint issuer mismatch")

	// errIDTokenAZP signals that the payload carries an azp claim that
	// disagrees with aud. RFC 7519 / OIDC Core 1.0 §2 require azp,
	// when present, to identify the party the token was issued for;
	// the handler derives the requesting client from azp when the aud
	// is multi-valued so a mismatched azp would otherwise let a
	// different aud entry impersonate the original client.
	errIDTokenAZP = errors.New("endsession: id_token_hint azp mismatch")

	// errIDTokenStale signals that the payload's "iat" claim is older
	// than [maxIDTokenHintAge]. The signature continues to verify, but
	// the OP refuses to admit ancient tokens to the logout flow so an
	// attacker who exfiltrates a forgotten id_token (browser history,
	// proxy log, leaked debug dump) cannot replay it indefinitely. The
	// check is gated on the presence of "iat"; tokens without the
	// claim fall through to the legacy posture (issuer / signature /
	// aud are sufficient to identify the requesting client).
	errIDTokenStale = errors.New("endsession: id_token_hint too old")
)

// verifyIDTokenHint parses raw, verifies the signature against the OP
// keyset, asserts the iss claim matches the configured issuer, and
// returns the requesting client_id (azp when present, otherwise the
// first audience). The function does NOT enforce "exp": OIDC
// RP-Initiated Logout 1.0 lets the user sign out from a stale tab,
// and the spec does not require freshness through "exp".
//
// The function DOES enforce a soft "iat" age cap of
// [maxIDTokenHintAge] when the claim is present. Tokens older than
// that are rejected so an attacker who exfiltrates a long-forgotten
// id_token (browser history, proxy log, or leaked debug dump) cannot
// replay it indefinitely against the logout endpoint. Tokens without
// "iat" fall through to the legacy posture; issuer / signature /
// audience are still sufficient to identify the requesting client
// without admitting cross-OP forgery.
//
// now is the wall-clock reading the iat comparison uses; callers
// pass [timex.SystemClock]'s reading or a [Deps.Clock]-derived value
// so the same instant flows through every subsystem.
func verifyIDTokenHint(set *keys.Set, issuer, raw string, now time.Time) (string, error) {
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
		Issuer   string          `json:"iss"`
		Audience json.RawMessage `json:"aud"`
		AZP      string          `json:"azp"`
		IssuedAt int64           `json:"iat"`
	}
	if err := json.Unmarshal(payload, &wire); err != nil {
		return "", fmt.Errorf("%w: %w", errIDTokenMalformed, err)
	}
	if issuer != "" && wire.Issuer != issuer {
		return "", errIDTokenIssuer
	}
	if wire.IssuedAt > 0 {
		// "iat" is a NumericDate (seconds since the Unix epoch). Convert
		// and compare against the cap. A token whose iat is in the
		// future is admitted: the spec does not forbid pre-dated tokens
		// and a small clock skew is the most common cause; the bound
		// here is one-sided so freshness skew never blocks a logout.
		issued := time.Unix(wire.IssuedAt, 0).UTC()
		if now.Sub(issued) > maxIDTokenHintAge {
			return "", errIDTokenStale
		}
	}
	aud, err := decodeAudienceFirst(wire.Audience)
	if err != nil {
		return "", err
	}
	if wire.AZP != "" {
		// OIDC Core 1.0 §2: when azp is present it identifies the
		// party the token was issued for. Use it as the requesting
		// client_id and verify it appears among the aud entries so a
		// stolen multi-aud token cannot escape its azp binding.
		if !audienceContains(wire.Audience, wire.AZP) {
			return "", errIDTokenAZP
		}
		return wire.AZP, nil
	}
	return aud, nil
}

// hintNow returns the wall-clock reading used by [verifyIDTokenHint]
// for the iat-age comparison. A configured [Deps.Clock] wins; the
// fallback is [timex.SystemClock] (the single sanctioned wall-clock
// seam). The helper mirrors [endSessionNow] but is duplicated rather
// than shared so the dependency direction stays one-way (idtoken.go
// must not import handler.go's helpers, only the other way around).
func hintNow(c Clock) time.Time {
	if c != nil {
		return c.Now().UTC()
	}
	return timex.SystemClock.Now().UTC()
}

// audienceContains reports whether raw (a JSON aud value, either a
// bare string or an array of strings) includes want. Empty raw or a
// decode error returns false; the audience caller has already checked
// that decodeAudienceFirst accepts the shape, so a mid-call decode
// failure here can only be a malformed payload.
func audienceContains(raw json.RawMessage, want string) bool {
	if want == "" || len(raw) == 0 {
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == want
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err != nil {
		return false
	}
	for _, a := range multi {
		if a == want {
			return true
		}
	}
	return false
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
