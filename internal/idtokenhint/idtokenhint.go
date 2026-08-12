// Package idtokenhint verifies that a presented id_token_hint is an ID
// Token this OP issued, and returns the claims the presenting endpoint
// needs to decide what to do with it.
//
// Two endpoints accept an id_token_hint and they read it for opposite
// purposes. At RP-Initiated Logout the hint is what names the client:
// the caller is an unauthenticated browser, so the token's audience is
// the only binding the OP has. At CIBA back-channel authentication the
// client has already authenticated on the same request, so the hint is
// checked against a client_id the OP already knows and is read for its
// sub.
//
// That difference is a policy the endpoints own — it decides which
// audience shapes are acceptable, whether a stale token may be admitted,
// and which claims are mandatory. What it does not change is the
// question underneath it: was this token minted by this OP. [Verify]
// answers exactly that and stops, so the parse, key resolution,
// signature, and issuer checks cannot drift apart between the two
// endpoints while their audience rules legitimately differ.
package idtokenhint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/keys"
)

// Sentinel errors returned by [Verify]. Callers translate them into
// their own endpoint-scoped errors: both endpoints deliberately collapse
// every cause onto a single wire response so the surface is not an
// oracle for which check failed, and both keep the distinction in their
// own vocabulary so log analysis can still tell the causes apart.
var (
	// ErrUnverifiable signals that the caller passed no keyset, so the
	// OP has no way to check the presented token. It is a wiring fault
	// rather than a client error.
	ErrUnverifiable = errors.New("idtokenhint: no OP keyset to verify against")

	// ErrMalformed signals that the input is not a syntactically valid
	// compact-serialised JWS, that its alg is outside the project
	// allow-list, or that its payload is not a JSON object.
	ErrMalformed = errors.New("idtokenhint: malformed")

	// ErrSignature signals that signature verification failed, that the
	// kid header is missing, or that the kid names no live entry in the
	// OP keyset.
	ErrSignature = errors.New("idtokenhint: signature invalid")

	// ErrIssuer signals that the payload's iss claim is missing or does
	// not equal the OP issuer. Without the check, a kid collision would
	// be enough to replay a token this OP never minted — or one it
	// minted for a different tenant.
	ErrIssuer = errors.New("idtokenhint: issuer mismatch")
)

// Claims are the verified members of an id_token_hint. Audience is left
// as raw JSON because RFC 7519 §4.1.3 permits both a bare string and an
// array of strings, and the two endpoints interrogate the value
// differently: use [Contains] or [First] rather than decoding it again.
type Claims struct {
	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	Audience json.RawMessage `json:"aud"`
	AZP      string          `json:"azp"`
	IssuedAt int64           `json:"iat"`
}

// Verify parses raw, verifies its signature against set, and asserts
// that the payload's iss claim equals issuer. An empty issuer skips the
// issuer check; every other check is unconditional.
//
// Verify enforces nothing about the audience, the subject, or freshness.
// Those are the caller's to decide and the two endpoints decide them
// differently — see the package comment.
//
// ctx carries no I/O of its own. It travels so the keyset can name the
// request in its retired-kid audit event when a hint arrives signed by a
// key the OP has since retired.
func Verify(ctx context.Context, set *keys.Set, issuer, raw string) (Claims, error) {
	if set == nil {
		return Claims{}, ErrUnverifiable
	}
	jws, _, err := jose.ParseSigned(raw)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	kid := jws.Signatures[0].Header.KeyID
	if kid == "" {
		return Claims{}, ErrSignature
	}
	entry, ok := set.Find(ctx, kid)
	if !ok {
		return Claims{}, ErrSignature
	}
	payload, err := jws.Verify(entry.Signer.Public())
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if issuer != "" && claims.Issuer != issuer {
		return Claims{}, ErrIssuer
	}
	return claims, nil
}

// Contains reports whether the aud claim includes want. An empty want,
// an absent claim, or a value that decodes as neither a string nor an
// array of strings returns false, so an unparseable audience fails
// closed.
func Contains(raw json.RawMessage, want string) bool {
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

// First returns the first audience value. A missing claim, an empty
// array, or an empty first element yields [ErrMalformed]: a caller that
// reaches for First is one that identifies the requesting client from
// the audience, and an audience naming nobody cannot do that.
func First(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", ErrMalformed
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return "", ErrMalformed
		}
		return single, nil
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err != nil {
		return "", fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(multi) == 0 || multi[0] == "" {
		return "", ErrMalformed
	}
	return multi[0], nil
}
