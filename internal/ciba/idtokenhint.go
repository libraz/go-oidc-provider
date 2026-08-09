package ciba

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/keys"
)

// Sentinel errors returned by [VerifyIDTokenHint]. The
// backchannel-authentication handler collapses every one onto the
// same invalid_request wire code so the response is not an oracle for
// which check failed; the distinction survives here so the audit
// stream and log analysis can still tell the causes apart.
var (
	// ErrIDTokenHintUnverifiable signals that the caller handed
	// [VerifyIDTokenHint] a nil keyset, so the OP has no way to check
	// the presented token. It is a wiring fault rather than a client
	// error and the handler surfaces it as server_error.
	ErrIDTokenHintUnverifiable = errors.New("ciba: id_token_hint cannot be verified without an OP keyset")

	// ErrIDTokenHintMalformed signals that the input is not a
	// syntactically valid compact-serialised JWS, that its alg is
	// outside the project allow-list, or that its payload is not a
	// JSON object.
	ErrIDTokenHintMalformed = errors.New("ciba: id_token_hint is malformed")

	// ErrIDTokenHintSignature signals that signature verification
	// failed, that the kid header is missing, or that the kid matches
	// no live entry in the OP keyset.
	ErrIDTokenHintSignature = errors.New("ciba: id_token_hint signature is invalid")

	// ErrIDTokenHintIssuer signals that the payload's iss claim is
	// missing or does not equal the OP issuer. Without it a token this
	// OP never minted — but which happens to carry a colliding kid —
	// could be replayed as a hint.
	ErrIDTokenHintIssuer = errors.New("ciba: id_token_hint issuer does not match the OP")

	// ErrIDTokenHintAudience signals that the token was not issued to
	// the client presenting it: either aud does not contain the
	// authenticated client_id, or azp is present and names a different
	// party. This is the check that stops one CIBA client from
	// impersonating another client's end-users.
	ErrIDTokenHintAudience = errors.New("ciba: id_token_hint was not issued to the requesting client")

	// ErrIDTokenHintSubject signals that the verified payload carried
	// no sub claim, so the OP cannot name the end-user the hint refers
	// to.
	ErrIDTokenHintSubject = errors.New("ciba: id_token_hint carries no sub claim")
)

// VerifyIDTokenHint verifies an inbound CIBA id_token_hint against the
// OP's own keyset and returns the token's sub claim. CIBA Core 1.0
// §7.1 requires the OP — not the embedder — to establish that the hint
// is an ID Token this OP issued to this client, because the sub it
// carries is what the whole authentication ceremony is addressed to.
//
// The checks, in order:
//
//   - the JWS parses in compact form with an allowed alg and carries a
//     kid naming a live entry of set (active or retiring keys);
//   - the signature verifies under that entry's public key;
//   - iss equals issuer (when issuer is non-empty);
//   - aud contains clientID, and azp — when present — equals clientID;
//   - sub is non-empty.
//
// clientID MUST be the client the request already authenticated as.
// Passing an empty clientID fails with [ErrIDTokenHintAudience] rather
// than admitting an unbound token.
//
// # Freshness is deliberately not checked
//
// Neither exp nor iat is enforced. A CIBA consumption device (a POS
// terminal, a call-centre agent console) legitimately holds an ID
// Token minted during a session that ended long ago — ID Tokens are
// short-lived, so under an exp gate nearly every real hint would be
// rejected and the primary CIBA use case would not work. Freshness
// also buys nothing here: the requesting client has authenticated at
// the endpoint, and the signature plus the audience binding are what
// identify it and prevent cross-OP or cross-client forgery. The same
// deliberate choice is documented for RP-Initiated Logout's
// id_token_hint in [github.com/libraz/go-oidc-provider/internal/endsession].
//
// # Pairwise subjects
//
// The returned sub is verbatim what the ID Token carried. For a client
// registered with subject_type=pairwise (OIDC Core 1.0 §8.1) that value
// is a per-sector pseudonym, not the OP-internal subject; the caller is
// responsible for refusing that configuration rather than handing a
// pseudonym to a resolver that cannot map it back.
//
// ctx is the backchannel-authentication request's context. Verification
// does no I/O and does not observe cancellation; the context travels so
// the keyset's retired-kid audit event can name the request that
// presented a hint signed by a key the OP has retired.
func VerifyIDTokenHint(ctx context.Context, set *keys.Set, issuer, clientID, raw string) (string, error) {
	if set == nil {
		return "", ErrIDTokenHintUnverifiable
	}
	if clientID == "" {
		return "", ErrIDTokenHintAudience
	}
	jws, _, err := jose.ParseSigned(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrIDTokenHintMalformed, err)
	}
	kid := jws.Signatures[0].Header.KeyID
	if kid == "" {
		return "", ErrIDTokenHintSignature
	}
	entry, ok := set.Find(ctx, kid)
	if !ok {
		return "", ErrIDTokenHintSignature
	}
	payload, err := jws.Verify(entry.Signer.Public())
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrIDTokenHintSignature, err)
	}
	var wire struct {
		Issuer   string          `json:"iss"`
		Subject  string          `json:"sub"`
		Audience json.RawMessage `json:"aud"`
		AZP      string          `json:"azp"`
	}
	if err := json.Unmarshal(payload, &wire); err != nil {
		return "", fmt.Errorf("%w: %w", ErrIDTokenHintMalformed, err)
	}
	if issuer != "" && wire.Issuer != issuer {
		return "", ErrIDTokenHintIssuer
	}
	if !audienceContains(wire.Audience, clientID) {
		return "", ErrIDTokenHintAudience
	}
	// OIDC Core 1.0 §2: when azp is present it names the party the
	// token was issued for. A multi-audience token that lists the
	// requesting client but was minted for someone else must not pass
	// as that client's hint.
	if wire.AZP != "" && wire.AZP != clientID {
		return "", ErrIDTokenHintAudience
	}
	if wire.Subject == "" {
		return "", ErrIDTokenHintSubject
	}
	return wire.Subject, nil
}

// audienceContains reports whether raw — a JWT aud claim, which RFC
// 7519 §4.1.3 allows to be either a bare string or an array of strings
// — includes want. An empty want, an absent claim, or a payload shape
// that decodes as neither form returns false, so an unparseable
// audience fails closed.
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
