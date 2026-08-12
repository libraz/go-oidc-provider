package endsession

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/internal/idtokenhint"
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

// hintClaims carries the id_token_hint facts the handler acts on.
// The value is produced once per request by [verifyIDTokenHint] and
// then flows through the resolution, CSRF, and termination steps so
// the token is parsed and verified exactly once.
type hintClaims struct {
	// clientID is the requesting client: the "azp" claim when present,
	// otherwise the first "aud" entry.
	clientID string

	// subject is the token's "sub" claim, expressed in the per-client
	// subject space (the pairwise hash for a pairwise client). The
	// CSRF gate compares it against the browser session's subject so a
	// hint can only skip the confirmation prompt for the session it
	// actually belongs to. An empty value means the token carried no
	// "sub", which never matches.
	subject string
}

// verifyIDTokenHint establishes that raw is an ID Token this OP issued
// — [idtokenhint.Verify] covers the parse, key resolution, signature,
// and issuer checks, shared with the CIBA endpoint — and then applies
// the rules that belong to logout specifically: the age cap below, and
// the derivation of the requesting client_id from azp when present and
// otherwise from the first audience.
//
// The function does NOT enforce "exp": OIDC RP-Initiated Logout 1.0
// lets the user sign out from a stale tab, and the spec does not
// require freshness through "exp".
//
// It DOES enforce a soft "iat" age cap of [maxIDTokenHintAge] when the
// claim is present. Tokens older than that are rejected so an attacker
// who exfiltrates a long-forgotten id_token (browser history, proxy
// log, or leaked debug dump) cannot replay it indefinitely against the
// logout endpoint. Tokens without "iat" fall through to the legacy
// posture; issuer / signature / audience are still sufficient to
// identify the requesting client without admitting cross-OP forgery.
//
// The age cap is what distinguishes this verifier from CIBA's, which
// establishes the same provenance but bounds nothing. The cap belongs
// here because the hint is the only thing binding the request to a
// client: the caller is an unauthenticated browser and the client
// identity is read out of the token. CIBA's hint arrives on a request
// whose client has already authenticated, so a stale token there is
// replayable only by the party it was issued to.
//
// now is the wall-clock reading the iat comparison uses; callers
// pass [timex.SystemClock]'s reading or a [Deps.Clock]-derived value
// so the same instant flows through every subsystem.
//
// ctx is the logout request's context. Nothing here performs I/O; it
// travels only so the keyset's retired-kid audit event can name the
// request that presented a hint signed by a key the OP has retired.
func verifyIDTokenHint(ctx context.Context, set *keys.Set, issuer, raw string, now time.Time) (hintClaims, error) {
	claims, err := idtokenhint.Verify(ctx, set, issuer, raw)
	if err != nil {
		return hintClaims{}, translateVerifyError(err)
	}
	if claims.IssuedAt > 0 {
		// "iat" is a NumericDate (seconds since the Unix epoch). Convert
		// and compare against the cap. A token whose iat is in the
		// future is admitted: the spec does not forbid pre-dated tokens
		// and a small clock skew is the most common cause; the bound
		// here is one-sided so freshness skew never blocks a logout.
		issued := time.Unix(claims.IssuedAt, 0).UTC()
		if now.Sub(issued) > maxIDTokenHintAge {
			return hintClaims{}, errIDTokenStale
		}
	}
	aud, err := idtokenhint.First(claims.Audience)
	if err != nil {
		return hintClaims{}, errIDTokenMalformed
	}
	if claims.AZP != "" {
		// OIDC Core 1.0 §2: when azp is present it identifies the
		// party the token was issued for. Use it as the requesting
		// client_id and verify it appears among the aud entries so a
		// stolen multi-aud token cannot escape its azp binding.
		if !idtokenhint.Contains(claims.Audience, claims.AZP) {
			return hintClaims{}, errIDTokenAZP
		}
		return hintClaims{clientID: claims.AZP, subject: claims.Subject}, nil
	}
	return hintClaims{clientID: aud, subject: claims.Subject}, nil
}

// translateVerifyError restates an [idtokenhint] sentinel in this
// package's vocabulary, keeping the original as the wrapped cause so a
// log reader still sees which JOSE step failed. A nil keyset reaches
// this endpoint only through a wiring fault, and the handler has no
// server_error channel on a logout page, so it is reported as a
// signature failure: the OP could not establish that it signed the
// token, which is what the caller is told either way.
func translateVerifyError(err error) error {
	switch {
	case errors.Is(err, idtokenhint.ErrIssuer):
		return errIDTokenIssuer
	case errors.Is(err, idtokenhint.ErrSignature), errors.Is(err, idtokenhint.ErrUnverifiable):
		return fmt.Errorf("%w: %w", errIDTokenSignature, err)
	default:
		return fmt.Errorf("%w: %w", errIDTokenMalformed, err)
	}
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
