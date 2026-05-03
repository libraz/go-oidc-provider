package endpointsupport

import "strings"

// SanitizeChallengeValue scrubs s so it can be safely embedded as the
// quoted value of an auth-param in a WWW-Authenticate header (RFC 7235
// §2.1 / RFC 6750 §3.1). The function removes:
//
//   - CR (0x0D) and LF (0x0A): a header value that carries either
//     could split the response and inject an arbitrary follow-up
//     header (CRLF injection). Removal is preferred over escape
//     because there is no legitimate use of CR/LF in OAuth error
//     descriptions.
//   - NUL (0x00): some HTTP intermediaries treat NUL as a string
//     terminator; stripping it removes the ambiguity.
//   - All other C0 controls (0x01 through 0x1F except handled above)
//     and DEL (0x7F): RFC 7230 §3.2.6 forbids them from header values.
//   - The double-quote character ("): the value is wrapped in quotes,
//     so an unescaped " breaks out of the auth-param. The library
//     posture is to drop rather than escape so the header stays
//     reproducible across slog redactors that re-quote fields.
//   - The backslash character (\): it is the only auth-param escape,
//     and an unescaped \ at the end of a value would leave the
//     trailing quote unparsed. Same rationale for drop over escape.
//
// The function never returns longer than s. An empty input returns
// "".
//
// Callers that need to compose multiple challenge parameters (realm,
// error, error_description, scope) should run each through this helper
// independently so a problem in one parameter does not poison the
// others.
func SanitizeChallengeValue(s string) string {
	if s == "" {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '"', c == '\\':
			// Drop instead of escape; see godoc.
			continue
		case c < 0x20, c == 0x7F:
			// All C0 controls (including CR / LF / NUL) and DEL.
			continue
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// BuildBearerChallenge composes a WWW-Authenticate Bearer challenge
// from a set of auth-params. Each non-empty value is sanitised through
// [SanitizeChallengeValue] before it lands in the header so a
// caller-supplied error_description / realm / scope cannot inject CR /
// LF / quote breakouts.
//
// scheme is the leading authentication scheme name; v0.x callers pass
// either "Bearer" (RFC 6750) or "DPoP" (RFC 9449). Other values are
// accepted verbatim — the helper does not validate scheme tokens, on
// the assumption that the caller built the value from a closed
// internal constant set.
//
// params is processed in order; an entry whose value is empty after
// sanitisation is skipped so the header stays compact and valid for
// strict parsers that reject empty quoted-string values.
func BuildBearerChallenge(scheme string, params ...ChallengeParam) string {
	var b strings.Builder
	b.WriteString(scheme)
	first := true
	for _, p := range params {
		clean := SanitizeChallengeValue(p.Value)
		if clean == "" {
			continue
		}
		if first {
			b.WriteByte(' ')
			first = false
		} else {
			b.WriteString(", ")
		}
		b.WriteString(p.Name)
		b.WriteString(`="`)
		b.WriteString(clean)
		b.WriteByte('"')
	}
	return b.String()
}

// ChallengeParam is one auth-param in a WWW-Authenticate Bearer / DPoP
// challenge. The struct mirrors the (name, value) pairs RFC 6750 §3 /
// RFC 9449 §7.1 enumerate (realm, error, error_description, scope,
// algs, nonce, ...) so the call site reads as the spec describes.
type ChallengeParam struct {
	Name  string
	Value string
}

// challengeNames is the closed catalogue of auth-param names the
// library composes. The constants are exported so endpoint packages
// can reference them by name rather than passing string literals.
const (
	ChallengeRealm            = "realm"
	ChallengeError            = "error"
	ChallengeErrorDescription = "error_description"
	ChallengeScope            = "scope"
	ChallengeAlgs             = "algs"
)

// challengeBuilderHasOnlySafeNames is documented separately so
// callers can audit the closed name set in one place. Note: the
// helper does not enforce the name set; supplying an unrecognised
// name passes through verbatim, which is fine because the names
// themselves do not flow from untrusted input.
