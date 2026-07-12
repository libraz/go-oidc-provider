package ciba

import (
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MaxBindingMessageRunes is the upper bound on binding_message
// length that [ValidateBindingMessage] enforces. CIBA Core §7.1
// permits the OP to set a length cap and 50 runes is the documented
// limit for this implementation.
const MaxBindingMessageRunes = 50

// ValidateBindingMessage returns the canonical form of the supplied
// binding_message: empty input is treated as "not supplied" and
// returned as ("", nil); any other value is trimmed and
// length-checked against [MaxBindingMessageRunes] (rune count, not
// byte count, so a string of multibyte runes is not falsely
// rejected).
//
// The returned value is the RAW trimmed input — it is deliberately
// NOT HTML-escaped or otherwise transformed. CIBA Core §7.1's
// anti-phishing interlock requires the authentication device to
// display the identical value the consumption device requested;
// escaping here would make the two devices show different strings.
// Any rendering-context escaping (HTML, terminal, etc.) is the
// embedder's responsibility at the point the value is displayed.
//
// The function still guards against display-spoofing: a
// binding_message containing a Unicode control character (category
// Cc, which includes CR/LF/NUL and other non-printable code points)
// is rejected with [ErrBindingMessageInvalidChar], since such
// characters could be used to truncate or forge the rendered
// message on the authentication device.
//
// When the trimmed value exceeds the length cap the function
// returns [ErrBindingMessageTooLong]. Both sentinels map to the
// invalid_binding_message wire code at the caller.
func ValidateBindingMessage(s string) (string, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "", nil
	}
	if utf8.RuneCountInString(trimmed) > MaxBindingMessageRunes {
		return "", ErrBindingMessageTooLong
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return "", ErrBindingMessageInvalidChar
		}
	}
	return trimmed, nil
}

// ValidateScope splits the raw scope parameter and verifies that the
// openid scope value is a member. The function returns
// [ErrMissingScope] when the parameter is empty or blank, and
// [ErrScopeMissingOpenID] when openid is absent from the resulting
// list. Duplicates are preserved; the caller is responsible for any
// further normalisation.
//
// Tokenisation uses [strings.Fields] (any Unicode whitespace run), a
// deliberate superset of the RFC 6749 §3.3 separator (ASCII space,
// 0x20) so a lenient CIBA client that separates scopes with tabs still
// authenticates. Spec-conformant (0x20-separated) inputs tokenise
// identically to the wire-facing 0x20-only path in [internal/oidcscope].
func ValidateScope(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, ErrMissingScope
	}
	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return nil, ErrMissingScope
	}
	hasOpenID := false
	for _, p := range parts {
		if p == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		return nil, ErrScopeMissingOpenID
	}
	return parts, nil
}

// ParseRequestedExpiry parses the requested_expiry parameter the
// client sent on /bc-authorize. An empty input means "client did not
// supply a value" and returns (0, nil); the caller substitutes
// [DefaultExpiresIn] (or any embedder override). Otherwise the value
// MUST parse as a positive base-10 integer interpreted as seconds;
// non-positive or unparseable values yield [ErrInvalidRequestedExpiry].
//
// When upper is greater than zero and the parsed value exceeds it,
// the function returns upper — matching CIBA Core §7.1's allowance
// for the OP to clamp the lifetime down. A zero or negative upper
// disables clamping.
func ParseRequestedExpiry(raw string, upper time.Duration) (time.Duration, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || n <= 0 {
		return 0, ErrInvalidRequestedExpiry
	}
	d := time.Duration(n) * time.Second
	if upper > 0 && d > upper {
		return upper, nil
	}
	return d, nil
}

// HintKind is the closed sum returned by [ClassifyHint] naming
// which of the three CIBA hint parameters the client supplied. The
// type is closed: callers exhaustively switch on it and the linter
// flags any new case the caller forgets to handle.
type HintKind uint8

const (
	// HintNone is the zero value. [ClassifyHint] never returns this
	// alongside a nil error; observing it indicates a bug in the
	// caller's dispatch.
	HintNone HintKind = iota

	// HintLoginHint means the request supplied a login_hint
	// parameter (an opaque identifier the embedder's resolver maps
	// to a stable subject).
	HintLoginHint

	// HintIDTokenHint means the request supplied an id_token_hint
	// parameter (a previously issued ID token whose sub claim
	// identifies the end-user).
	HintIDTokenHint

	// HintLoginHintToken means the request supplied a
	// login_hint_token parameter (a signed JWT the embedder's
	// resolver verifies and maps to a stable subject).
	HintLoginHintToken
)

// String returns the wire-friendly name of k, suitable for audit
// and log output. Unknown values surface as "none".
func (k HintKind) String() string {
	switch k {
	case HintLoginHint:
		return "login_hint"
	case HintIDTokenHint:
		return "id_token_hint"
	case HintLoginHintToken:
		return "login_hint_token"
	case HintNone:
		return "none"
	default:
		return "none"
	}
}

// ClassifyHint inspects the three CIBA hint parameters and returns
// the kind plus the value of whichever one is non-empty. CIBA Core
// §7.1 requires exactly one to be supplied: when zero or more than
// one is non-empty the function returns [ErrInvalidHintCombination].
// The caller maps this to the invalid_request wire code.
func ClassifyHint(loginHint, idTokenHint, loginHintToken string) (HintKind, string, error) {
	loginHint = strings.TrimSpace(loginHint)
	idTokenHint = strings.TrimSpace(idTokenHint)
	loginHintToken = strings.TrimSpace(loginHintToken)
	count := 0
	if loginHint != "" {
		count++
	}
	if idTokenHint != "" {
		count++
	}
	if loginHintToken != "" {
		count++
	}
	if count != 1 {
		return HintNone, "", ErrInvalidHintCombination
	}
	switch {
	case loginHint != "":
		return HintLoginHint, loginHint, nil
	case idTokenHint != "":
		return HintIDTokenHint, idTokenHint, nil
	default:
		return HintLoginHintToken, loginHintToken, nil
	}
}
