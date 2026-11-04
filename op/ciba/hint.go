package ciba

// HintKind names which of the three CIBA Core 1.0 §7.1 hint
// parameters the inbound /bc-authorize request supplied. The type is
// closed: callers exhaustively switch on it and the linter flags any
// new case the caller forgets to handle.
type HintKind uint8

const (
	// HintNone is the zero value. The library never invokes a hint
	// resolver with this kind alongside a successful classification;
	// observing it indicates a bug in the dispatch.
	HintNone HintKind = iota

	// HintLoginHint means the request supplied a login_hint
	// parameter (an opaque identifier the embedder's resolver maps
	// to a stable subject).
	HintLoginHint

	// HintIDTokenHint means the request supplied an id_token_hint
	// parameter: an ID Token this OP previously issued to the
	// requesting client, whose sub claim identifies the end-user.
	// The OP verifies the token itself before the hint reaches a
	// resolver, so the value a resolver observes for this kind is the
	// OP-verified sub, never the JWT.
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
