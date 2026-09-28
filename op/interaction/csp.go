package interaction

import (
	"errors"
	"fmt"
	"strings"
)

// defaultCSP is the Content-Security-Policy every page the library
// renders itself carries. [HTMLDriver] emits no <style>, <img>,
// <script> or inline handler, so the policy costs it nothing and
// removes the whole subresource attack surface from the login and
// consent ceremony.
//
// form-action is deliberately absent: a successful consent POST
// redirects to the relying party's cross-origin redirect_uri, browsers
// enforce form-action against redirect targets, and pinning it to
// 'self' therefore blocks flow completion. The double-submit CSRF
// token and the Origin allowlist are the defense on that axis.
const defaultCSP = "default-src 'none'; style-src 'none'; frame-ancestors 'none'; base-uri 'none'"

// ErrCSPNotPermitted is returned by [NormalizeCSP] for a policy that
// would disable a protection the OP owns rather than the embedder. The
// wrapped message names the offending directive.
var ErrCSPNotPermitted = errors.New("interaction: content security policy directive not permitted")

// NormalizeCSP validates an embedder-supplied Content-Security-Policy
// for an interaction page and returns the policy that will actually be
// sent. An empty policy selects the library default, which loads no
// subresources at all.
//
// The three directives below are protections of the authorization
// ceremony itself, not styling decisions, so they are not the
// embedder's to relax:
//
//   - frame-ancestors MUST be 'none' or absent. The consent page
//     carries a one-click grant; allowing it to be framed reopens
//     clickjacking, which X-Frame-Options alone no longer covers.
//   - base-uri MUST be 'none' or absent. The interaction form posts to
//     a relative action, so an injected <base> would redirect the
//     credential or consent submission to another origin.
//   - form-action MUST be absent. Browsers apply it to redirect
//     targets, so any value including 'self' blocks the cross-origin
//     302 to the relying party that completes a successful consent.
//
// A missing frame-ancestors or base-uri is appended rather than
// rejected; every other directive is passed through untouched, in the
// order given. A comma, a control character or a non-ASCII byte is
// rejected: the header grammar reads a comma as the start of another,
// independent policy the checks above would never see, and the others
// make a browser read a directive differently from this parser.
//
// Relaxing script-src (directly or through default-src) is permitted
// and carries a real cost worth stating: the interaction page holds the
// CSRF token and the continuation reference in its DOM, so script
// running on it can complete the ceremony without the user. Branding
// needs style-src, img-src and font-src; it does not need script-src.
//
// Stable since v1.1.
func NormalizeCSP(policy string) (string, error) {
	if strings.TrimSpace(policy) == "" {
		return defaultCSP, nil
	}
	if strings.Contains(policy, ",") {
		return "", fmt.Errorf("%w: a comma starts a separate policy", ErrCSPNotPermitted)
	}
	if strings.IndexFunc(policy, outsideCSPGrammar) >= 0 {
		return "", fmt.Errorf("%w: policy contains a character outside the CSP grammar", ErrCSPNotPermitted)
	}
	var (
		directives         []string
		haveFrameAncestors bool
		haveBaseURI        bool
	)
	for _, raw := range strings.Split(policy, ";") {
		directive := strings.TrimSpace(raw)
		if directive == "" {
			continue
		}
		isFrameAncestors, isBaseURI, err := classifyDirective(directive)
		if err != nil {
			return "", err
		}
		if isFrameAncestors {
			haveFrameAncestors = true
		}
		if isBaseURI {
			haveBaseURI = true
		}
		directives = append(directives, directive)
	}
	if len(directives) == 0 {
		// The input was non-empty but held only separators. Appending
		// the two protections to it would produce a policy with no
		// default-src, which permits every subresource — the opposite
		// of what an embedder who typed a policy at all intended.
		return defaultCSP, nil
	}
	if !haveFrameAncestors {
		directives = append(directives, "frame-ancestors 'none'")
	}
	if !haveBaseURI {
		directives = append(directives, "base-uri 'none'")
	}
	return strings.Join(directives, "; "), nil
}

// classifyDirective validates one semicolon-separated directive against
// the three protections [NormalizeCSP] does not let an embedder relax,
// and reports whether it is frame-ancestors or base-uri so the caller
// can track which of those still need appending. Extracted from
// NormalizeCSP's loop so the loop body stays under the linter's
// cognitive-complexity budget; behavior is unchanged.
func classifyDirective(directive string) (isFrameAncestors, isBaseURI bool, err error) {
	fields := strings.Fields(directive)
	name := strings.ToLower(fields[0])
	values := fields[1:]
	switch name {
	case "form-action":
		return false, false, fmt.Errorf(
			"%w: form-action is applied to redirect targets and would block the "+
				"cross-origin redirect that completes a successful consent",
			ErrCSPNotPermitted,
		)
	case "frame-ancestors":
		if !isNoneOnly(values) {
			return false, false, fmt.Errorf("%w: frame-ancestors must be 'none'", ErrCSPNotPermitted)
		}
		return true, false, nil
	case "base-uri":
		if !isNoneOnly(values) {
			return false, false, fmt.Errorf("%w: base-uri must be 'none'", ErrCSPNotPermitted)
		}
		return false, true, nil
	}
	return false, false, nil
}

// outsideCSPGrammar reports whether r cannot appear in a single
// serialized policy: anything but space, tab and printable ASCII.
func outsideCSPGrammar(r rune) bool {
	return r != ' ' && r != '\t' && (r < 0x21 || r > 0x7e)
}

// isNoneOnly reports whether a directive's source list is exactly
// 'none'. A list that pairs 'none' with any other source is not
// treated as equivalent: browsers ignore 'none' in that position, so
// accepting it would let "frame-ancestors 'none' https://embed.example"
// through as if it forbade framing.
func isNoneOnly(values []string) bool {
	return len(values) == 1 && values[0] == "'none'"
}
