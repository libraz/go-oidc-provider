// Package userinfo assembles the claim payload returned at /userinfo and
// embedded in id_token bodies, applying the scope → claim mapping defined
// by OpenID Connect Core 1.0 §5.4.
//
// The package is a pure transformation: it takes the universe of known
// claim values for a subject and projects it onto the subset of claim
// names the granted scopes authorise. It never consults storage, never
// touches the wall clock, and never mutates its inputs. The HTTP layer
// (which lives in op/, alongside the bearer-token check and rate-limit
// machinery) wraps this package's output in a JSON response.
//
// # Custom scopes
//
// Standard OpenID scopes are recognised by name. Embedders that register
// custom scopes via op.WithScope wire their scope → claim names mapping
// through [Input.CustomScopeClaims]; the package merges that mapping with
// the standard one before releasing claims.
package userinfo

import (
	"errors"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

// ErrSubjectRequired is returned by [Build] when the input does not carry a
// non-empty Subject. Every UserInfo response MUST include "sub" (OIDC Core
// 1.0 §5.3.2); a call site that omits it is a programmer error.
var ErrSubjectRequired = errors.New("userinfo: Subject is required")

// Standard scope names the package recognises. Values mirror the constants
// in op/claim.go; they are duplicated here so internal/userinfo can stay
// independent of the public package (the op package would import this one
// during HTTP handler construction, not the other way around).
const (
	scopeOpenID  = "openid"
	scopeProfile = "profile"
	scopeEmail   = "email"
	scopeAddress = "address"
	scopePhone   = "phone"
)

// Input is the bundle [Build] consumes.
type Input struct {
	// Subject is the OP-internal stable identifier of the end-user. It
	// is always written into the "sub" claim of the response. An empty
	// Subject yields [ErrSubjectRequired].
	Subject string

	// Scopes is the list of scopes the access token was granted. The
	// package uses it to decide which claim groups to release. Scope
	// values not recognised in [CustomScopeClaims] or the standard
	// mapping are ignored silently; that is consistent with OIDC Core
	// 1.0 §5.4, which says the OP "MAY" release additional claims for
	// unknown scopes.
	Scopes []string

	// Source is the universe of known claim values for the subject. The
	// caller typically populates it from a [store.UserStore] read.
	// Claim values not present in Source are simply not released — the
	// package never invents data.
	Source map[string]any

	// CustomScopeClaims maps a scope name to the list of claim names it
	// releases. Embedders register custom scopes via op.WithScope; the
	// HTTP layer threads the resulting mapping through this field.
	CustomScopeClaims map[string][]string

	// Claims is the parsed OIDC Core 1.0 §5.5 "claims" request
	// parameter as carried by the authorizing grant. Nil when the
	// request did not include the parameter or the OP is configured
	// to ignore it. Build honours the userinfo location of this
	// payload by adding the requested claim names on top of the
	// scope-derived allow-list, applying the spec's "MUST equal" /
	// "MUST be one of" constraints when present, and silently
	// omitting any claim whose data is absent from Source.
	Claims *authorize.ClaimsRequest
}

// Build returns the claim map [the OP] writes into a /userinfo response or
// embeds in an id_token. The map always contains "sub"; every other claim
// is included only if (a) one of the granted scopes authorises it AND
// (b) the corresponding key is present in [Input.Source].
//
// Build never mutates its inputs. The returned map is a fresh allocation;
// the caller may serialise or further mutate it freely.
func Build(in Input) (map[string]any, error) {
	if in.Subject == "" {
		return nil, ErrSubjectRequired
	}
	out := map[string]any{
		"sub": in.Subject,
	}
	allowed := allowedClaimNames(in.Scopes, in.CustomScopeClaims)
	for name := range allowed {
		if name == "sub" {
			continue
		}
		v, ok := in.Source[name]
		if !ok {
			continue
		}
		out[name] = v
	}
	projectRequestedClaims(out, in)
	return out, nil
}

// projectRequestedClaims adds claims requested via the OIDC Core §5.5
// "claims" parameter on top of the scope-derived projection in out.
// The function is best-effort:
//
//   - A claim already released by scope is skipped (no double-write).
//   - A claim whose name does not exist in Source is silently omitted —
//     the spec stops at "OP MUST attempt to provide" for essential
//     claims, and the project's posture is to omit on absent rather
//     than emit a JSON null.
//   - When the spec carries a "value" / "values" constraint and the
//     stored value disagrees, the claim is omitted (the OP cannot
//     satisfy the constraint and the spec permits omission).
//
// "sub" is never overwritten — it is the only claim Build always emits
// regardless of scope, and §5.5 explicitly notes that requesting sub
// is a no-op.
func projectRequestedClaims(out map[string]any, in Input) {
	if in.Claims == nil || len(in.Claims.UserInfo) == 0 {
		return
	}
	for name, spec := range in.Claims.UserInfo {
		if name == "sub" {
			continue
		}
		if _, already := out[name]; already {
			continue
		}
		v, ok := in.Source[name]
		if !ok {
			continue
		}
		if !spec.Allows(v) {
			continue
		}
		out[name] = v
	}
}

// allowedClaimNames returns the set of claim names the granted scopes
// authorise. The merge favours the caller's CustomScopeClaims for scope
// names also present in the standard mapping; that lets embedders
// override (rare, but explicitly supported by OIDC Core 1.0 §5.4).
func allowedClaimNames(scopes []string, custom map[string][]string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, scope := range scopes {
		if extras, ok := custom[scope]; ok {
			for _, name := range extras {
				out[name] = struct{}{}
			}
			continue
		}
		for _, name := range standardScopeClaims(scope) {
			out[name] = struct{}{}
		}
	}
	return out
}

// standardScopeClaims returns the claim names a recognised standard scope
// authorises, per OIDC Core 1.0 §5.4. Unknown scopes return nil and are
// ignored by [allowedClaimNames]. The slice returned is a fresh copy so
// callers cannot mutate the package's internal lists.
func standardScopeClaims(scope string) []string {
	switch scope {
	case scopeOpenID:
		// "sub" is always released; nothing extra.
		return nil
	case scopeProfile:
		return slices.Clone(profileClaims)
	case scopeEmail:
		return slices.Clone(emailClaims)
	case scopeAddress:
		return slices.Clone(addressClaims)
	case scopePhone:
		return slices.Clone(phoneClaims)
	default:
		return nil
	}
}

// profileClaims is the closed set of claim names released by the
// "profile" scope (OIDC Core 1.0 §5.4). The list is package-private and
// returned as a clone by [standardScopeClaims].
var profileClaims = []string{ //nolint:gochecknoglobals // closed mapping per RFC.
	"name",
	"family_name",
	"given_name",
	"middle_name",
	"nickname",
	"preferred_username",
	"profile",
	"picture",
	"website",
	"gender",
	"birthdate",
	"zoneinfo",
	"locale",
	"updated_at",
}

// emailClaims is the closed set released by the "email" scope.
var emailClaims = []string{ //nolint:gochecknoglobals // closed mapping per RFC.
	"email",
	"email_verified",
}

// addressClaims is the closed set released by the "address" scope.
var addressClaims = []string{ //nolint:gochecknoglobals // closed mapping per RFC.
	"address",
}

// phoneClaims is the closed set released by the "phone" scope.
var phoneClaims = []string{ //nolint:gochecknoglobals // closed mapping per RFC.
	"phone_number",
	"phone_number_verified",
}
