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

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/userinfo/userclaims"
)

// ErrSubjectRequired is returned by [Build] when the input does not carry a
// non-empty Subject. Every UserInfo response MUST include "sub" (OIDC Core
// 1.0 §5.3.2); a call site that omits it is a programmer error.
var ErrSubjectRequired = errors.New("userinfo: Subject is required")

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
	allowed := userclaims.ScopeClaimNames(in.Scopes, in.CustomScopeClaims)
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
