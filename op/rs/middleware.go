package rs

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

// Requirement is a condition a verified [Token] must meet on a route
// guarded by [Verifier.Middleware]. The set is closed: [RequireScope],
// [RequireACR] and [RequireMaxAge] are the only implementations, so every
// failure maps onto a challenge the package knows how to write.
//
// Stable since v1.5.
type Requirement interface {
	check(tok *Token) *Error
}

// Middleware returns a wrapper that verifies every request with
// [Verifier.Verify], then checks reqs in order. A request that passes
// reaches next with the token available through [FromContext]. A request
// that fails gets the [Error]'s status, its WWW-Authenticate challenge
// (for 400, 401 and 403) and an empty body; next is not called.
//
// A nil entry in reqs panics here, at wiring time, rather than letting
// the route run unguarded.
//
// Stable since v1.5.
func (v *Verifier) Middleware(reqs ...Requirement) func(http.Handler) http.Handler {
	if slices.Contains(reqs, nil) {
		panic("rs: Middleware received a nil Requirement") //nolint:forbidigo // wiring-time programming error; a handler-returning function has no error result.
	}
	reqs = slices.Clone(reqs)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, e := v.verify(r)
			if e == nil {
				e = checkRequirements(tok, reqs)
				if e != nil {
					e = v.decorate(e, tok.scheme)
				}
			}
			if e != nil {
				writeError(w, e)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenKey{}, tok)))
		})
	}
}

func checkRequirements(tok *Token, reqs []Requirement) *Error {
	for _, req := range reqs {
		if e := req.check(tok); e != nil {
			return e
		}
	}
	return nil
}

// writeError writes e's status and challenge with an empty body.
func writeError(w http.ResponseWriter, e *Error) {
	if e.writesChallenge() {
		w.Header().Set("WWW-Authenticate", e.WWWAuthenticate())
	}
	w.WriteHeader(e.Status)
}

// RequireScope requires the token to carry every scope in scopes. A miss
// is 403 insufficient_scope with the required scopes in the challenge's
// scope attribute (RFC 6750 §3.1). Called with no scopes it requires
// nothing, so a route table can pass an empty list without a special case.
//
// Stable since v1.5.
func RequireScope(scopes ...string) Requirement { //nolint:ireturn // Requirement is sealed; the implementations are unexported by design.
	return scopeRequirement{scopes: slices.Clone(scopes)}
}

type scopeRequirement struct {
	scopes []string
}

func (s scopeRequirement) check(tok *Token) *Error {
	for _, want := range s.scopes {
		if !slices.Contains(tok.Scopes, want) {
			return &Error{
				Status:      http.StatusForbidden,
				Code:        codeInsufficientScope,
				Description: "access token lacks a required scope",
				Scope:       slices.Clone(s.scopes),
			}
		}
	}
	return nil
}

// RequireACR requires the token's "acr" to reach at least the level of
// acr on the ladder levels declares — the same [op.ACRLevels] value the
// OP was configured with, so both sides rank acr values identically. A
// token whose acr is absent or unknown to levels does not meet it. A miss
// is 401 insufficient_user_authentication with acr in the challenge's
// acr_values attribute (RFC 9470 §3).
//
// acr must be resolvable by levels (an entry of the map or a canonical
// AAL URI); otherwise RequireACR panics, so a typo surfaces when the
// route is wired rather than as a route nobody can reach.
//
// Stable since v1.5.
func RequireACR(levels op.ACRLevels, acr string) Requirement { //nolint:ireturn // Requirement is sealed; the implementations are unexported by design.
	levels = maps.Clone(levels)
	if _, ok := acrLevel(levels, acr); !ok {
		panic("rs: RequireACR: acr " + acr + " is not declared in levels") //nolint:forbidigo // wiring-time programming error; a Requirement constructor has no error result.
	}
	return acrRequirement{levels: levels, acr: acr}
}

type acrRequirement struct {
	levels op.ACRLevels
	acr    string
}

func (a acrRequirement) check(tok *Token) *Error {
	if got, ok := acrLevel(a.levels, tok.ACR); ok && a.levels.Satisfies(context.Background(), a.acr, got, nil) {
		return nil
	}
	return &Error{
		Status:      http.StatusUnauthorized,
		Code:        codeInsufficientAuthn,
		Description: "a stronger authentication is required",
		ACRValues:   []string{a.acr},
	}
}

// acrLevel returns the lowest AAL at which levels considers acr met,
// which is the level levels assigns it.
func acrLevel(levels op.ACRLevels, acr string) (op.AAL, bool) {
	if acr == "" {
		return op.AAL0, false
	}
	for _, lvl := range []op.AAL{op.AAL1, op.AAL2, op.AAL3} {
		if levels.Satisfies(context.Background(), acr, lvl, nil) {
			return lvl, true
		}
	}
	return op.AAL0, false
}

// RequireMaxAge requires the end-user authentication behind the token
// ("auth_time") to be no older than d when the token is verified. A
// token without auth_time does not meet it. A miss is 401
// insufficient_user_authentication with d, in whole seconds, as the
// challenge's max_age attribute (RFC 9470 §3).
//
// d must be positive; RequireMaxAge panics otherwise. To require only
// that auth_time is present, pass a duration longer than any session.
//
// Stable since v1.5.
func RequireMaxAge(d time.Duration) Requirement { //nolint:ireturn // Requirement is sealed; the implementations are unexported by design.
	if d <= 0 {
		panic("rs: RequireMaxAge requires a positive duration") //nolint:forbidigo // wiring-time programming error; a Requirement constructor has no error result.
	}
	return maxAgeRequirement{maxAge: d}
}

type maxAgeRequirement struct {
	maxAge time.Duration
}

func (m maxAgeRequirement) check(tok *Token) *Error {
	if !tok.AuthTime.IsZero() && !tok.verifiedAt.IsZero() && tok.verifiedAt.Sub(tok.AuthTime) <= m.maxAge {
		return nil
	}
	return &Error{
		Status:      http.StatusUnauthorized,
		Code:        codeInsufficientAuthn,
		Description: "a more recent authentication is required",
		MaxAge:      m.maxAge,
	}
}
