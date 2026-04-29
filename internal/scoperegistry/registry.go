// Package scoperegistry holds the runtime view of the registered scope
// set the OP enforces. The public-facing scope metadata type lives in
// [github.com/libraz/go-oidc-provider/op] (op.Scope) and carries the
// full UI surface; this package strips that down to the fields the
// HTTP layers actually consult so that internal handlers depend only
// on internal types.
//
// The registry is read-only after [New] returns. The op layer assembles
// it once at construction and threads the *Registry into every endpoint
// dependency that needs scope policy (discovery, /authorize, /token).
package scoperegistry

import (
	"fmt"
	"slices"
	"strings"
)

// Entry is the internal representation of a single registered scope.
// It mirrors the protocol-relevant subset of op.Scope: UI metadata
// (title, description, claims) is intentionally left out so that no
// handler grows a dependency on UI fields it has no business reading.
type Entry struct {
	// Name is the wire identifier. Empty values are not permitted;
	// the op layer rejects them at construction time.
	Name string

	// Public, when false, omits the scope from the discovery
	// scopes_supported list. Acceptance is governed by AllowedClients.
	Public bool

	// AllowedClients, when non-empty, restricts the scope to the
	// listed client_id values. An empty slice means every client may
	// request the scope.
	AllowedClients []string

	// Required marks scopes the user cannot decline at consent. The
	// field is informational only at this layer; the consent surface
	// reads it through a separate metadata channel.
	Required bool
}

// Registry is the read-only lookup the OP threads into authorize /
// token / discovery handlers. Construct one with [New]; it is safe for
// concurrent reads after construction.
type Registry struct {
	// byName indexes registered entries by their wire identifier. It
	// is private so the registry's "no mutation after New" invariant
	// cannot be violated through the public surface.
	byName map[string]Entry

	// publicNames is the deduplicated, lexicographically-stable list
	// of scope names that are eligible for the discovery document.
	// Pre-computed at construction so [Registry.PublicNames] can
	// return it without any allocation on the hot path.
	publicNames []string
}

// New returns a Registry built from entries. Entries with duplicate
// Name overwrite earlier entries; the op layer rejects duplicates
// before reaching this constructor, so in practice the input is
// already unique. A nil or empty input yields an empty Registry whose
// [Registry.IsRegistered] always returns false.
//
// The constructor copies AllowedClients into freshly allocated slices
// so a later mutation of the caller's slice cannot silently change
// admission policy at runtime.
//
// New panics if any entry's Name has surrounding whitespace.
// Whitespace-padded scope names cannot survive a round-trip through
// the OAuth wire format (RFC 6749 §3.3 lists scope tokens as
// space-delimited %x21 / %x23-5B / %x5D-7E sequences) so an entry
// like " openid " could never match a real request; surfacing the bug
// at construction time is preferable to a silent never-matches at
// admission. The op layer SHOULD validate the same condition before
// reaching this constructor; the panic is a structural backstop for
// programmer errors.
func New(entries []Entry) *Registry {
	r := &Registry{byName: make(map[string]Entry, len(entries))}
	for _, e := range entries {
		if e.Name == "" {
			continue
		}
		if strings.TrimSpace(e.Name) != e.Name {
			//nolint:forbidigo // construction-time programmer error; op/op.go validates upstream and the panic is a structural backstop.
			panic(fmt.Errorf("scoperegistry: scope name %q has surrounding whitespace", e.Name))
		}
		stored := Entry{
			Name:           e.Name,
			Public:         e.Public,
			Required:       e.Required,
			AllowedClients: append([]string(nil), e.AllowedClients...),
		}
		r.byName[e.Name] = stored
	}
	r.publicNames = computePublicNames(r.byName)
	return r
}

// computePublicNames extracts the public scope names from byName and
// returns them sorted in canonical wire order. The discovery document
// uses the result verbatim, so a stable ordering keeps the JSON shape
// reproducible across runs.
func computePublicNames(byName map[string]Entry) []string {
	out := make([]string, 0, len(byName))
	for name, e := range byName {
		if e.Public {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// IsRegistered reports whether name has a registered entry.
func (r *Registry) IsRegistered(name string) bool {
	if r == nil {
		return false
	}
	_, ok := r.byName[name]
	return ok
}

// IsPublic reports whether name is registered AND eligible for the
// discovery scopes_supported list. Unknown names return false; the
// caller is expected to consult [Registry.IsRegistered] separately if
// it needs to distinguish "not registered" from "registered private".
func (r *Registry) IsPublic(name string) bool {
	if r == nil {
		return false
	}
	e, ok := r.byName[name]
	return ok && e.Public
}

// Allows reports whether clientID is permitted to request scope. The
// registry only governs the AllowedClients gate; admission of unknown
// scopes is the responsibility of the upstream pipeline (the op layer
// intersects with [store.Client.Scopes] before reaching this function,
// and refresh-token scope widening rejects names outside the prior
// grant). The rules are:
//
//   - nil receiver: returns true (no registry configured; admission
//     is whatever the upstream pipeline already decided).
//   - Unknown scope: returns true. The registry is an allowlist gate
//     for *registered* AllowedClients restrictions; scopes that are
//     not registered here are not subject to a per-client allowlist
//     and pass through. Callers that need to reject unregistered
//     scopes outright SHOULD consult [Registry.IsRegistered] before
//     calling Allows (closes audit F-5: the contract is now explicit
//     and tested rather than relying on caller defence-in-depth).
//   - Registered scope with empty AllowedClients: returns true. An
//     empty allowlist means "every client may request the scope".
//   - Registered scope with non-empty AllowedClients: returns true
//     only when clientID is one of the listed identifiers.
func (r *Registry) Allows(scope, clientID string) bool {
	if r == nil {
		return true
	}
	e, ok := r.byName[scope]
	if !ok {
		return true
	}
	if len(e.AllowedClients) == 0 {
		return true
	}
	return slices.Contains(e.AllowedClients, clientID)
}

// PublicNames returns the discovery-eligible scope names in stable
// lexicographic order. The slice is freshly allocated on every call so
// callers may mutate it without affecting future reads.
func (r *Registry) PublicNames() []string {
	if r == nil {
		return nil
	}
	return slices.Clone(r.publicNames)
}
