package authorizeendpoint

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// scopeDecision is what the ceremony decided about scope. The
// distinction the type exists to carry is "the user answered" versus
// "no ceremony ran": an approval of nothing and an absent ceremony
// both leave the approved set empty, and only the latter may fall back
// to the full requested set.
type scopeDecision struct {
	// answered reports that a consent-shaped Interaction returned a
	// scope decision during this attempt.
	answered bool

	// presented is the scope set the ceremony put in front of the
	// user. The ceremony is authoritative over exactly these names:
	// scopes outside the set were never up for review and must not be
	// touched.
	presented []string

	// approved is the subset the user accepted.
	approved []string
}

// resolveScopeDecision reads the ceremony's verdict off the terminal
// Result and the orchestrator state.
func resolveScopeDecision(authnState authn.State, result interaction.Result, requested []string) scopeDecision {
	if !authnState.ScopeApprovalRecorded {
		return scopeDecision{}
	}
	presented := authnState.RequestedScopes
	if len(presented) == 0 {
		presented = requested
	}
	return scopeDecision{
		answered:  true,
		presented: append([]string(nil), presented...),
		approved:  append([]string(nil), result.Scope...),
	}
}

// grantScope picks the scope slice the authorize-code mint records into
// the grant and the authorization code. An answered ceremony wins
// outright — including when it approved nothing. The fallback to the
// requested set applies only to chains that ran no consent screen
// (existing grant covered, or the embedder suppressed consent).
func (d scopeDecision) grantScope(requested []string) []string {
	if d.answered {
		return append([]string(nil), d.approved...)
	}
	return append([]string(nil), requested...)
}

// declined is the set the ceremony presented and the user did not
// approve. It is what a grant amendment removes.
func (d scopeDecision) declined() []string {
	if !d.answered {
		return nil
	}
	out := make([]string, 0, len(d.presented))
	for _, s := range d.presented {
		if !slices.Contains(d.approved, s) {
			out = append(out, s)
		}
	}
	return out
}

// grantUpsert collects the inputs upsertGrant needs. The struct exists
// so the helper stays under the linter's parameter limit and so future
// fields (e.g., per-claim consent payload) can be added without
// churning the call site.
type grantUpsert struct {
	Subject  string
	ClientID string
	Scope    []string
	AuthTime time.Time
	ACR      string
	AMR      []string

	// DeclinedScope is the set a consent ceremony presented and the
	// user refused. The ordinary upsert removes these names from the
	// reused grant, which is the only thing that makes a withdrawal
	// observable: leaving them on the record means the next request
	// for the same scope is reported as already consented and is
	// served without a ceremony. Empty for every non-consent-driven
	// call (silent re-stamp, first-party auto-grant), which keeps
	// those paths widen-only as before.
	DeclinedScope []string

	// Claims is the parsed OIDC Core 1.0 §5.5 "claims" request
	// parameter as carried by the authorize / PAR request. The
	// upsertGrant helper persists it onto the grant record so the
	// userinfo and id_token issuance paths can honour the requested
	// claim projection. A nil pointer leaves the grant's existing
	// Claims map untouched.
	Claims *authorize.ClaimsRequest

	// AuthorizationDetails is the validated RFC 9396 authorization_details
	// the request carried. upsertGrant persists it verbatim so the token
	// endpoint and introspection can echo it. Nil leaves the grant's
	// existing details untouched on the refresh path.
	AuthorizationDetails []map[string]any

	// GMAction is the Grant Management draft action ("create" / "replace"
	// / "merge") or empty for the ordinary (non-GM) upsert. GMGrantID is
	// the targeted grant for replace / merge.
	GMAction   string
	GMGrantID  string
	NewGrantID string

	Now time.Time
}

// errGrantNotOwned signals a Grant Management replace / merge referenced a
// grant_id that does not resolve to a grant owned by the authenticated
// (subject, client). The caller maps it to the OAuth invalid_grant wire
// error. Keeping it distinct from a store fault prevents a cross-subject
// or cross-client grant from being mutated.
var errGrantNotOwned = errors.New("authorizeendpoint: grant_id not owned by subject/client")

// upsertGrant ensures a grant exists for (subject, clientID) covering
// at least the supplied scope. The auth context (AuthTime, ACR, AMR) is
// refreshed on every call that resolved one, so the persisted record
// always reflects the authentication backing the authorization; OIDC
// Core 1.0 §12 requires refresh-token-derived id_tokens to carry the
// same acr/amr as the originating authentication, and the library reads
// them back through the grant on every token issuance.
func upsertGrant(
	ctx context.Context,
	deps resolved,
	in grantUpsert,
) (*store.Grant, error) {
	switch in.GMAction {
	case gmActionReplace, gmActionMerge:
		return mutateManagedGrant(ctx, deps, in)
	case gmActionCreate:
		return createGrant(ctx, deps, in)
	default:
		return reuseOrCreateGrant(ctx, deps, in)
	}
}

// codeAuthorizationDetails is the authorization_details a code records:
// what this request granted, or the grant's resulting set after a Grant
// Management replace / merge, which address the grant as a unit. The
// shared grant's union is never copied onto an ordinary code, so details
// granted by one authorization do not reach another's tokens.
func codeAuthorizationDetails(req *authorize.Request, g *store.Grant) []map[string]any {
	switch req.GrantManagementAction {
	case gmActionReplace, gmActionMerge:
		return authorize.CloneAuthorizationDetails(g.AuthorizationDetails)
	default:
		return authorize.CloneAuthorizationDetails(req.AuthorizationDetails)
	}
}

// reuseOrCreateGrant is the ordinary (non-Grant-Management) path: it
// amends the existing (subject, client) grant, and mints one only when
// the subject has none for this client.
//
// Amending covers the widening case as well as the covered one. A
// repeat authorization asking for more than the record holds used to
// mint a second grant carrying the union, which left the superseded
// record — and its live refresh chain — behind with nothing reaping it:
// the consent screen shows one relationship, so a second row is a
// grant the user cannot see and cannot revoke. Grant Management's
// create action still mints per authorization, but it reaches
// [createGrant] through [upsertGrant] rather than through here, so the
// addressable-unit semantics that action promises are unaffected.
//
// When the call comes from an answered consent ceremony
// ([grantUpsert.DeclinedScope] non-empty) the record is first narrowed:
// the ceremony is authoritative over the names it presented, so a scope
// the user unticked leaves the record before the union re-adds what was
// approved.
func reuseOrCreateGrant(ctx context.Context, deps resolved, in grantUpsert) (*store.Grant, error) {
	now := in.Now.UTC()
	encodedClaims := authorize.EncodeClaimsToGrant(in.Claims)
	existing, err := deps.Grants.FindBySubjectClient(ctx, in.Subject, in.ClientID)
	if validationErr := validateReusableGrantLookup(existing, err, in); validationErr != nil {
		return nil, validationErr
	}
	if err != nil || existing == nil {
		return createGrant(ctx, deps, in)
	}
	if len(in.DeclinedScope) > 0 {
		existing.Scope = removeScopes(existing.Scope, in.DeclinedScope)
	}
	existing.Scope = oidcscope.Union(existing.Scope, in.Scope)
	existing.UpdatedAt = now
	stampReusedGrantAuthContext(existing, in)
	if encodedClaims != nil {
		existing.Claims = encodedClaims
	}
	if in.AuthorizationDetails != nil {
		existing.AuthorizationDetails = appendAuthorizationDetails(
			existing.AuthorizationDetails,
			in.AuthorizationDetails,
		)
	}
	if err := deps.Grants.Save(ctx, existing); err != nil {
		return nil, fmt.Errorf("authorizeendpoint: refresh grant: %w", err)
	}
	return existing, nil
}

// stampReusedGrantAuthContext refreshes the reused grant's
// authentication context.
//
// A context that names nothing at all is not written through. Every
// token later minted from the grant — a refresh-issued id_token, an
// introspection response — reads acr / amr / auth_time back off the
// record, so replacing a recorded authentication with "no
// authentication" would degrade the whole remaining lifetime of the
// grant rather than just the response in hand. Callers resolve a real
// context for every exit that reaches here, which makes this a floor
// rather than a branch with semantics of its own.
func stampReusedGrantAuthContext(g *store.Grant, in grantUpsert) {
	if in.AuthTime.IsZero() && in.ACR == "" && len(in.AMR) == 0 {
		return
	}
	g.AuthTime = in.AuthTime
	g.ACR = in.ACR
	g.AMR = append(g.AMR[:0:0], in.AMR...)
}

func validateReusableGrantLookup(
	existing *store.Grant,
	err error,
	in grantUpsert,
) error {
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("authorizeendpoint: find reusable grant: %w", err)
	}
	return checkLookedUpGrant(existing, in.Subject, in.ClientID, "reusable grant")
}

// checkLookedUpGrant rejects a grant-store result that is nil or does not
// belong to (subject, clientID); label names the lookup in the message.
func checkLookedUpGrant(g *store.Grant, subject, clientID, label string) error {
	if g == nil {
		return fmt.Errorf("authorizeendpoint: %s lookup returned nil record", label)
	}
	if g.ID == "" || g.Subject != subject || g.ClientID != clientID {
		return fmt.Errorf("authorizeendpoint: %s lookup returned mismatched record", label)
	}
	return nil
}

// createGrant mints a brand-new grant. Grant Management's create action
// uses it directly (a fresh grant_id every time, never reusing an
// existing record), and the ordinary path falls back to it when no
// reusable grant exists.
func createGrant(ctx context.Context, deps resolved, in grantUpsert) (*store.Grant, error) {
	now := in.Now.UTC()
	grantID := in.NewGrantID
	if grantID == "" {
		var err error
		grantID, err = keys.RandomBase64URL(uidByteLength)
		if err != nil {
			return nil, err
		}
	}
	g := &store.Grant{
		ID:                   grantID,
		Subject:              in.Subject,
		ClientID:             in.ClientID,
		Scope:                append([]string(nil), in.Scope...),
		AuthTime:             in.AuthTime,
		ACR:                  in.ACR,
		AMR:                  append([]string(nil), in.AMR...),
		Claims:               authorize.EncodeClaimsToGrant(in.Claims),
		AuthorizationDetails: authorize.CloneAuthorizationDetails(in.AuthorizationDetails),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := deps.Grants.Save(ctx, g); err != nil {
		return nil, fmt.Errorf("authorizeendpoint: persist grant: %w", err)
	}
	return g, nil
}

// mutateManagedGrant applies a Grant Management replace / merge to the
// targeted grant_id. It enforces the ownership invariant — the grant MUST
// resolve to one owned by the authenticated (subject, client) — before any
// mutation, returning [errGrantNotOwned] otherwise so a hostile request
// cannot read or rewrite another principal's grant.
func mutateManagedGrant(ctx context.Context, deps resolved, in grantUpsert) (*store.Grant, error) {
	g, err := deps.Grants.Find(ctx, in.GMGrantID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errGrantNotOwned
		}
		return nil, fmt.Errorf("authorizeendpoint: find managed grant: %w", err)
	}
	if g == nil {
		return nil, errors.New("authorizeendpoint: managed grant lookup returned nil record")
	}
	if g.ID == "" || g.ID != in.GMGrantID {
		return nil, errors.New("authorizeendpoint: managed grant lookup returned mismatched record")
	}
	if g.ClientID != in.ClientID || g.Subject != in.Subject {
		return nil, errGrantNotOwned
	}
	switch in.GMAction {
	case gmActionReplace:
		g.Scope = append([]string(nil), in.Scope...)
		g.AuthorizationDetails = authorize.CloneAuthorizationDetails(in.AuthorizationDetails)
	case gmActionMerge:
		g.Scope = oidcscope.Union(g.Scope, in.Scope)
		g.AuthorizationDetails = appendAuthorizationDetails(g.AuthorizationDetails, in.AuthorizationDetails)
	}
	stampReusedGrantAuthContext(g, in)
	if encodedClaims := authorize.EncodeClaimsToGrant(in.Claims); encodedClaims != nil {
		g.Claims = encodedClaims
	}
	g.UpdatedAt = in.Now.UTC()
	if err := deps.Grants.Save(ctx, g); err != nil {
		return nil, fmt.Errorf("authorizeendpoint: replace/merge grant: %w", err)
	}
	return g, nil
}

// removeScopes returns base without any element of drop, preserving
// base's order.
func removeScopes(base, drop []string) []string {
	if len(drop) == 0 {
		return base
	}
	out := make([]string, 0, len(base))
	for _, s := range base {
		if !slices.Contains(drop, s) {
			out = append(out, s)
		}
	}
	return out
}

// appendAuthorizationDetails merges the existing and new
// authorization_details for a Grant Management merge. Elements are
// deep-cloned so the persisted grant does not alias the request's maps, and
// an added element that is deep-equal to one already present is skipped so a
// repeated merge of the same authorization_details does not accumulate
// unbounded duplicates on the grant.
func appendAuthorizationDetails(base, add []map[string]any) []map[string]any {
	out := authorize.CloneAuthorizationDetails(base)
	for _, el := range authorize.CloneAuthorizationDetails(add) {
		if !tokens.ContainsAuthorizationDetail(out, el) {
			out = append(out, el)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
