package tokens

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Sentinel errors returned by [ResolveOpaqueAccessToken]. Callers branch
// on them via [errors.Is] to pick their own wire response and audit
// reason; every one of them means the token MUST NOT be honoured.
var (
	// ErrOpaqueAccessTokenUnknown signals the store holds no record for
	// the presented value. It also matches [store.ErrNotFound].
	ErrOpaqueAccessTokenUnknown = errors.New("tokens: opaque access token unknown")

	// ErrOpaqueAccessTokenRevoked signals the record is marked revoked.
	ErrOpaqueAccessTokenRevoked = errors.New("tokens: opaque access token revoked")

	// ErrOpaqueAccessTokenExpired signals the record's expiry is unset
	// or not after the supplied clock reading.
	ErrOpaqueAccessTokenExpired = errors.New("tokens: opaque access token expired")

	// ErrOpaqueAccessTokenClientGone signals the client the token was
	// issued to no longer resolves through the client registry.
	ErrOpaqueAccessTokenClientGone = errors.New("tokens: opaque access token client no longer registered")

	// ErrOpaqueAccessTokenSubject signals the configured subject
	// projector could not produce the per-client public subject.
	ErrOpaqueAccessTokenSubject = errors.New("tokens: opaque access token subject projection failed")

	// ErrOpaqueAccessTokenLookup signals a store fault: the question
	// could not be answered, as opposed to being answered "no".
	ErrOpaqueAccessTokenLookup = errors.New("tokens: opaque access token lookup failed")
)

// OpaqueAccessTokenLookup bundles the substores [ResolveOpaqueAccessToken]
// consults.
type OpaqueAccessTokenLookup struct {
	// Store is the opaque access-token substore. It must be non-nil.
	Store store.OpaqueAccessTokenStore

	// Clients is the client registry. A nil value skips the live
	// client-existence check.
	Clients store.ClientStore

	// SubjectProjector converts the recorded OP-internal subject into
	// the per-client public subject. Nil means the recorded subject is
	// already the public one.
	SubjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error)

	// Grants tells an OP-internal recorded subject from an already
	// public one; consulted only when SubjectProjector is set.
	Grants store.GrantStore
}

// OpaqueAccessTokenView is a live opaque access-token record together
// with the values every reader derives from it.
type OpaqueAccessTokenView struct {
	// Record is the stored row. Its Subject is the OP-internal value
	// for a grant-backed token and the wire value otherwise.
	Record *store.OpaqueAccessToken

	// Subject is the per-client public subject, the value a JWT access
	// token minted for the same grant carries in "sub".
	Subject string

	// Client is the issuing client, or nil when no registry is wired.
	Client *store.Client
}

// Confirmation returns the RFC 7800 cnf members the token is bound to,
// or nil for a bearer token. The DPoP (RFC 9449 §6.1) and mTLS
// (RFC 8705 §3.1) members are independent, so a dual-bound token
// carries both and a reader must verify both.
func (v *OpaqueAccessTokenView) Confirmation() map[string]string {
	rec := v.Record
	if rec.DPoPJKT == "" && rec.MTLSCertThumbprint == "" {
		return nil
	}
	cnf := make(map[string]string, 2)
	if rec.DPoPJKT != "" {
		cnf["jkt"] = rec.DPoPJKT
	}
	if rec.MTLSCertThumbprint != "" {
		cnf["x5t#S256"] = rec.MTLSCertThumbprint
	}
	return cnf
}

// ResolveOpaqueAccessToken is the one place an opaque access token is
// judged live. /introspect, /userinfo and token exchange all call it, so
// a check added here reaches every reader: the record must exist, not
// be revoked, not be expired at now, and name a client the registry
// still holds — the same client-deletion rule the JWT readers apply.
// The returned view carries the public subject: a recorded subject is
// projected only when its GrantID names a Grant record; no GrantID, or
// a GrantID with no Grant record (a custom-grant chain), means the
// subject is already public.
//
// Audience and sender-constraint proof checks stay with the caller,
// since each endpoint answers them against its own request.
func ResolveOpaqueAccessToken(
	ctx context.Context,
	opts OpaqueAccessTokenLookup,
	raw string,
	now time.Time,
) (*OpaqueAccessTokenView, error) {
	rec, err := opts.Store.Find(ctx, raw)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%w: %w", ErrOpaqueAccessTokenUnknown, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrOpaqueAccessTokenLookup, err)
	}
	if rec == nil {
		return nil, fmt.Errorf("%w: %w", ErrOpaqueAccessTokenUnknown, store.ErrNotFound)
	}
	if rec.Revoked {
		return nil, ErrOpaqueAccessTokenRevoked
	}
	if !rec.ExpiresAt.After(now) {
		return nil, ErrOpaqueAccessTokenExpired
	}
	view := &OpaqueAccessTokenView{Record: rec, Subject: rec.Subject}
	if opts.Clients != nil {
		if view.Client, err = lookupOpaqueTokenClient(ctx, opts.Clients, rec.ClientID); err != nil {
			return nil, err
		}
	}
	if opts.SubjectProjector != nil {
		if view.Subject, err = publicOpaqueSubject(ctx, opts, rec, view.Client); err != nil {
			return nil, err
		}
	}
	return view, nil
}

// publicOpaqueSubject returns the wire subject for rec: the recorded
// value projected when it is OP-internal, verbatim otherwise.
func publicOpaqueSubject(ctx context.Context, opts OpaqueAccessTokenLookup, rec *store.OpaqueAccessToken, client *store.Client) (string, error) {
	internal, err := opaqueSubjectIsInternal(ctx, opts.Grants, rec.GrantID)
	if err != nil {
		return "", err
	}
	if !internal {
		return rec.Subject, nil
	}
	return projectOpaqueTokenSubject(ctx, opts.SubjectProjector, rec.Subject, client)
}

// opaqueSubjectIsInternal reports whether an opaque token's recorded
// subject is the OP-internal identifier, which only a token descending
// from a Grant record carries. client_credentials mints with no GrantID
// and a custom-grant chain's GrantID has no Grant record; both record
// the wire subject. A grant store that cannot answer fails closed.
func opaqueSubjectIsInternal(ctx context.Context, grants store.GrantStore, grantID string) (bool, error) {
	if grantID == "" {
		return false, nil
	}
	if grants == nil {
		return false, ErrOpaqueAccessTokenSubject
	}
	g, err := grants.Find(ctx, grantID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("%w: grant: %w", ErrOpaqueAccessTokenLookup, err)
	}
	return g != nil, nil
}

// lookupOpaqueTokenClient returns the client an opaque token was issued
// to, or [ErrOpaqueAccessTokenClientGone] once the registry no longer
// holds it.
func lookupOpaqueTokenClient(ctx context.Context, clients store.ClientStore, clientID string) (*store.Client, error) {
	client, err := clients.GetClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrOpaqueAccessTokenClientGone
		}
		return nil, fmt.Errorf("%w: client: %w", ErrOpaqueAccessTokenLookup, err)
	}
	if client == nil {
		return nil, ErrOpaqueAccessTokenClientGone
	}
	return client, nil
}

// projectOpaqueTokenSubject converts the recorded subject into the
// per-client public one. Projection needs the client, so a nil client
// (no registry wired) fails closed.
func projectOpaqueTokenSubject(
	ctx context.Context,
	project func(ctx context.Context, raw string, client *store.Client) (string, error),
	raw string,
	client *store.Client,
) (string, error) {
	if client == nil {
		return "", ErrOpaqueAccessTokenSubject
	}
	projected, err := project(ctx, raw, client)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrOpaqueAccessTokenSubject, err)
	}
	if projected == "" {
		return "", ErrOpaqueAccessTokenSubject
	}
	return projected, nil
}
