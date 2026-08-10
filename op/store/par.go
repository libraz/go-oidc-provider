package store

import (
	"context"
	"time"
)

// PushedAuthRequest is the persistent record of a pushed authorization
// request (RFC 9126). The client posts the authorization parameters to the
// PAR endpoint and receives an opaque request_uri; the parameters are then
// retrieved at the authorization endpoint by URI lookup. The record is
// strictly single-use: the URI MUST be consumed at most once, mirroring the
// authorization-code one-time semantics (RFC 9126 §2.2).
type PushedAuthRequest struct {
	// URI is the opaque request_uri returned to the client. It is the
	// natural primary key of the record. Generated with crypto/rand and
	// returned as a "urn:ietf:params:oauth:request_uri:..." string by the
	// PAR endpoint.
	URI string

	// ClientID identifies the client that pushed the request. The
	// authorization endpoint rejects requests where the URI's owner does
	// not match the authenticated client.
	ClientID string

	// RawParams is the serialised authorization request as it arrived at
	// the PAR endpoint, including any signed JAR object. The library
	// parses this back into typed parameters at the authorization
	// endpoint; the storage layer treats it as an opaque blob.
	RawParams []byte

	// ExpiresAt is the wall-clock time at which the URI becomes invalid
	// regardless of consumption status (RFC 9126 §2.2 mandates a short
	// lifetime, typically 60 seconds).
	ExpiresAt time.Time

	// ConsumedAt is non-nil after the URI has been redeemed at the
	// authorization endpoint. The library treats a non-nil ConsumedAt as
	// proof of replay.
	ConsumedAt *time.Time

	// CreatedAt is the wall-clock time at which the record was first
	// persisted. Supplied by the caller.
	CreatedAt time.Time
}

// PushedAuthRequestStore is the substore for PAR records. It belongs to the
// atomic-routing cluster so PAR consumption and the associated authorization
// artefacts share one backend consistency domain in composite deployments.
// Implementations MUST make Consume itself atomic. During authorization-code
// completion the OP additionally calls it through a [Tx], committing PAR
// consumption with the Grant and Authorization Code.
type PushedAuthRequestStore interface {
	// Save persists a freshly created PAR record. The implementation
	// MUST hash [PushedAuthRequest.URI] (SHA-256, ideally HMAC'd with a
	// server-side pepper) before persisting and MUST NOT store the raw
	// value; see the package doc for the hash-on-store contract. Save
	// MUST return [ErrAlreadyExists] if a record whose hashed URI
	// collides with an existing row already exists; the library treats
	// that as a fatal randomness fault.
	Save(ctx context.Context, par *PushedAuthRequest) error

	// Find returns the PAR record identified by uri without consuming
	// it. The implementation MUST hash the presented uri and look up
	// the resulting digest, comparing against the stored hash in
	// constant time. It MUST return [ErrNotFound] when no such record
	// exists, and — mirroring the sibling substores (RefreshToken,
	// Session, Interaction) — MUST also return [ErrNotFound] for a
	// record whose ExpiresAt has passed. Find is the expiry gate: the
	// authorization endpoint calls it when the request_uri is presented,
	// so an expired request_uri is rejected at presentation. The
	// authoritative single-use check lives in
	// [PushedAuthRequestStore.Consume].
	Find(ctx context.Context, uri string) (*PushedAuthRequest, error)

	// Consume atomically marks the PAR record as consumed and returns
	// it. The implementation MUST hash the presented uri and look up
	// the resulting digest. It MUST return [ErrNotFound] when the
	// record is absent, [ErrAlreadyConsumed] when the record's
	// ConsumedAt was already set on entry, and a non-nil error if the
	// compare-and-set fails. The returned record's ConsumedAt MUST be
	// non-nil on success.
	//
	// On [ErrAlreadyConsumed] the returned record MUST be nil. A
	// replayed request_uri is a failed operation, and the record
	// carries [PushedAuthRequest.RawParams] — the entire authorization
	// request the client pushed — so handing it back would let a caller
	// that mishandles the error proceed on a replayed request. This is
	// deliberately unlike [AuthorizationCodeStore.Consume], which
	// returns the record on replay because RFC 9700 §2.1.1 requires the
	// OP to identify and revoke the grant the replayed code belongs to;
	// no such cascade exists for a request_uri.
	//
	// Consume enforces single-use only; it MUST NOT reject a record
	// solely because its ExpiresAt has passed. Expiry is gated at
	// presentation by [PushedAuthRequestStore.Find], which the
	// authorization endpoint calls when the request_uri is resolved. An
	// interactive login (password + second factor + consent) that
	// outlives the request_uri lifetime reaches Consume only after Find
	// already admitted the request, so applying the expiry gate again
	// here would fail the flow at code emission for no security benefit.
	// The record's own single-use invariant, plus store-side GC of
	// expired rows, remain the durability bounds.
	Consume(ctx context.Context, uri string) (*PushedAuthRequest, error)
}
