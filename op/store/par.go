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
// transactional cluster: at the authorization endpoint the library consumes
// the URI and issues the associated authorization code in a single
// transaction so that a partial failure cannot leave a still-redeemable URI
// next to an issued code.
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
	// exists. Find is exposed for diagnostics and pre-flight
	// validation; the authoritative single-use check lives in
	// [PushedAuthRequestStore.Consume].
	Find(ctx context.Context, uri string) (*PushedAuthRequest, error)

	// Consume atomically marks the PAR record as consumed and returns
	// it. The implementation MUST hash the presented uri and look up
	// the resulting digest. It MUST return [ErrNotFound] when the
	// record is absent, [ErrAlreadyConsumed] when the record's
	// ConsumedAt was already set on entry, and a non-nil error if the
	// compare-and-set fails. The returned record's ConsumedAt MUST be
	// non-nil on success.
	Consume(ctx context.Context, uri string) (*PushedAuthRequest, error)
}
