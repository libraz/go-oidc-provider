package clientauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op/store"
)

// ErrJWKSNotConfigured is returned by [StoreJWKSResolver] when the
// looked-up client has neither inline JWKs nor a JWKsURI configured.
// The verifier maps it to [ErrCredentialsInvalid] so the wire response
// stays uniform — an attacker cannot tell "client missing JWKs" apart
// from "wrong signature" by inspecting the response code.
var ErrJWKSNotConfigured = errors.New("clientauth: client has no JWKs configured")

// ErrJWKSURIUnsupported is returned by [StoreJWKSResolver] when the
// looked-up client carries a JWKsURI but no inline JWKs. The v1.0
// resolver is inline-only because the HTTP fetcher / cache / SSRF
// gate lives in [internal/jar] and pulling it into clientauth would
// invert the package layering. A follow-up Wave promotes the JWKS
// fetcher to a shared package and wires it here.
var ErrJWKSURIUnsupported = errors.New("clientauth: JWKsURI is not yet supported by the inline resolver")

// StoreJWKSResolver is a [JWKSResolver] backed by an
// [store.ClientStore]. It resolves a clientID to the client's
// inline-registered JWKs ([store.Client.JWKs]). It is the resolver
// the OP wiring layer installs by default so private_key_jwt works
// out-of-the-box for clients that publish their public keys
// in-band.
//
// The resolver does NOT fetch [store.Client.JWKsURI]. v1.0 ships
// the inline path only; embedders that need the URL path either
// register the keys inline at provisioning time or wait for the
// follow-up Wave that promotes [internal/jar]'s JWKS fetcher to a
// shared location.
type StoreJWKSResolver struct {
	clients store.ClientStore
}

// NewStoreJWKSResolver returns a [JWKSResolver] that reads inline
// JWKs from the supplied [store.ClientStore]. A nil store is a
// programmer error; the constructor returns an error rather than
// deferring the panic to first use.
func NewStoreJWKSResolver(clients store.ClientStore) (*StoreJWKSResolver, error) {
	if clients == nil {
		return nil, errors.New("clientauth: NewStoreJWKSResolver requires a ClientStore")
	}
	return &StoreJWKSResolver{clients: clients}, nil
}

// JWKS implements [JWKSResolver]. It looks the client up by id,
// decodes the inline JWK Set on [store.Client.JWKs], and returns
// it. Missing client / missing keys / malformed JSON all surface
// distinct errors so the verifier can decide which onto-wire
// translation is appropriate (today every path collapses to
// [ErrCredentialsInvalid] to avoid leaking signal).
func (r *StoreJWKSResolver) JWKS(ctx context.Context, clientID string) (*josev4.JSONWebKeySet, error) {
	client, err := r.clients.GetClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrJWKSNotConfigured
		}
		return nil, fmt.Errorf("clientauth: client lookup: %w", err)
	}
	if len(client.JWKs) == 0 {
		if client.JWKsURI != "" {
			return nil, ErrJWKSURIUnsupported
		}
		return nil, ErrJWKSNotConfigured
	}
	var keys josev4.JSONWebKeySet
	if err := json.Unmarshal(client.JWKs, &keys); err != nil {
		return nil, fmt.Errorf("clientauth: parse client JWKs: %w", err)
	}
	if len(keys.Keys) == 0 {
		return nil, ErrJWKSNotConfigured
	}
	return &keys, nil
}
