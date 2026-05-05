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
// looked-up client carries a JWKsURI but no inline JWKs AND the
// resolver was constructed without a [URLFetcher]. The verifier maps
// it to [ErrCredentialsInvalid] so the wire response does not leak
// "you forgot to wire the fetcher" to the client.
var ErrJWKSURIUnsupported = errors.New("clientauth: JWKsURI is not configured on this resolver")

// URLFetcher fetches a parsed JWK Set from a remote URL. The
// production wiring backs this with [github.com/libraz/go-oidc-provider/internal/jar.Fetcher],
// which adds caching, singleflight, an SSRF deny-list, and a body cap.
// The interface stays narrow so [internal/clientauth] does not have
// to import [internal/jar] (and so embedders can stub it in tests).
type URLFetcher interface {
	Fetch(ctx context.Context, url string) (*josev4.JSONWebKeySet, error)
}

// StoreJWKSResolver is a [JWKSResolver] backed by an
// [store.ClientStore]. It resolves a clientID to the client's
// inline-registered JWKs ([store.Client.JWKs]). When the client has
// no inline JWKs but registered a [store.Client.JWKsURI] AND the
// resolver was constructed with a [URLFetcher], the resolver
// transparently fetches the keyset from the URL.
//
// It is the resolver the OP wiring layer installs by default so
// private_key_jwt works out-of-the-box for clients that publish their
// public keys either in-band or via a discovery URL.
type StoreJWKSResolver struct {
	clients    store.ClientStore
	urlFetcher URLFetcher
}

// NewStoreJWKSResolver returns a [JWKSResolver] that reads inline
// JWKs from the supplied [store.ClientStore]. A nil store is a
// programmer error; the constructor returns an error rather than
// deferring the panic to first use. Pass a non-nil [URLFetcher]
// (typically a `*jar.Fetcher`) via [StoreJWKSResolver.SetURLFetcher]
// when the embedder wants the resolver to honour
// [store.Client.JWKsURI] in addition to the inline path.
func NewStoreJWKSResolver(clients store.ClientStore) (*StoreJWKSResolver, error) {
	if clients == nil {
		return nil, errors.New("clientauth: NewStoreJWKSResolver requires a ClientStore")
	}
	return &StoreJWKSResolver{clients: clients}, nil
}

// SetURLFetcher attaches a [URLFetcher] so the resolver can honour
// [store.Client.JWKsURI] when the client has no inline JWKs. Passing
// nil disables URL-based resolution; the resolver then falls back to
// [ErrJWKSURIUnsupported] for clients that registered only a URI.
func (r *StoreJWKSResolver) SetURLFetcher(f URLFetcher) {
	r.urlFetcher = f
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
		if client.JWKsURI == "" {
			return nil, ErrJWKSNotConfigured
		}
		if r.urlFetcher == nil {
			return nil, ErrJWKSURIUnsupported
		}
		keys, err := r.urlFetcher.Fetch(ctx, client.JWKsURI)
		if err != nil {
			return nil, fmt.Errorf("clientauth: fetch JWKs: %w", err)
		}
		if keys == nil || len(keys.Keys) == 0 {
			return nil, ErrJWKSNotConfigured
		}
		return keys, nil
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
