package clientauth

import (
	"context"
	"errors"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/op/store"
)

// ErrJWKSNotConfigured is returned by [StoreJWKSResolver] when the
// looked-up client has neither inline JWKs nor a JWKsURI configured, or
// has both.
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

// errClientLookup marks a client-store failure other than
// [store.ErrNotFound], which the verifier surfaces as a server-side fault.
var errClientLookup = errors.New("clientauth: client lookup")

// URLFetcher fetches a parsed JWK Set from a remote URL. The
// production wiring backs this with internal/jar.Fetcher,
// which adds caching, singleflight, an SSRF deny-list, and a body cap.
// The interface stays narrow so internal/clientauth does not have
// to import internal/jar (and so embedders can stub it in tests).
type URLFetcher interface {
	Fetch(ctx context.Context, url string) (*josev4.JSONWebKeySet, error)
}

// freshURLFetcher is the optional extension a [URLFetcher] implements to
// support a cache-bypassing refetch. The production
// internal/jar.Fetcher satisfies it;
// a fetcher that only implements [URLFetcher] simply loses key-rotation
// recovery (the resolver falls back to the cached keyset).
type freshURLFetcher interface {
	FetchFresh(ctx context.Context, url string) (*josev4.JSONWebKeySet, error)
}

// StoreJWKSResolver is a [JWKSResolver] backed by an
// [store.ClientStore]. It resolves a clientID to the client's
// inline-registered JWKs ([store.Client.JWKs]) or, when the client
// registered a [store.Client.JWKsURI] instead AND the resolver was
// constructed with a [URLFetcher], to the keyset fetched from the URL.
// A client carrying both is refused.
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
	// Wrap the store so the three GetClient seams a single assertion
	// verification hits (alg pin, JWKS lookup, rotation refetch) collapse
	// to one backing-store round-trip per request context (see clientmemo.go).
	return &StoreJWKSResolver{clients: memoClientStore{inner: clients}}, nil
}

// SetURLFetcher attaches a [URLFetcher] so the resolver can honour
// [store.Client.JWKsURI] when the client has no inline JWKs. Passing
// nil disables URL-based resolution; the resolver then falls back to
// [ErrJWKSURIUnsupported] for clients that registered only a URI.
func (r *StoreJWKSResolver) SetURLFetcher(f URLFetcher) {
	r.urlFetcher = f
}

// AssertionSigningAlg returns the per-client private_key_jwt alg pin,
// when one was registered. An empty string means the client did not pin
// the assertion algorithm.
func (r *StoreJWKSResolver) AssertionSigningAlg(ctx context.Context, clientID string) (string, error) {
	client, err := r.lookupClient(ctx, clientID)
	if err != nil {
		return "", err
	}
	return client.TokenEndpointAuthSigningAlg, nil
}

// JWKS implements [JWKSResolver]. It looks the client up by id,
// decodes the inline JWK Set on [store.Client.JWKs], and returns
// it. Missing client / missing keys / malformed JSON all surface
// distinct errors so the verifier can decide which onto-wire
// translation is appropriate (today every path collapses to
// [ErrCredentialsInvalid] to avoid leaking signal).
func (r *StoreJWKSResolver) JWKS(ctx context.Context, clientID string) (*josev4.JSONWebKeySet, error) {
	client, err := r.lookupClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if err := checkKeySource(client); err != nil {
		return nil, err
	}
	if len(client.JWKs) == 0 {
		if r.urlFetcher == nil {
			return nil, ErrJWKSURIUnsupported
		}
		keys, err := r.urlFetcher.Fetch(ctx, client.JWKsURI)
		if err != nil {
			return nil, fmt.Errorf("clientauth: fetch JWKs: %w", err)
		}
		return nonEmptyKeySet(keys)
	}
	// Decoding shares [rpjwks.ParseKeySet] with the fetched path, so the
	// registered keyset is bounded by the same member cap and decoded
	// member-wise: a key this build cannot represent (an X25519 encryption key
	// published next to the client's signing key, say) is ignored rather than
	// discarding the whole set, per RFC 7517 §5.
	keys, err := rpjwks.ParseKeySet(client.JWKs)
	if err != nil {
		return nil, fmt.Errorf("clientauth: parse client JWKs: %w", err)
	}
	return nonEmptyKeySet(keys)
}

// RefreshJWKS forces a cache-bypassing refetch of a jwks_uri-registered
// client's keyset, so an assertion signed with a key the client rotated
// in after the OP last cached its keyset can still authenticate. It is
// consulted by [PrivateKeyJWTVerifier.Verify] only after a verification
// miss, and only when the assertion's kid is absent from the cached set.
//
// Inline-JWKs clients cannot rotate out-of-band, so RefreshJWKS returns
// their inline keyset unchanged (equivalent to [StoreJWKSResolver.JWKS]).
// A jwks_uri client whose fetcher does not implement [freshURLFetcher]
// yields [ErrJWKSURIUnsupported]; the verifier treats that as "no fresh
// keys available" and leaves the original miss in place.
func (r *StoreJWKSResolver) RefreshJWKS(ctx context.Context, clientID string) (*josev4.JSONWebKeySet, error) {
	client, err := r.lookupClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if err := checkKeySource(client); err != nil {
		return nil, err
	}
	if len(client.JWKs) != 0 {
		return r.JWKS(ctx, clientID)
	}
	fresh, ok := r.urlFetcher.(freshURLFetcher)
	if !ok {
		return nil, ErrJWKSURIUnsupported
	}
	keys, err := fresh.FetchFresh(ctx, client.JWKsURI)
	if err != nil {
		return nil, fmt.Errorf("clientauth: refetch JWKs: %w", err)
	}
	return nonEmptyKeySet(keys)
}

// lookupClient loads the client, mapping a missing one to
// [ErrJWKSNotConfigured] and a store fault to [errClientLookup].
func (r *StoreJWKSResolver) lookupClient(ctx context.Context, clientID string) (*store.Client, error) {
	client, err := r.clients.GetClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrJWKSNotConfigured
		}
		return nil, fmt.Errorf("%w: %w", errClientLookup, err)
	}
	return client, nil
}

// nonEmptyKeySet returns keys, or [ErrJWKSNotConfigured] when it holds none.
func nonEmptyKeySet(keys *josev4.JSONWebKeySet) (*josev4.JSONWebKeySet, error) {
	if keys == nil || len(keys.Keys) == 0 {
		return nil, ErrJWKSNotConfigured
	}
	return keys, nil
}

// checkKeySource applies the OP-wide jwks-vs-jwks_uri rule
// ([rpjwks.CheckKeySource]): a client with neither, or both, has no key
// source to verify against.
func checkKeySource(client *store.Client) error {
	if err := rpjwks.CheckKeySource(client.JWKs, client.JWKsURI); err != nil {
		return fmt.Errorf("%w: %w", ErrJWKSNotConfigured, err)
	}
	return nil
}
