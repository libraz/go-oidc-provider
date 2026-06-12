package clientencjwks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Default knobs the package applies when [Config] leaves a field
// zero. The numbers mirror the JAR JWKS fetcher posture so the
// outbound-encryption side does not introduce new SSRF / DoS
// surface relative to the inbound side.
const (
	// defaultHTTPTimeout caps the per-request budget on the JWKS
	// fetcher. Five seconds is the same value the JAR fetcher uses.
	defaultHTTPTimeout = 5 * time.Second

	// defaultJWKSCacheTTL is the in-memory cache lifetime for a
	// fetched keyset. Five minutes is short enough that an RP key
	// rotation propagates without operator intervention while
	// saving most fetches.
	defaultJWKSCacheTTL = 5 * time.Minute

	// defaultMaxBodyBytes caps the JWKS body size at 64 KiB. Real
	// keysets are well under 4 KiB; the ceiling exists to bound
	// memory use against a malicious or misconfigured peer.
	defaultMaxBodyBytes = int64(64 * 1024)
)

// Config configures [New]. The zero value is a hardened production
// posture: deny-list engaged, default timeouts, default cache TTL.
// Tests opt into more permissive shapes by setting fields explicitly.
type Config struct {
	// Clock drives the JWKS cache TTL. A nil value falls back to
	// [timex.SystemClock]; tests inject a fake clock so cache
	// behaviour is deterministic without sleeping.
	Clock timex.Clock

	// HTTPTimeout caps the per-request budget on the JWKS fetcher.
	// Zero falls back to [defaultHTTPTimeout].
	HTTPTimeout time.Duration

	// JWKSCacheTTL is the in-memory cache lifetime applied to every
	// fetched keyset. Zero falls back to [defaultJWKSCacheTTL].
	JWKSCacheTTL time.Duration

	// AllowPrivateNetwork, when true, suppresses the SSRF deny-list
	// so deployments that legitimately host RPs on a private LAN
	// can reach those endpoints. Cloud-metadata addresses remain
	// rejected even with this flag set.
	AllowPrivateNetwork bool

	// MaxBodyBytes caps the JWKS body size. Zero falls back to
	// [defaultMaxBodyBytes].
	MaxBodyBytes int64

	// BaseTransport overrides the [http.RoundTripper] base inside
	// the SSRF-hardened client. Production callers leave it nil; a
	// caller that already maintains an instrumented transport
	// (otelhttp wrap, custom dial pool) injects it here. The SSRF
	// dial hook is reinstalled on the supplied transport so the
	// deny-list still fires regardless.
	BaseTransport http.RoundTripper
}

// Resolver builds a [jose.EncryptionRecipient] for an RP given the
// client record and the registered (alg, enc) pair. The struct is
// safe for concurrent use; callers construct it once at startup and
// share the instance across every outbound-encryption response path.
type Resolver struct {
	cache   *jwksCache
	fetcher *fetcher
}

// New returns a resolver wired with the supplied configuration. The
// function applies [Config] defaults for every zero-valued field; a
// zero-valued [Config] is a valid hardened production posture.
func New(cfg Config) *Resolver {
	httpTimeout := cfg.HTTPTimeout
	if httpTimeout <= 0 {
		httpTimeout = defaultHTTPTimeout
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxBodyBytes
	}

	client := securefetch.NewClient(securefetch.Policy{
		AllowPrivateNetwork: cfg.AllowPrivateNetwork,
		MaxBodyBytes:        maxBody,
		AcceptContentTypes:  []string{"application/json", "application/jwk-set+json"},
		Timeout:             httpTimeout,
		BaseTransport:       cfg.BaseTransport,
	})
	return &Resolver{
		cache:   newJWKSCache(cfg.Clock, cfg.JWKSCacheTTL),
		fetcher: &fetcher{client: client},
	}
}

// ResolveRecipient returns the JOSE encryption recipient for client
// given the client's registered (alg, enc) pair. Caller branches on
// the package sentinels via [errors.Is] (see the package doc for the
// full list).
//
// Resolution proceeds in this order:
//
//  1. If alg and enc are both empty the client did not register
//     encryption metadata for this response path; the function
//     surfaces [ErrNoEncryptionConfigured] so the caller skips the
//     JWE wrap.
//  2. Both alg and enc must be on the OP allow-list
//     ([internal/jose.JWEAlg.IsAllowed] /
//     [internal/jose.JWEEnc.IsAllowed]); a non-empty value outside
//     the list surfaces [ErrAlgNotAllowed].
//  3. The JWKS comes from inline JWKs (preferred) or from
//     JWKsURI through the cache. A client carrying neither shape
//     surfaces [ErrJWKSConfigured].
//  4. The first key with `use=enc` (or empty `use`, per RFC 7517
//     §4.2 — `use` is OPTIONAL) whose `alg` matches or is
//     unspecified wins. No matching key surfaces
//     [ErrNoMatchingKey].
func (r *Resolver) ResolveRecipient(
	ctx context.Context,
	client *store.Client,
	alg, enc string,
) (jose.EncryptionRecipient, error) {
	if alg == "" && enc == "" {
		return jose.EncryptionRecipient{}, ErrNoEncryptionConfigured
	}
	jweAlg, jweEnc, err := validateAlgEnc(alg, enc)
	if err != nil {
		return jose.EncryptionRecipient{}, err
	}
	if client == nil {
		return jose.EncryptionRecipient{}, ErrJWKSConfigured
	}
	keys, err := r.resolveJWKS(ctx, client)
	if err != nil {
		return jose.EncryptionRecipient{}, err
	}
	key, ok, weakErr := pickEncryptionKey(keys, jweAlg)
	if weakErr != nil {
		return jose.EncryptionRecipient{}, weakErr
	}
	if !ok {
		return jose.EncryptionRecipient{}, ErrNoMatchingKey
	}
	return jose.EncryptionRecipient{
		Alg:   jweAlg,
		Enc:   jweEnc,
		KeyID: key.KeyID,
		Key:   key.Key,
	}, nil
}

// resolveJWKS returns the parsed JWKS for client. Inline JWKs win
// over JWKsURI; both empty surfaces [ErrJWKSConfigured]. Remote
// fetches go through the package's TTL cache so a busy outbound
// path collapses repeated lookups to one network round-trip per
// cache window.
func (r *Resolver) resolveJWKS(
	ctx context.Context,
	client *store.Client,
) (*josev4.JSONWebKeySet, error) {
	if len(client.JWKs) > 0 {
		var keys josev4.JSONWebKeySet
		if err := json.Unmarshal(client.JWKs, &keys); err != nil {
			return nil, fmt.Errorf("%w: parse inline jwks: %w", ErrJWKSFetch, err)
		}
		return &keys, nil
	}
	if client.JWKsURI != "" {
		if cached, ok := r.cache.get(client.JWKsURI); ok {
			return cached, nil
		}
		keys, err := r.fetcher.fetch(ctx, client.JWKsURI)
		if err != nil {
			return nil, err
		}
		r.cache.put(client.JWKsURI, keys)
		return keys, nil
	}
	return nil, ErrJWKSConfigured
}

// validateAlgEnc parses raw alg / enc strings against the OP-wide
// JWE allow-list. Either side outside the list collapses onto
// [ErrAlgNotAllowed] so an attacker probing for sub-causes through
// the wire response learns nothing useful.
//
// The function tolerates an empty alg / enc only when both are
// empty (handled by the caller). When one side is set the other
// MUST also be set, otherwise the function returns
// [ErrAlgNotAllowed] — partial encryption metadata is a
// configuration bug.
func validateAlgEnc(alg, enc string) (jose.JWEAlg, jose.JWEEnc, error) {
	if alg == "" || enc == "" {
		return "", "", fmt.Errorf("%w: alg=%q enc=%q (both required)", ErrAlgNotAllowed, alg, enc)
	}
	jweAlg, ok := jose.ParseJWEAlg(alg)
	if !ok {
		return "", "", fmt.Errorf("%w: alg %q", ErrAlgNotAllowed, alg)
	}
	jweEnc, ok := jose.ParseJWEEnc(enc)
	if !ok {
		return "", "", fmt.Errorf("%w: enc %q", ErrAlgNotAllowed, enc)
	}
	return jweAlg, jweEnc, nil
}

// pickEncryptionKey returns the first key in keys whose `use` is
// "enc" or empty (RFC 7517 §4.2 — `use` is OPTIONAL) and whose
// `alg` matches or is unspecified. The function returns false when
// no key qualifies so the caller surfaces [ErrNoMatchingKey].
//
// The caller is responsible for validating the (alg, enc) pair
// against the OP allow-list before calling this helper; the helper
// does not re-check.
func pickEncryptionKey(keys *josev4.JSONWebKeySet, alg jose.JWEAlg) (josev4.JSONWebKey, bool, error) {
	if keys == nil {
		return josev4.JSONWebKey{}, false, nil
	}
	target := alg.String()
	var weakErr error
	for i := range keys.Keys {
		k := keys.Keys[i]
		if k.Use != "" && k.Use != "enc" {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != target {
			continue
		}
		if err := jose.AssertJWEAlgKeyShape(alg, k.Key); err != nil {
			weakErr = fmt.Errorf("%w: kid %q: %w", ErrWeakRecipientKey, k.KeyID, err)
			continue
		}
		return k, true, nil
	}
	return josev4.JSONWebKey{}, false, weakErr
}
