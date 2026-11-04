package rs

import (
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// DPoPMode selects how a [Verifier] treats DPoP (RFC 9449).
//
// Stable since v1.5.
type DPoPMode int

const (
	// DPoPAllowed is the zero value. Bearer tokens are accepted, and a
	// token whose cnf carries "jkt" is accepted only under the DPoP scheme
	// with a valid proof. The challenge offers both the Bearer and the
	// DPoP scheme.
	//
	// Stable since v1.5.
	DPoPAllowed DPoPMode = iota

	// DPoPRequired accepts only DPoP-bound tokens presented under the
	// DPoP scheme. The challenge offers the DPoP scheme alone.
	//
	// Stable since v1.5.
	DPoPRequired
)

// optInAllowPrivateNetwork is the setting a private-network refusal
// names, spelled as the embedder writes it.
const optInAllowPrivateNetwork = "rs.Config.AllowPrivateNetwork"

// Config configures [New]. Issuer and Audience are required; every other
// field has a working zero value.
//
// Stable since v1.5.
type Config struct {
	// Issuer is the authorization server's issuer identifier. The "iss"
	// claim of a JWT, and the "iss" member of an introspection response,
	// must equal it byte for byte. When JWKSURI or the introspection
	// endpoint is left empty, the OpenID Provider metadata at Issuer +
	// "/.well-known/openid-configuration" is fetched once, cached, and its
	// "issuer" must equal Issuer as well.
	Issuer string

	// Audience is this resource server's identifier. A token is accepted
	// only when its "aud" (a string or an array) contains it. It is also
	// the realm of the Bearer challenge.
	Audience string

	// JWKSURI is the issuer's JWK Set URL. Empty takes "jwks_uri" from the
	// discovery document. The URL must use https; plain http is admitted
	// only for a loopback IP literal with AllowPrivateNetwork set.
	JWKSURI string

	// HTTPClient supplies the transport and timeout for discovery, JWK Set
	// and introspection requests. Only its Transport and Timeout are read:
	// the SSRF guard is always layered over the transport and redirects
	// are never followed. Nil uses the default transport.
	HTTPClient *http.Client

	// AllowPrivateNetwork lets discovery, JWK Set and introspection
	// requests reach loopback and private addresses. Cloud metadata
	// addresses stay blocked.
	AllowPrivateNetwork bool

	// Introspection enables RFC 7662 introspection for access tokens that
	// are not JWTs. Nil rejects every non-JWT token as invalid_token. See
	// [IntrospectionConfig] for the client authentication methods.
	Introspection *IntrospectionConfig

	// DPoP selects the DPoP posture. The zero value is [DPoPAllowed].
	DPoP DPoPMode

	// DPoPReplay records consumed DPoP proof identifiers. Nil uses an
	// in-process store, which detects a replay only on the instance that
	// saw the first use; a deployment running more than one instance must
	// supply a shared store such as the one its OP uses. When Logger is
	// set, [New] logs one warning for the in-process default.
	DPoPReplay store.ConsumedJTIStore

	// MTLSProxy names the header a trusted reverse proxy forwards the
	// client certificate in, and the CIDR ranges it is trusted from — the
	// same value the OP's [op.WithMTLSProxy] takes and
	// [op.Provider.MTLSProxy] reads back. Nil considers only the
	// certificate of the TLS handshake (r.TLS).
	MTLSProxy *op.MTLSProxy

	// Logger receives the in-process replay-store warning and the causes
	// of discovery, JWK Set and introspection failures. Nil logs nothing.
	Logger *slog.Logger

	// Clock is the time source for token expiry, DPoP proof windows and
	// RequireMaxAge. Nil uses the system clock.
	Clock op.Clock
}

// IntrospectionConfig configures RFC 7662 introspection of opaque access
// tokens. Exactly one client authentication method is set: ClientSecret
// (client_secret_basic), PrivateKey (private_key_jwt, RFC 7523) or
// TLSCertificate (tls_client_auth / self_signed_tls_client_auth, RFC 8705).
// An OP running a FAPI 2.0 profile refuses client_secret_basic, so a FAPI
// deployment sets PrivateKey or TLSCertificate.
//
// The request asks for an RFC 9701 JWT response and accepts plain JSON.
// A JWT response must carry typ "token-introspection+jwt", be signed by a
// key in the issuer's JWK Set, name Issuer as "iss" and ClientID in "aud";
// its token_introspection member is then read like a JSON response.
//
// The OP answers with the token's contents only when the authenticating
// client is listed in the IntrospectionClients of a protected resource
// the token is addressed to; otherwise every token reads as inactive.
// With this library's OP that is:
//
//	op.WithFeature(feature.Introspect),
//	op.WithProtectedResources(op.ProtectedResource{
//		Resource:             "<Config.Audience>",
//		IntrospectionClients: []string{"<IntrospectionConfig.ClientID>"},
//	})
//
// Stable since v1.5.
type IntrospectionConfig struct {
	// Endpoint is the introspection endpoint URL. Empty takes
	// "introspection_endpoint" from the discovery document. The URL rules
	// of [Config.JWKSURI] apply.
	Endpoint string

	// ClientID is the client_id the resource server authenticates as.
	// Required.
	ClientID string

	// ClientSecret selects client_secret_basic with this secret.
	ClientSecret string

	// PrivateKey selects private_key_jwt: each request carries a client
	// assertion signed with this key, with iss and sub set to ClientID and
	// aud set to Config.Issuer. The key is ECDSA P-256 (ES256), RSA of at
	// least 2048 bits (PS256) or Ed25519 (EdDSA).
	PrivateKey crypto.Signer

	// KeyID is the "kid" header of the client assertion, naming the
	// PrivateKey's public key in the client's registered JWK Set.
	// Required with PrivateKey.
	KeyID string

	// TLSCertificate selects mutual-TLS client authentication: the
	// certificate is presented on the connection to the introspection
	// endpoint. When Endpoint is empty, the discovery document's
	// "mtls_endpoint_aliases" introspection_endpoint is preferred over
	// "introspection_endpoint". The TLS settings of Config.HTTPClient's
	// transport are kept when it is an [*http.Transport]; any other
	// round-tripper is replaced by a clone of [http.DefaultTransport]
	// without its environment proxy.
	TLSCertificate *tls.Certificate
}

// Verifier checks access tokens for one resource server. It is safe for
// concurrent use; build one with [New] at startup and share it.
//
// Stable since v1.5.
type Verifier struct {
	issuer        string
	audience      string
	jwksURI       string
	introspection *IntrospectionConfig
	dpopMode      DPoPMode

	clock  timex.Clock
	logger *slog.Logger
	dpop   *dpop.Verifier
	mtls   *mtls.Verifier
	keys   *rpjwks.Fetcher
	fetch  *securefetch.Client
	rule   schemeRule

	// introspectFetch carries introspection requests: it accepts the RFC
	// 9701 JWT media type and, under mTLS, presents the client certificate.
	introspectFetch *securefetch.Client
	assertion       *clientAssertion

	metaMu       sync.Mutex
	meta         *serverMetadata
	metaFailedAt time.Time
}

// schemeRule carries the URL policy every outbound fetch target obeys.
type schemeRule struct {
	allowPrivate bool
}

// New validates cfg and returns a [Verifier]. It performs no network I/O;
// discovery and the JWK Set are fetched on first use.
//
// Stable since v1.5.
func New(cfg Config) (*Verifier, error) {
	rule := schemeRule{allowPrivate: cfg.AllowPrivateNetwork}
	if err := cfg.validate(rule); err != nil {
		return nil, err
	}
	clock := timex.OrSystem(cfg.Clock)
	replay := cfg.DPoPReplay
	if replay == nil {
		replay = inmem.New(inmem.WithClock(clock)).ConsumedJTIs()
		if cfg.Logger != nil {
			cfg.Logger.Warn("rs: DPoP replay protection uses an in-process store; a proof replayed against another instance is not detected (set Config.DPoPReplay to a shared store)")
		}
	}
	dv, err := dpop.NewVerifier(dpop.VerifierConfig{JTIs: replay, Clock: clock})
	if err != nil {
		return nil, fmt.Errorf("rs: %w", err)
	}
	var proxy mtls.ProxyConfig
	if cfg.MTLSProxy != nil {
		prefixes, perr := mtls.ParseTrustedProxies(cfg.MTLSProxy.TrustedProxies)
		if perr != nil {
			return nil, fmt.Errorf("rs: Config.MTLSProxy: %w", perr)
		}
		proxy = mtls.ProxyConfig{HeaderName: cfg.MTLSProxy.HeaderName, TrustedProxies: prefixes}
	}
	mv, err := mtls.NewVerifier(mtls.VerifierConfig{Proxy: proxy})
	if err != nil {
		return nil, fmt.Errorf("rs: %w", err)
	}
	transport, timeout := transportOf(cfg.HTTPClient)
	keys := rpjwks.New(rpjwks.Config{
		Clock:               clock,
		Timeout:             timeout,
		AllowPrivateNetwork: cfg.AllowPrivateNetwork,
		OptIn:               optInAllowPrivateNetwork,
		BaseTransport:       transport,
	})
	policy := securefetch.Policy{
		AllowPrivateNetwork: cfg.AllowPrivateNetwork,
		OptIn:               optInAllowPrivateNetwork,
		AllowedSchemes:      rule.schemes(),
		AcceptContentTypes:  []string{"application/json"},
		Timeout:             timeout,
		BaseTransport:       transport,
	}
	fetch := securefetch.NewClient(policy)
	var (
		introspection   *IntrospectionConfig
		introspectFetch *securefetch.Client
		assertion       *clientAssertion
	)
	if cfg.Introspection != nil {
		c := *cfg.Introspection
		introspection = &c
		introspectFetch = newIntrospectFetch(c, policy)
		if !nilcheck.IsNil(c.PrivateKey) {
			assertion, err = newClientAssertion(c.ClientID, c.KeyID, cfg.Issuer, c.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("rs: Config.Introspection.PrivateKey: %w", err)
			}
		}
	}
	return &Verifier{
		issuer:          cfg.Issuer,
		audience:        cfg.Audience,
		jwksURI:         cfg.JWKSURI,
		introspection:   introspection,
		introspectFetch: introspectFetch,
		assertion:       assertion,
		dpopMode:        cfg.DPoP,
		clock:           clock,
		logger:          cfg.Logger,
		dpop:            dv,
		mtls:            mv,
		keys:            keys,
		fetch:           fetch,
		rule:            rule,
	}, nil
}

// validate reports the first configuration error in c.
func (c Config) validate(rule schemeRule) error {
	switch {
	case c.Issuer == "":
		return errors.New("rs: Config.Issuer is required")
	case c.Audience == "":
		return errors.New("rs: Config.Audience is required")
	}
	switch c.DPoP {
	case DPoPAllowed, DPoPRequired:
	default:
		return fmt.Errorf("rs: Config.DPoP has unknown value %d", int(c.DPoP))
	}
	if p := c.MTLSProxy; p != nil && p.HeaderName != "" && len(p.TrustedProxies) == 0 {
		return errors.New("rs: Config.MTLSProxy names a header but no trusted proxies; the header would be trusted from nowhere")
	}
	if p := c.MTLSProxy; p != nil {
		if _, err := mtls.ParseTrustedProxies(p.TrustedProxies); err != nil {
			return fmt.Errorf("rs: Config.MTLSProxy: %w", err)
		}
	}
	return c.validateURLs(rule)
}

// validateURLs applies the outbound URL rule to every fetch target known
// at construction.
func (c Config) validateURLs(rule schemeRule) error {
	if c.JWKSURI != "" {
		if err := rule.check("Config.JWKSURI", c.JWKSURI); err != nil {
			return err
		}
	}
	if err := c.validateIntrospection(rule); err != nil {
		return err
	}
	if c.needsDiscovery() {
		return rule.check("Config.Issuer (used for discovery)", c.Issuer)
	}
	return nil
}

func (c Config) validateIntrospection(rule schemeRule) error {
	in := c.Introspection
	if in == nil {
		return nil
	}
	if in.ClientID == "" {
		return errors.New("rs: Config.Introspection requires ClientID")
	}
	methods := 0
	for _, set := range [...]bool{in.ClientSecret != "", !nilcheck.IsNil(in.PrivateKey), in.TLSCertificate != nil} {
		if set {
			methods++
		}
	}
	if methods != 1 {
		return errors.New("rs: Config.Introspection requires exactly one of ClientSecret, PrivateKey and TLSCertificate")
	}
	if !nilcheck.IsNil(in.PrivateKey) {
		if in.KeyID == "" {
			return errors.New("rs: Config.Introspection.PrivateKey requires KeyID")
		}
		if _, ok := assertionAlg(in.PrivateKey); !ok {
			return errors.New("rs: Config.Introspection.PrivateKey must be an ECDSA P-256, RSA (2048 bits or more) or Ed25519 key")
		}
	}
	if c := in.TLSCertificate; c != nil && (len(c.Certificate) == 0 || c.PrivateKey == nil) {
		return errors.New("rs: Config.Introspection.TLSCertificate requires a certificate and its private key")
	}
	if in.Endpoint != "" {
		return rule.check("Config.Introspection.Endpoint", in.Endpoint)
	}
	return nil
}

// needsDiscovery reports whether some endpoint has to come from the
// issuer's discovery document.
func (c Config) needsDiscovery() bool {
	return c.JWKSURI == "" || (c.Introspection != nil && c.Introspection.Endpoint == "")
}

// check enforces the outbound URL rule: an absolute https URL, or plain
// http to a loopback IP literal when private networks are allowed.
func (r schemeRule) check(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("rs: %s must be an absolute URL", name)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if addr, err := netip.ParseAddr(u.Hostname()); err == nil && addr.IsLoopback() && r.allowPrivate {
			return nil
		}
		return fmt.Errorf("rs: %s must use https; plain http is admitted only for a loopback IP literal with AllowPrivateNetwork", name)
	default:
		return fmt.Errorf("rs: %s must use https", name)
	}
}

// schemes is the scheme allow-list handed to the SSRF-hardened client.
func (r schemeRule) schemes() []string {
	if r.allowPrivate {
		return []string{"http", "https"}
	}
	return []string{"https"}
}

// transportOf extracts the parts of an embedder-supplied client the fetch
// layer honours.
func transportOf(c *http.Client) (http.RoundTripper, time.Duration) {
	if c == nil {
		return nil, 0
	}
	return c.Transport, c.Timeout
}
