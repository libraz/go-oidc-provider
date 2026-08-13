package netsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Default knobs the package applies when [Options] leaves a field
// zero. The numbers mirror the in-tree posture of the JAR / sector /
// backchannel fetchers so the consolidation does not change the
// observable shape of any one fetcher.
const (
	// DefaultTimeout is the per-request budget applied when
	// [Options.Timeout] is zero. Five seconds is the minimum the JAR
	// JWKS fetcher already used; raising it would let a slow peer
	// stall the OP, lowering it would refuse healthy upstreams.
	DefaultTimeout = 5 * time.Second

	// DefaultDialTimeout caps the time the kernel may spend on a
	// single TCP / TLS dial. The cap is independent of the overall
	// timeout so a stalled DNS lookup cannot consume the entire
	// per-request budget.
	DefaultDialTimeout = 3 * time.Second
)

// Sentinel errors returned by the SSRF gate. Callers branch on these
// with [errors.Is] to distinguish gate refusals from generic transport
// errors.
var (
	// ErrPrivateNetworkBlocked signals the URL or one of its resolved
	// addresses lands in the deny-list. Loopback, link-local, RFC
	// 1918 / ULA, and unspecified addresses surface as this error.
	ErrPrivateNetworkBlocked = errors.New("netsec: target resolves to a deny-listed network")

	// ErrCloudMetadataBlocked signals the URL targets a cloud-provider
	// metadata service. The error is a distinct sentinel because the
	// gate fires even when [Options.AllowPrivate] is true; callers
	// that surface the rejection to operators may want to log it
	// separately so a metadata-IP attempt is not buried in the
	// private-network noise.
	ErrCloudMetadataBlocked = errors.New("netsec: target is a cloud metadata service")

	// ErrSchemeNotAllowed signals the URL scheme is outside the
	// http / https allow-list.
	ErrSchemeNotAllowed = errors.New("netsec: scheme not allowed")

	// ErrMissingHost signals the URL has no host component.
	ErrMissingHost = errors.New("netsec: url has no host")

	// ErrRedirectBlocked signals a redirect target failed the
	// deny-list re-check or exceeded [Options.MaxRedirects].
	ErrRedirectBlocked = errors.New("netsec: redirect blocked")
)

// Options configures [NewHTTPClient]. The zero value is a hardened
// production posture: deny-list engaged, no redirects, default
// timeout. Tests opt into more permissive shapes (allow private,
// follow redirects, custom resolver) by setting fields explicitly.
type Options struct {
	// AllowPrivate, when true, suppresses the [IsPrivateIP] /
	// [IsLocalHostname] gate so deployments that legitimately host
	// their RPs on a private LAN can reach those endpoints.
	// Cloud-metadata addresses ([IsCloudMetadataIP]) are still
	// rejected — see the package doc for the rationale.
	AllowPrivate bool

	// AllowLoopback is the narrow flavour of [Options.AllowPrivate]:
	// it releases the gate for loopback destinations only (127.0.0.0/8,
	// ::1, and their IPv4-mapped IPv6 spellings, plus the textual names
	// [IsLocalHostname] matches). Link-local, RFC 1918, IPv6 ULA, the
	// unspecified address and cloud metadata stay blocked.
	//
	// The field exists so a caller whose documented promise is "this
	// reaches a stub bound on a loopback port" does not have to buy the
	// whole private-network range to keep that promise. A textual
	// loopback name is still resolved and every resolved address must
	// itself be loopback, so a split-horizon resolver cannot widen the
	// opt-in by mapping "localhost" onto an internal host.
	//
	// [Options.AllowPrivate] is the wider setting and wins when both
	// are true.
	AllowLoopback bool

	// AllowedSchemes is the URL scheme allow-list. A nil / empty value
	// falls back to {"http", "https"}; pass {"https"} to force TLS.
	AllowedSchemes []string

	// MaxRedirects caps the number of redirects [http.Client] will
	// follow. Zero (the default) refuses every redirect; the gate
	// re-runs on each Location header before the redirect is taken.
	MaxRedirects int

	// Timeout is the overall request budget. Zero falls back to
	// [DefaultTimeout].
	Timeout time.Duration

	// DialTimeout caps the TCP / TLS dial phase. Zero falls back to
	// [DefaultDialTimeout].
	DialTimeout time.Duration

	// Resolver overrides the DNS resolver consulted for the pre-dial
	// gate. A nil value falls back to [net.DefaultResolver]; tests
	// inject a stub so the rebinding gate can be exercised
	// deterministically.
	Resolver *net.Resolver

	// LookupHook is a finer-grained injection point than [Options.Resolver]:
	// it replaces the LookupIPAddr call directly so the test does not
	// have to construct a synthetic [*net.Resolver]. Production code
	// leaves this nil; the field is unexported-ish in spirit but kept
	// public so tests outside the package can wire it.
	LookupHook func(ctx context.Context, host string) ([]net.IPAddr, error)

	// DialControlHook lets a test observe / replace the
	// [Dialer.Control] body. Production code leaves this nil and the
	// package installs its own deny-list check; tests wrap the result
	// to assert the hook fired or to simulate a specific kernel-level
	// failure shape.
	DialControlHook func(network, address string, c syscall.RawConn) error

	// BaseTransport overrides the [http.RoundTripper] base. The
	// package installs its own [http.Transport] when this is nil.
	//
	// When a non-nil value is supplied, the dial-time SSRF gate is
	// only installed if the value is a [*http.Transport]: the package
	// clones it and replaces [http.Transport.DialContext] so the
	// deny-list fires at kernel-resolution time. For any other
	// [http.RoundTripper] (otelhttp wrap, in-process round-tripper,
	// recording transport for tests) the package CANNOT reach the
	// dialer, so it falls back to a per-RoundTrip URL re-check that
	// runs [AssertSafeURLParsed] before delegating. The fallback
	// catches gross URL-level SSRF (private literal IP, cloud metadata
	// host) but does not protect against a DNS-rebinding peer that
	// hands out a public address at gate-time and a private one at
	// dial-time. Embedders requiring full dial-time protection MUST
	// supply a [*http.Transport].
	BaseTransport http.RoundTripper

	// Proxy is the per-request proxy resolver installed on the default
	// transport. The zero value (nil) means "no proxy"; the SSRF
	// posture is therefore independent of the [HTTP_PROXY] /
	// [HTTPS_PROXY] environment variables that [http.ProxyFromEnvironment]
	// would otherwise honour. Embedders that need an outbound proxy
	// pass [http.ProxyFromEnvironment] (or a custom resolver)
	// explicitly so the trust boundary is visible at the call site
	// rather than implied by the deployment environment.
	//
	// The field is consulted only when [BaseTransport] is nil; a
	// caller-supplied transport carries its own proxy configuration.
	Proxy func(*http.Request) (*url.URL, error)
}

// allowedSchemes returns the resolved scheme allow-list, applying the
// http+https default when the caller left the field nil.
func (o Options) allowedSchemes() []string {
	if len(o.AllowedSchemes) == 0 {
		return []string{"http", "https"}
	}
	return o.AllowedSchemes
}

// resolveTimeout returns the overall request budget the client should
// apply, falling back to [DefaultTimeout] when the option is unset.
func (o Options) resolveTimeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return DefaultTimeout
}

// resolveDialTimeout returns the dial budget the [Dialer] should
// apply, falling back to [DefaultDialTimeout] when the option is unset.
func (o Options) resolveDialTimeout() time.Duration {
	if o.DialTimeout > 0 {
		return o.DialTimeout
	}
	return DefaultDialTimeout
}

// resolver returns the [*net.Resolver] the gate should consult for
// pre-dial DNS. Nil falls back to [net.DefaultResolver].
func (o Options) resolver() *net.Resolver {
	if o.Resolver != nil {
		return o.Resolver
	}
	return net.DefaultResolver
}

// AssertSafeURL runs the syntactic + DNS-time SSRF gate against raw.
// The function returns nil when raw is safe to dial; any deny-list
// rejection wraps one of the package sentinels so callers branch with
// [errors.Is].
//
// Callers SHOULD invoke this before constructing the [*http.Request]
// so a clearly-bad URL never reaches the HTTP layer; [NewHTTPClient]
// re-runs the same gate at dial time so a TOCTOU window between this
// call and [http.Client.Do] cannot widen the surface.
func AssertSafeURL(ctx context.Context, raw string, opts Options) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("netsec: parse url: %w", err)
	}
	return AssertSafeURLParsed(ctx, u, opts)
}

// AssertSafeURLParsed is the [*url.URL] flavour of [AssertSafeURL].
// The two share an implementation; the parsed flavour exists so
// callers that already hold a [*url.URL] avoid the round-trip through
// [url.Parse].
func AssertSafeURLParsed(ctx context.Context, u *url.URL, opts Options) error {
	if !schemeAllowed(u.Scheme, opts.allowedSchemes()) {
		return fmt.Errorf("%w: %q", ErrSchemeNotAllowed, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return ErrMissingHost
	}
	if IsLocalHostname(host) {
		if opts.AllowPrivate {
			// Even with AllowPrivate, "localhost" is benign so we let
			// it through; a deployment opting into private networks
			// expects to reach loopback addresses.
			return nil
		}
		if opts.AllowLoopback {
			// The loopback-only opt-in admits the textual name but
			// still insists the name resolves to a loopback address:
			// a split-horizon resolver that maps "localhost" onto an
			// internal host would otherwise turn the narrow opt-in
			// back into a private-network one.
			return assertResolvedHostSafe(ctx, host, opts)
		}
		return fmt.Errorf("%w: host %q is loopback / localhost", ErrPrivateNetworkBlocked, host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return assertIPSafe(ip, host, opts)
	}
	return assertResolvedHostSafe(ctx, host, opts)
}

// addrVerdict is the outcome [Options.classifyAddr] returns for one
// resolved address.
type addrVerdict int

const (
	// addrAllowed means the address may be dialled under the caller's
	// opt-in posture.
	addrAllowed addrVerdict = iota
	// addrDeniedPrivate means the address is inside the private
	// deny-list and no opt-in released it.
	addrDeniedPrivate
	// addrDeniedMetadata means the address is a cloud-metadata
	// service, which no opt-in releases.
	addrDeniedMetadata
)

// classifyAddr is the single place the package decides whether one
// address may be dialled. All four enforcement points — the IP-literal
// check, the DNS-time check, the [Dialer.Control] hook and the
// redirect re-check — route through it so an opt-in cannot mean one
// thing at the URL gate and another at the socket.
func (o Options) classifyAddr(ip net.IP) addrVerdict {
	if IsCloudMetadataIP(ip) {
		// Rejected under every opt-in; see [IsCloudMetadataIP].
		return addrDeniedMetadata
	}
	if o.AllowPrivate {
		return addrAllowed
	}
	if !IsPrivateIP(ip) {
		return addrAllowed
	}
	if o.AllowLoopback && ip.IsLoopback() {
		// [net.IP.IsLoopback] covers 127.0.0.0/8, ::1 and the
		// IPv4-mapped IPv6 spelling of the v4 block.
		return addrAllowed
	}
	return addrDeniedPrivate
}

// assertIPSafe runs the deny-list against a literal IP host. The
// helper is split out so [AssertSafeURLParsed] stays under the
// project gocognit gate.
func assertIPSafe(ip net.IP, host string, opts Options) error {
	switch opts.classifyAddr(ip) {
	case addrDeniedMetadata:
		return fmt.Errorf("%w: host %q is a cloud metadata IP", ErrCloudMetadataBlocked, host)
	case addrDeniedPrivate:
		return fmt.Errorf("%w: host %q is loopback / link-local / private", ErrPrivateNetworkBlocked, host)
	case addrAllowed:
	}
	return nil
}

// assertResolvedHostSafe performs the DNS-time SSRF check.
func assertResolvedHostSafe(ctx context.Context, host string, opts Options) error {
	lookup := opts.LookupHook
	if lookup == nil {
		lookup = opts.resolver().LookupIPAddr
	}
	lookupCtx, cancel := context.WithTimeout(ctx, opts.resolveTimeout())
	defer cancel()
	addrs, err := lookup(lookupCtx, host)
	if err != nil {
		return fmt.Errorf("netsec: lookup %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("netsec: lookup %q returned no addresses", host)
	}
	for _, addr := range addrs {
		switch opts.classifyAddr(addr.IP) {
		case addrDeniedMetadata:
			return fmt.Errorf("%w: host %q resolves to a cloud metadata IP %s",
				ErrCloudMetadataBlocked, host, addr.IP)
		case addrDeniedPrivate:
			return fmt.Errorf("%w: host %q resolves to a private IP %s",
				ErrPrivateNetworkBlocked, host, addr.IP)
		case addrAllowed:
		}
	}
	return nil
}

// schemeAllowed reports whether scheme is one of allowed (case-fold).
func schemeAllowed(scheme string, allowed []string) bool {
	want := strings.ToLower(scheme)
	for _, a := range allowed {
		if strings.EqualFold(a, want) {
			return true
		}
	}
	return false
}

// NewHTTPClient returns a [*http.Client] hardened against the SSRF
// patterns documented on the package. The caller MUST still invoke
// [AssertSafeURL] before constructing the request — the client-side
// gate is a defence-in-depth layer that catches DNS rebinding (the
// resolver hands out a public IP on the syntactic check, then a
// private IP at dial time); it does not replace the URL-time check.
//
// The returned client carries a custom [*http.Transport] with a
// [Dialer.Control] hook that re-checks the kernel-resolved address
// against the deny-list. A redirect target whose host fails the gate
// surfaces as [ErrRedirectBlocked]; otherwise the redirect count is
// capped at [Options.MaxRedirects].
//
// When [Options.BaseTransport] is a non-nil [http.RoundTripper] that
// is NOT a [*http.Transport], the package cannot reach the dialer.
// In that case the function wraps the supplied round-tripper with a
// per-request [AssertSafeURLParsed] re-check — the kernel-level
// dial gate is unreachable, but URL-level SSRF (private IP literal,
// cloud metadata host, scheme outside the allow-list) still fires
// before the round-trip is delegated. Embedders that require the
// dial-time gate MUST pass a [*http.Transport] (or leave the field
// nil so the package builds its own).
//
// The default [http.Transport] is built with [Options.Proxy] (nil
// by default — no proxy). Callers that need an outbound proxy pass
// [http.ProxyFromEnvironment] (or a custom resolver) explicitly so
// the trust boundary is visible at the call site rather than implied
// by the deployment environment.
func NewHTTPClient(opts Options) *http.Client {
	dialer := &net.Dialer{
		Timeout:   opts.resolveDialTimeout(),
		KeepAlive: 30 * time.Second,
		Control:   makeDialControl(opts),
	}
	transport := opts.BaseTransport
	if transport == nil {
		// Mirror http.DefaultTransport's posture but install our own
		// dialer and sharpen the connection budgets so a misbehaving
		// peer cannot starve the OP's outbound pool. Proxy resolution
		// is opt-in via [Options.Proxy] so the SSRF model does not
		// silently inherit HTTP_PROXY / HTTPS_PROXY from the env.
		transport = &http.Transport{
			Proxy:                 opts.Proxy,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          16,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   opts.resolveDialTimeout(),
			ExpectContinueTimeout: 1 * time.Second,
			DialContext:           dialer.DialContext,
		}
	} else if t, ok := transport.(*http.Transport); ok {
		// Clone so we do not mutate the caller's transport.
		// Replacing DialContext is the only way the deny-list
		// reaches the kernel-level resolution; the clone preserves
		// the caller's other settings (proxy, TLS config) verbatim.
		clone := t.Clone()
		clone.DialContext = dialer.DialContext
		transport = clone
	} else {
		// The supplied round-tripper is not a [*http.Transport],
		// so we cannot reach the dialer. Wrap it so [AssertSafeURLParsed]
		// re-runs on every outbound request URL before delegating.
		transport = &urlGateRoundTripper{base: transport, opts: opts}
	}

	return &http.Client{
		Transport:     transport,
		Timeout:       opts.resolveTimeout(),
		CheckRedirect: makeCheckRedirect(opts),
	}
}

// urlGateRoundTripper wraps a caller-supplied [http.RoundTripper]
// that is not a [*http.Transport]. It re-runs [AssertSafeURLParsed]
// on every outbound request URL before delegating so the URL-level
// deny-list fires regardless of the underlying transport's dialer.
//
// The wrap is the fallback the package installs when the dial-time
// gate is unreachable; see [NewHTTPClient]'s godoc for the trade-off
// versus the *http.Transport path.
type urlGateRoundTripper struct {
	base http.RoundTripper
	opts Options
}

// RoundTrip implements [http.RoundTripper].
func (r *urlGateRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := AssertSafeURLParsed(req.Context(), req.URL, r.opts); err != nil {
		return nil, err
	}
	return r.base.RoundTrip(req)
}

// makeDialControl returns a [Dialer.Control] hook that rejects
// connections whose resolved address lands in the deny-list. The hook
// fires after the kernel resolved the address but before the SYN
// goes out, so a TOCTOU rebinding between the URL-time gate and the
// dial cannot escape.
func makeDialControl(opts Options) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		// network is "tcp4" / "tcp6"; address is "ip:port".
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("netsec: split host/port %q: %w", address, err)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			// The dialer always hands a literal IP at this point
			// (resolution already happened); a non-IP host is a bug
			// in the caller, not an attack.
			return fmt.Errorf("netsec: dial address %q is not an IP literal", address)
		}
		switch opts.classifyAddr(ip) {
		case addrDeniedMetadata:
			return fmt.Errorf("%w: dial address %s is a cloud metadata IP", ErrCloudMetadataBlocked, ip)
		case addrDeniedPrivate:
			return fmt.Errorf("%w: dial address %s is loopback / link-local / private", ErrPrivateNetworkBlocked, ip)
		case addrAllowed:
		}
		if opts.DialControlHook != nil {
			return opts.DialControlHook(network, address, c)
		}
		return nil
	}
}

// makeCheckRedirect returns the [http.Client.CheckRedirect] hook that
// caps redirects at [Options.MaxRedirects] and re-runs the deny-list
// against every Location target. The function returns
// [http.ErrUseLastResponse] when [Options.MaxRedirects] is zero so the
// caller surfaces the 30x verbatim instead of seeing a synthetic
// "stopped after N redirects" error.
func makeCheckRedirect(opts Options) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if opts.MaxRedirects <= 0 {
			return http.ErrUseLastResponse
		}
		if len(via) >= opts.MaxRedirects {
			return fmt.Errorf("%w: exceeded MaxRedirects=%d", ErrRedirectBlocked, opts.MaxRedirects)
		}
		if err := AssertSafeURLParsed(req.Context(), req.URL, opts); err != nil {
			return fmt.Errorf("%w: %w", ErrRedirectBlocked, err)
		}
		return nil
	}
}
