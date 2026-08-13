package backchannel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/internal/netsec"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
)

// DefaultTimeout is the per-RP request budget the [HTTPDeliverer]
// applies when the embedder does not supply one. The value is long
// enough for a healthy RP to ack, short enough that a stalled RP
// does not hold the OP's logout flow open beyond the user's patience.
const DefaultTimeout = 5 * time.Second

// maxResponseBytes caps the response body the deliverer reads.
// Logout-token responses are RFC 7807 problem documents at most; a
// few KiB is plenty. The cap defends against a misbehaving RP that
// streams an unbounded body in response to a POST.
const maxResponseBytes = 8 * 1024

// Deliverer is the transport seam the [Coordinator] uses to ship a
// signed Logout Token to one RP. Implementations MUST be safe for
// concurrent use; the coordinator dispatches in goroutines.
//
// Deliver returns nil on a successful 200 / 204 response. Any
// non-2xx status, transport error, or context expiry returns a
// non-nil error so the coordinator can route the failure to the
// audit pipeline.
type Deliverer interface {
	Deliver(ctx context.Context, target Target, logoutToken string) error
}

// Target carries the per-RP routing data the [Coordinator] feeds to
// the [Deliverer]. The struct is a small value type; the coordinator
// builds one per fan-out and the deliverer never mutates it.
type Target struct {
	// ClientID is the audience client_id. The deliverer logs it on
	// failure so operators can correlate without parsing the token.
	ClientID string

	// Subject is the per-client subject value stamped into the Logout
	// Token's sub claim. In pairwise deployments this is the projected
	// subject for ClientID; otherwise it is the OP-internal subject.
	Subject string

	// URL is the absolute endpoint registered via
	// [op/store.Client.BackchannelLogoutURI]. The DCR / RM /
	// static-client validators reject any non-https / userinfo-bearing
	// / fragment-bearing URL at registration time, so production
	// stores never hand a plaintext URL here. The deliverer's SSRF
	// gate ([HTTPDeliverer.assertSafeURL]) remains as defence-in-depth
	// for the loopback / private-network carve-outs and for stores
	// populated by older builds.
	URL string
}

// HTTPDeliverer is the production [Deliverer]. It POSTs the logout
// token as application/x-www-form-urlencoded under the form field
// "logout_token", per OpenID Connect Back-Channel Logout 1.0 §2.5.
//
// The deliverer never follows redirects: the spec requires a direct
// POST to the registered URI, and a redirect is the easiest way an
// adversary upstream of the RP could trick the OP into sending a
// signed logout token to an unintended endpoint. The shared
// [*securefetch.Client] surfaces a redirect as a non-2xx status (the
// underlying [netsec] client sets MaxRedirects=0 and returns
// http.ErrUseLastResponse, leaving the 30x for the status gate).
//
// The deliverer also enforces an SSRF deny-list on every Target.URL:
// loopback / link-local / RFC 1918 / IPv6 ULA destinations are
// refused before the request is issued so a hostile RP cannot
// register backchannel_logout_uri = "http://127.0.0.1/..." or
// "http://169.254.169.254/..." and have the OP POST a signed
// logout_token at an internal service. Embedders fronting their RPs
// with private DNS opt out of the gate by setting AllowPrivateNetwork;
// dev / CI setups that only need a loopback stub set the narrower
// AllowLoopbackNetwork instead.
type HTTPDeliverer struct {
	// Client is the underlying [*http.Client]. A nil Client falls
	// back to a package-default with the timeout below; embedders
	// that already maintain a shared http.Client (e.g. with
	// instrumentation) inject it here.
	Client *http.Client

	// Timeout is the per-request budget. A zero value applies
	// [DefaultTimeout].
	Timeout time.Duration

	// AllowPrivateNetwork, when true, suppresses the SSRF deny-list
	// the deliverer applies to RP-controlled URIs. The default false
	// rejects loopback / link-local / RFC 1918 hosts so an
	// attacker-controlled backchannel_logout_uri cannot pivot the OP
	// onto an internal service. Embedders fronting their RPs with
	// private DNS opt in via op.WithBackchannelAllowPrivateNetwork.
	AllowPrivateNetwork bool

	// AllowLoopbackNetwork is the narrow counterpart of
	// AllowPrivateNetwork: it admits loopback destinations
	// (127.0.0.0/8, ::1, and the textual loopback names, the latter
	// only when they resolve to a loopback address) and leaves every
	// other deny-listed range — link-local, RFC 1918, IPv6 ULA, cloud
	// metadata — refused. op.WithAllowInsecureBackchannelLogoutForDev
	// sets this flag rather than AllowPrivateNetwork so the dev opt-in
	// delivers exactly the destination set its godoc promises.
	AllowLoopbackNetwork bool

	// Resolver overrides the DNS resolver consulted when the deny-list
	// is engaged. The default nil value falls back to [net.DefaultResolver];
	// tests inject a stub so the SSRF guard can be exercised without a
	// real DNS round-trip.
	Resolver *net.Resolver

	// fetchOnce / fetchClient wire the lazy [*securefetch.Client]
	// construction so callers may flip [AllowPrivateNetwork] (or
	// inject a stub [Resolver]) after [NewHTTPDeliverer] returned but
	// before the first Deliver. The captured policy is fixed at the
	// moment of first use; mutations after that point are ignored.
	fetchOnce   sync.Once
	fetchClient *securefetch.Client
}

// NewHTTPDeliverer returns an [HTTPDeliverer] with the supplied
// timeout. Passing zero substitutes [DefaultTimeout]. The constructed
// value carries no pre-built [*securefetch.Client]: [Deliver] builds
// one lazily on first use so a caller that flips
// [HTTPDeliverer.AllowPrivateNetwork] (or wires a stub
// [HTTPDeliverer.Resolver]) after construction sees the change
// reflected in the dial-time deny-list. Callers may set
// [HTTPDeliverer.Client] to supply a custom outbound transport. Only its
// Transport is used: redirect handling, request timeout, and the dial-time
// deny-list always remain under this deliverer's policy.
//
// The dial-time hook in [netsec.NewHTTPClient] re-checks the
// kernel-resolved address against the same deny-list that fires at
// the URL gate so a DNS-rebinding peer cannot bypass [assertSafeURL]
// by handing out a public address at gate-time and a private one at
// dial-time.
func NewHTTPDeliverer(timeout time.Duration) *HTTPDeliverer {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &HTTPDeliverer{Timeout: timeout}
}

// resolveClient returns the [*securefetch.Client] [Deliver] should
// use. The helper accepts an embedder-supplied [HTTPDeliverer.Client]'s
// transport as its base, while always constructing the surrounding hardened
// envelope using the current [HTTPDeliverer.AllowPrivateNetwork] flag. A
// caller cannot weaken redirect, timeout, or dial-time policy by supplying a
// full client. [HTTPDeliverer.AllowLoopbackNetwork] travels with it, so the
// narrow opt-in reaches the dial-time hook as well as the URL gate.
func (d *HTTPDeliverer) resolveClient() *securefetch.Client {
	d.fetchOnce.Do(func() {
		policy := securefetch.Policy{
			AllowPrivateNetwork:  d.AllowPrivateNetwork,
			AllowLoopbackNetwork: d.AllowLoopbackNetwork,
			AllowedSchemes:       []string{"http", "https"},
			MaxBodyBytes:         maxResponseBytes,
			Timeout:              d.timeoutOrDefault(),
			Resolver:             d.Resolver,
		}
		if d.Client != nil {
			policy.BaseTransport = d.Client.Transport
		}
		d.fetchClient = securefetch.NewClient(policy)
	})
	return d.fetchClient
}

// Deliver implements [Deliverer]. The function returns a non-nil
// error on transport failure, a non-2xx status, or an unexpected
// 3xx (because the deliverer refuses to follow redirects). The body
// is drained to a small cap so the connection can be re-used.
//
// Before issuing the POST, Deliver runs an SSRF deny-list against
// the parsed Target.URL: loopback, link-local, RFC 1918 / ULA, and
// IPv6 unique-local addresses are rejected unless AllowPrivateNetwork
// is true (or, for the loopback block alone,
// AllowLoopbackNetwork). The check is per-call (not cached) so a client that
// rotates DNS at the last second cannot escape the gate by racing
// the resolver; the cost is one DNS round-trip per delivery, which
// is negligible against the network round-trip the POST itself
// requires.
func (d *HTTPDeliverer) Deliver(ctx context.Context, target Target, logoutToken string) error {
	if target.URL == "" {
		return errors.New("backchannel: empty Target.URL")
	}
	if err := d.assertSafeURL(ctx, target.URL); err != nil {
		return err
	}
	client := d.resolveClient()
	form := url.Values{"logout_token": {logoutToken}}
	req, err := client.NewRequest(ctx, http.MethodPost, target.URL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return classifyDeliverError(target.URL, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json, text/plain;q=0.5")

	if _, err := client.DoAndDiscard(req); err != nil { //nolint:bodyclose // securefetch.DoAndDiscard drains and closes the body internally.
		return classifyDeliverError(target.URL, err)
	}
	return nil
}

// ErrPrivateNetworkBlocked is the sentinel returned when Target.URL
// resolves to a deny-listed host (loopback / link-local / RFC 1918 /
// IPv6 ULA). Callers can check for it with errors.Is to record an
// audit event distinct from "RP returned 5xx"; the coordinator
// already routes any non-nil delivery error through the failure
// audit, so most callers do not branch on the sentinel.
var ErrPrivateNetworkBlocked = errors.New("backchannel: target resolves to a deny-listed network")

// assertSafeURL implements the SSRF deny-list. The function returns
// nil when the URL host resolves entirely to public addresses; any
// rejection (unparseable URL, scheme outside http/https, missing
// host, IP literal in a deny-listed range, hostname resolving to a
// deny-listed address, or a cloud-metadata IP) wraps
// [ErrPrivateNetworkBlocked] so callers can branch with [errors.Is].
//
// The check delegates to the shared [*securefetch.Client]; the same
// envelope backs the JAR JWKS fetcher and the sector_identifier_uri
// fetcher so the OP-side SSRF gates cannot drift apart. The
// dial-time check installed by [netsec.NewHTTPClient]
// re-runs the deny-list against the kernel-resolved address so a DNS
// rebinding peer cannot pivot between gate and dial.
//
// Cloud-metadata IPs (169.254.169.254 et al) remain rejected even
// when [HTTPDeliverer.AllowPrivateNetwork] is true, as does every
// non-loopback private range when only
// [HTTPDeliverer.AllowLoopbackNetwork] is set.
func (d *HTTPDeliverer) assertSafeURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("backchannel: parse Target.URL %q: %w", raw, err)
	}
	if err := d.resolveClient().AssertSafeURLParsed(ctx, u); err != nil {
		return classifyNetsecError(raw, err)
	}
	return nil
}

// timeoutOrDefault returns the effective per-request timeout the
// deliverer uses for both the SSRF gate and the HTTP round-trip.
func (d *HTTPDeliverer) timeoutOrDefault() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return DefaultTimeout
}

// classifyNetsecError maps a [netsec] sentinel onto the deliverer's
// existing taxonomy. Loopback / RFC 1918 / cloud-metadata rejections
// collapse onto [ErrPrivateNetworkBlocked] so callers can keep their
// existing [errors.Is] branch; everything else wraps under the
// "backchannel:" prefix the package has emitted historically.
func classifyNetsecError(raw string, err error) error {
	switch {
	case errors.Is(err, netsec.ErrPrivateNetworkBlocked),
		errors.Is(err, netsec.ErrCloudMetadataBlocked):
		return fmt.Errorf("%w: %w", ErrPrivateNetworkBlocked, err)
	case errors.Is(err, netsec.ErrSchemeNotAllowed):
		return fmt.Errorf("backchannel: Target.URL %q: %w", raw, err)
	case errors.Is(err, netsec.ErrMissingHost):
		return fmt.Errorf("backchannel: Target.URL %q is missing a host", raw)
	default:
		return fmt.Errorf("backchannel: %q: %w", raw, err)
	}
}

// classifyDeliverError maps an error from the
// [*securefetch.Client] (transport failure, status / size rejection,
// SSRF refusal at request-build time) onto the historical
// "backchannel: ..." surface plus the deny-list sentinel where
// applicable. The mapping preserves the [errors.Is] matrix the
// deliverer's tests pin.
func classifyDeliverError(rawURL string, err error) error {
	if errors.Is(err, netsec.ErrPrivateNetworkBlocked) ||
		errors.Is(err, netsec.ErrCloudMetadataBlocked) ||
		errors.Is(err, netsec.ErrSchemeNotAllowed) ||
		errors.Is(err, netsec.ErrMissingHost) {
		return classifyNetsecError(rawURL, err)
	}
	if errors.Is(err, securefetch.ErrUnexpectedStatus) {
		return fmt.Errorf("backchannel: %s: %w", rawURL, err)
	}
	return fmt.Errorf("backchannel: POST %s: %w", rawURL, err)
}

// DelivererFunc lets a plain function satisfy [Deliverer]. The
// helper is convenient for tests and for embedders that wrap an
// existing transport (queue dispatch, retry loop) without
// implementing the full struct.
type DelivererFunc func(ctx context.Context, target Target, logoutToken string) error

// Deliver implements [Deliverer].
func (f DelivererFunc) Deliver(ctx context.Context, target Target, logoutToken string) error {
	return f(ctx, target, logoutToken)
}
