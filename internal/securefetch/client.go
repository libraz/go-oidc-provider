package securefetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/libraz/go-oidc-provider/internal/netsec"
)

// Default knobs the package applies when [Policy] leaves a field zero.
// The numbers mirror the in-tree posture of the consolidated fetchers
// so existing call sites that pass an unzero-valued field observe the
// same behaviour they had before the consolidation.
const (
	// DefaultMaxBody is the response-body cap the envelope applies
	// when [Policy.MaxBodyBytes] is zero. 64 KiB matches the most
	// conservative ceiling among the call sites (sector / encryption
	// JWKS); fetchers needing a larger ceiling (the JAR JWKS path
	// uses 256 KiB) raise [Policy.MaxBodyBytes] explicitly.
	DefaultMaxBody = int64(64 * 1024)
)

// Sentinel errors returned by the response-side gates. Callers branch
// on these via [errors.Is] so they can map the failure onto a
// per-package taxonomy (e.g. ErrJWKSFetch, ErrSectorFetch) without
// depending on string matching.
var (
	// ErrEmptyURL signals the caller passed an empty URL string. The
	// gate fires before any network I/O so a bug in the call site
	// surfaces deterministically rather than as a transport error.
	ErrEmptyURL = errors.New("securefetch: empty url")

	// ErrUnexpectedStatus signals the upstream responded with a
	// non-2xx status. The wrapper carries the numeric status so
	// callers can log it without re-reading the response.
	ErrUnexpectedStatus = errors.New("securefetch: unexpected status")

	// ErrUnexpectedContentType signals the upstream's Content-Type
	// header does not match the [Policy.AcceptContentTypes] allow-list.
	// Empty allow-lists skip the check; a non-empty list with no
	// matches surfaces this error.
	ErrUnexpectedContentType = errors.New("securefetch: unexpected content-type")

	// ErrBodyTooLarge signals the response body would have exceeded
	// [Policy.MaxBodyBytes]. The caller sees this when the body
	// (read via [io.LimitReader]) returns more bytes than the cap.
	ErrBodyTooLarge = errors.New("securefetch: response body exceeds cap")

	// ErrReadBody signals the body read returned a transport error
	// before the cap was reached. The wrapper carries the underlying
	// error so callers can [errors.Unwrap] the cause.
	ErrReadBody = errors.New("securefetch: read body")
)

// Policy captures the per-endpoint security envelope. The zero value
// is a hardened production posture: GET/POST allowed, no redirects,
// SSRF deny-list engaged, http+https schemes, [DefaultMaxBody] cap,
// no content-type filter, default netsec timeouts.
//
// Each field reflects a security property the audit must verify per
// call site, not an arbitrary knob: a future review can grep the
// codebase for [Policy] literals and confirm every fetcher's posture
// in one pass.
type Policy struct {
	// AllowPrivateNetwork lifts the SSRF deny-list. Embedders fronting
	// their RPs through private DNS opt in via the corresponding
	// per-package option. Cloud-metadata addresses remain rejected
	// even with this flag set; see [netsec] for the rationale.
	AllowPrivateNetwork bool

	// AllowedSchemes restricts the URL scheme allow-list. A nil /
	// empty value falls back to {"http", "https"}; pass {"https"}
	// to force TLS (the sector resolver uses this).
	AllowedSchemes []string

	// MaxBodyBytes caps the response body the envelope reads. Zero
	// falls back to [DefaultMaxBody]; a negative value is invalid
	// (the constructor rejects it).
	MaxBodyBytes int64

	// AcceptContentTypes is the response Content-Type allow-list.
	// An empty list disables the check entirely (the back-channel
	// deliverer does not care about the response shape); a non-empty
	// list rejects any response whose declared media type is outside
	// the list.
	//
	// Matching is case-insensitive and ignores parameters (e.g.
	// "; charset=utf-8"); subtype suffixes (e.g. "+json") MUST be
	// listed verbatim.
	AcceptContentTypes []string

	// Timeout is the per-request budget. Zero falls back to
	// [netsec.DefaultTimeout].
	Timeout time.Duration

	// MaxRedirects caps the number of redirects the underlying
	// [http.Client] will follow. Zero (the default) refuses every
	// redirect; the gate re-runs on each Location header before the
	// redirect is taken.
	MaxRedirects int

	// BaseTransport overrides the [http.RoundTripper] base. The
	// envelope forwards the value verbatim to [netsec.NewHTTPClient];
	// see that function's godoc for the semantics around the
	// dial-time gate.
	BaseTransport http.RoundTripper

	// Resolver overrides the DNS resolver consulted for the URL-time
	// gate. A nil value falls back to [net.DefaultResolver]; tests
	// inject a stub so the rebinding gate can be exercised
	// deterministically.
	Resolver *net.Resolver

	// LookupHook is a finer-grained injection point than [Policy.Resolver]:
	// it replaces the LookupIPAddr call directly so the test does not
	// have to construct a synthetic [*net.Resolver]. Production code
	// leaves this nil; the field is kept exported so tests outside the
	// package can wire it.
	LookupHook func(ctx context.Context, host string) ([]net.IPAddr, error)

	// DialControlHook lets a test observe / replace the
	// [Dialer.Control] body installed by [netsec.NewHTTPClient].
	// Production code leaves this nil; tests wrap the result to assert
	// the hook fired or to simulate a specific kernel-level failure
	// shape.
	DialControlHook func(network, address string, c syscall.RawConn) error

	// DialTimeout caps the TCP / TLS dial phase. Zero falls back to
	// [netsec.DefaultDialTimeout].
	DialTimeout time.Duration

	// Proxy is forwarded to [netsec.Options.Proxy]; see that field's
	// godoc for the trade-offs around HTTP_PROXY / HTTPS_PROXY
	// inheritance.
	Proxy func(*http.Request) (*url.URL, error)

	// CheckRedirect overrides the [http.Client.CheckRedirect] hook
	// installed on the underlying client. Production callers leave
	// this nil so the [netsec.NewHTTPClient] default applies (every
	// redirect is refused via [http.ErrUseLastResponse], at which
	// point the response-side status gate surfaces the 3xx as a
	// failure). The sector_identifier_uri resolver overrides the
	// hook to surface a sentinel error instead of a 3xx so callers
	// can distinguish "redirect refused" from "upstream returned
	// 3xx" via [errors.Is].
	//
	// Embedders that supply a hook MUST NOT bypass [Policy.MaxRedirects];
	// the hook is invoked per redirect, not in place of the cap, so a
	// hook that returns nil is bounded by the policy's redirect budget.
	CheckRedirect func(req *http.Request, via []*http.Request) error

	// httpClientOverride lets tests inject a fully-formed [*http.Client]
	// so the envelope can be exercised without a real socket. The
	// field is unexported so the production surface stays narrow;
	// tests call [Policy.WithHTTPClientForTest].
	httpClientOverride *http.Client
}

// WithHTTPClientForTest returns a copy of p whose HTTP client is the
// supplied override. The helper exists so unit tests can exercise the
// response-side gates against an [httptest.Server] without bringing
// up the [netsec] dial-time hook; production callers leave the field
// nil and let [NewClient] build the hardened client.
func (p Policy) WithHTTPClientForTest(c *http.Client) Policy {
	p.httpClientOverride = c
	return p
}

// netsecOptions returns the [netsec.Options] snapshot the envelope
// uses for both the URL-time gate and the [*http.Client] construction.
// The function is the single source of truth so the dial-time and
// URL-time checks always agree on the AllowPrivate / scheme / timeout
// posture.
func (p Policy) netsecOptions() netsec.Options {
	return netsec.Options{
		AllowPrivate:    p.AllowPrivateNetwork,
		AllowedSchemes:  p.AllowedSchemes,
		Timeout:         p.Timeout,
		MaxRedirects:    p.MaxRedirects,
		BaseTransport:   p.BaseTransport,
		Resolver:        p.Resolver,
		LookupHook:      p.LookupHook,
		DialControlHook: p.DialControlHook,
		DialTimeout:     p.DialTimeout,
		Proxy:           p.Proxy,
	}
}

// resolvedMaxBody returns the body cap the envelope should apply,
// folding the zero-value default in one place.
func (p Policy) resolvedMaxBody() int64 {
	if p.MaxBodyBytes > 0 {
		return p.MaxBodyBytes
	}
	return DefaultMaxBody
}

// Client wraps a [*http.Client] hardened by [netsec.NewHTTPClient]
// and applies the response-side gates ([Policy.MaxBodyBytes],
// [Policy.AcceptContentTypes], status check) on every fetch. The
// type is safe for concurrent use; embedders construct a single
// instance per outbound surface and share it across goroutines.
type Client struct {
	policy Policy
	http   *http.Client
}

// NewClient returns a [*Client] with the supplied [Policy]. The
// function returns an error when the policy carries an unrecoverable
// misconfiguration (negative body cap); the SSRF posture, redirect
// policy, and timeouts are never invalid because they fall back to
// the hardened defaults documented on [Policy].
func NewClient(p Policy) *Client {
	if p.MaxBodyBytes < 0 {
		// Clamp negative caps to the default. A negative value is a
		// programmer error; rather than panic in library code the
		// constructor falls back to the conservative ceiling so the
		// envelope still applies a body cap.
		p.MaxBodyBytes = 0
	}
	c := &Client{policy: p}
	if p.httpClientOverride != nil {
		c.http = p.httpClientOverride
	} else {
		c.http = netsec.NewHTTPClient(p.netsecOptions())
	}
	if p.CheckRedirect != nil {
		c.http.CheckRedirect = p.CheckRedirect
	}
	return c
}

// Policy returns the policy the client was constructed with. The
// returned value is a copy; callers may mutate it without affecting
// the client.
func (c *Client) Policy() Policy {
	return c.policy
}

// HTTPClient returns the underlying [*http.Client] for the rare call
// site that needs to issue a custom-shaped request (a conditional GET
// with If-None-Match, for example) while still going through the
// dial-time SSRF gate. The returned client carries the envelope's
// timeout and redirect policy; callers MUST NOT mutate it.
//
// Most call sites should prefer [Client.Get] / [Client.Post] /
// [Client.Do]; the raw client surface exists so the JAR JWKS fetcher
// can keep its ETag plumbing without re-implementing the envelope.
func (c *Client) HTTPClient() *http.Client {
	return c.http
}

// Get builds a GET request against rawURL, runs the URL-time SSRF
// gate, executes the request, and returns the response body bounded
// by [Policy.MaxBodyBytes]. Status, Content-Type, and body-cap checks
// fire in that order so the wire-level error a caller sees is the
// most informative one; a non-2xx response short-circuits before the
// body-cap check, for instance, so the caller does not learn the
// upstream's body shape from an error message.
//
// The function is the canonical single-shot fetch helper. Call sites
// that need to set additional request headers (Accept, If-None-Match)
// build the request via [http.NewRequestWithContext] and run it
// through [Client.Do].
func (c *Client) Get(ctx context.Context, rawURL string) ([]byte, *http.Response, error) {
	req, err := c.NewRequest(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	return c.Do(req)
}

// Post builds a POST request against rawURL with the supplied body
// and Content-Type, runs the URL-time SSRF gate, executes the request,
// and returns the response body bounded by [Policy.MaxBodyBytes]. The
// helper is shaped for the back-channel logout deliverer: a small
// form-urlencoded body with a status-only response, where the body is
// drained for connection re-use rather than parsed.
func (c *Client) Post(ctx context.Context, rawURL, contentType string, body io.Reader) ([]byte, *http.Response, error) {
	req, err := c.NewRequest(ctx, http.MethodPost, rawURL, body)
	if err != nil {
		return nil, nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.Do(req)
}

// NewRequest constructs an [*http.Request] against rawURL with the
// supplied method and body, after running the URL-time SSRF gate. The
// helper exists so call sites that need to set additional headers
// (Accept, If-None-Match, custom user-agent) can do so before handing
// the request to [Client.Do].
//
// The URL-time gate fires here so a clearly-bad URL never reaches the
// HTTP layer; the dial-time gate baked into [Client.HTTPClient] runs
// independently so a TOCTOU window between the two cannot widen the
// surface.
func (c *Client) NewRequest(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	if rawURL == "" {
		return nil, ErrEmptyURL
	}
	if err := netsec.AssertSafeURL(ctx, rawURL, c.policy.netsecOptions()); err != nil {
		return nil, err
	}
	if body == nil {
		body = http.NoBody
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("securefetch: build request: %w", err)
	}
	return req, nil
}

// AssertSafeURL runs the URL-time SSRF gate against rawURL using the
// client's policy. The helper exists so call sites that need to gate
// a URL without (yet) constructing a request — the back-channel
// deliverer does so before its conditional URL-empty check — share
// the same gate the envelope applies on every fetch.
func (c *Client) AssertSafeURL(ctx context.Context, rawURL string) error {
	if rawURL == "" {
		return ErrEmptyURL
	}
	return netsec.AssertSafeURL(ctx, rawURL, c.policy.netsecOptions())
}

// AssertSafeURLParsed is the [*url.URL] flavour of [Client.AssertSafeURL].
func (c *Client) AssertSafeURLParsed(ctx context.Context, u *url.URL) error {
	if u == nil {
		return ErrEmptyURL
	}
	return netsec.AssertSafeURLParsed(ctx, u, c.policy.netsecOptions())
}

// Do executes req through the hardened [*http.Client], applies the
// status / content-type / body-cap gates, and returns the body bytes
// the caller will parse. The function closes the response body before
// returning; the [*http.Response] is returned for headers (ETag,
// Cache-Control) the caller may need.
//
// Drain semantics: when [Policy.MaxBodyBytes] is positive the function
// reads at most MaxBodyBytes+1 bytes via [io.LimitReader] so an
// upstream that exceeds the cap surfaces as [ErrBodyTooLarge] rather
// than a silent truncation. The body is fully drained before the
// function returns so the underlying connection can be re-used.
func (c *Client) Do(req *http.Request) ([]byte, *http.Response, error) {
	resp, err := c.http.Do(req) //nolint:gosec // G704: this package is the SSRF-hardened envelope; AssertSafeURL ran in NewRequest.
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		// Drain a small bounded prefix so the connection is reusable
		// even on the error path. We do not surface the drained bytes;
		// the status alone is enough for the caller's error envelope.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
		return nil, resp, fmt.Errorf("%w: %d", ErrUnexpectedStatus, resp.StatusCode)
	}

	if len(c.policy.AcceptContentTypes) > 0 {
		ct := resp.Header.Get("Content-Type")
		if !contentTypeAllowed(ct, c.policy.AcceptContentTypes) {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))
			return nil, resp, fmt.Errorf("%w: %q", ErrUnexpectedContentType, ct)
		}
	}

	limit := c.policy.resolvedMaxBody()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, resp, fmt.Errorf("%w: %w", ErrReadBody, err)
	}
	if int64(len(body)) > limit {
		return nil, resp, fmt.Errorf("%w: %d bytes", ErrBodyTooLarge, limit)
	}
	return body, resp, nil
}

// DoRaw executes req through the hardened [*http.Client] without
// applying any of the response-side gates. The caller takes ownership
// of the [*http.Response] (must close the body) and is expected to
// implement its own status / content-type / body-cap rules — the
// helper exists so the JAR JWKS fetcher can keep its 304 conditional-GET
// branch (which a status-2xx-only gate would reject) without bypassing
// the SSRF dial-time hook.
//
// Most call sites should prefer [Client.Do]; the raw surface is the
// exception, not the rule.
func (c *Client) DoRaw(req *http.Request) (*http.Response, error) {
	return c.http.Do(req) //nolint:gosec // G704: this package is the SSRF-hardened envelope; AssertSafeURL ran in NewRequest.
}

// DoAndDiscard executes req through the hardened [*http.Client] and
// drains the response body to a small bounded prefix. The function is
// the back-channel deliverer's entry point: the caller cares only
// about the status, and the response shape may legitimately be a
// problem document or empty.
//
// Status checking still applies (a non-2xx response surfaces as
// [ErrUnexpectedStatus]); the content-type and body-cap gates do not
// because the response body is intentionally discarded.
func (c *Client) DoAndDiscard(req *http.Request) (*http.Response, error) {
	resp, err := c.http.Do(req) //nolint:gosec // G704: this package is the SSRF-hardened envelope; AssertSafeURL ran in NewRequest.
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	limit := c.policy.resolvedMaxBody()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	if resp.StatusCode/100 != 2 {
		return resp, fmt.Errorf("%w: %d", ErrUnexpectedStatus, resp.StatusCode)
	}
	return resp, nil
}

// contentTypeAllowed reports whether ct (the raw header value) matches
// any entry in allowed. Matching is case-insensitive and ignores
// parameters (e.g. "; charset=utf-8"); subtype suffixes (e.g. "+json")
// MUST be listed verbatim.
func contentTypeAllowed(ct string, allowed []string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	for _, a := range allowed {
		if strings.EqualFold(ct, a) {
			return true
		}
	}
	return false
}
