package backchannel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultTimeout is the per-RP request budget the [HTTPDeliverer]
// applies when the embedder does not supply one. The value matches
// the design 002 §H.2 guidance: long enough for a healthy RP to ack,
// short enough that a stalled RP does not hold the OP's logout flow
// open beyond the user's patience.
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

	// URL is the absolute endpoint registered via
	// [op/store.Client.BackchannelLogoutURI]. The library does not
	// re-validate the scheme here — the registration validator has
	// already enforced HTTPS in production deployments — so the
	// deliverer accepts whatever the store hands back.
	URL string
}

// HTTPDeliverer is the production [Deliverer]. It POSTs the logout
// token as application/x-www-form-urlencoded under the form field
// "logout_token", per OpenID Connect Back-Channel Logout 1.0 §2.5.
//
// The deliverer never follows redirects: the spec requires a direct
// POST to the registered URI, and a redirect is the easiest way an
// adversary upstream of the RP could trick the OP into sending a
// signed logout token to an unintended endpoint. The custom
// CheckRedirect returns http.ErrUseLastResponse so the response is
// surfaced verbatim and the coordinator records the unexpected 3xx
// as a delivery failure.
type HTTPDeliverer struct {
	// Client is the underlying [*http.Client]. A nil Client falls
	// back to a package-default with the timeout below; embedders
	// that already maintain a shared http.Client (e.g. with
	// instrumentation) inject it here.
	Client *http.Client

	// Timeout is the per-request budget. A zero value applies
	// [DefaultTimeout].
	Timeout time.Duration
}

// NewHTTPDeliverer returns an [HTTPDeliverer] with the default
// no-redirect transport and the supplied timeout. Passing zero
// substitutes [DefaultTimeout]. The constructor is the recommended
// entry point because it pre-wires the redirect guard; callers that
// want to inject a fully-custom client may set [HTTPDeliverer.Client]
// directly but MUST install the same redirect policy or accept the
// security trade-off.
func NewHTTPDeliverer(timeout time.Duration) *HTTPDeliverer {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &HTTPDeliverer{
		Client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Timeout: timeout,
	}
}

// Deliver implements [Deliverer]. The function returns a non-nil
// error on transport failure, a non-2xx status, or an unexpected
// 3xx (because the deliverer refuses to follow redirects). The body
// is drained to a small cap so the connection can be re-used.
func (d *HTTPDeliverer) Deliver(ctx context.Context, target Target, logoutToken string) error {
	if target.URL == "" {
		return errors.New("backchannel: empty Target.URL")
	}
	form := url.Values{"logout_token": {logoutToken}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("backchannel: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json, text/plain;q=0.5")

	client := d.Client
	if client == nil {
		client = defaultHTTPClient(d.Timeout)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("backchannel: POST %s: %w", target.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("backchannel: %s returned status %d", target.URL, resp.StatusCode)
	}
	return nil
}

// defaultHTTPClient mirrors [NewHTTPDeliverer]'s defaults so a
// caller that constructs an [HTTPDeliverer] zero value still
// benefits from the timeout / redirect guard.
func defaultHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
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
