package securefetch_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/netsec"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
)

// redirectingRoundTripper is an in-process transport, not an
// [*http.Transport], that answers every request with a 302 to location.
type redirectingRoundTripper struct {
	location string
	hits     atomic.Int32
}

func (r *redirectingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.hits.Add(1)
	return &http.Response{
		StatusCode: http.StatusFound,
		Header:     http.Header{"Location": []string{r.location}},
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

// publicLookup resolves every name to a public address so the URL-time
// gate admits the first hop.
func publicLookup(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
}

func permissiveRedirect(*http.Request, []*http.Request) error { return nil }

// TestClient_PermissiveCheckRedirectCannotAdmitPrivateTarget pins that
// a Policy.CheckRedirect returning nil does not displace the envelope's
// redirect gate: a redirect to a loopback or private address through a
// non-*http.Transport round-tripper is refused and never delegated.
func TestClient_PermissiveCheckRedirectCannotAdmitPrivateTarget(t *testing.T) {
	t.Parallel()

	for _, target := range []string{"http://127.0.0.1/admin", "http://10.0.0.1/admin"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rt := &redirectingRoundTripper{location: target}
			c := securefetch.NewClient(securefetch.Policy{
				MaxRedirects:  3,
				BaseTransport: rt,
				LookupHook:    publicLookup,
				CheckRedirect: permissiveRedirect,
			})
			_, _, err := c.Get(context.Background(), "https://rp.example/jwks") //nolint:bodyclose // securefetch.Get drains and closes the body internally.
			if !errors.Is(err, netsec.ErrRedirectBlocked) || !errors.Is(err, netsec.ErrPrivateNetworkBlocked) {
				t.Fatalf("err=%v want ErrRedirectBlocked wrapping ErrPrivateNetworkBlocked", err)
			}
			if n := rt.hits.Load(); n != 1 {
				t.Fatalf("round-trips=%d want 1 (the redirect target must not be requested)", n)
			}
		})
	}
}

// TestClient_PermissiveCheckRedirectKeepsMaxRedirects pins that the
// redirect budget holds while a caller hook admits every redirect.
func TestClient_PermissiveCheckRedirectKeepsMaxRedirects(t *testing.T) {
	t.Parallel()

	rt := &redirectingRoundTripper{location: "https://rp.example/jwks"}
	c := securefetch.NewClient(securefetch.Policy{
		MaxRedirects:  2,
		BaseTransport: rt,
		LookupHook:    publicLookup,
		CheckRedirect: permissiveRedirect,
	})
	_, _, err := c.Get(context.Background(), "https://rp.example/jwks") //nolint:bodyclose // securefetch.Get drains and closes the body internally.
	if !errors.Is(err, netsec.ErrRedirectBlocked) {
		t.Fatalf("err=%v want ErrRedirectBlocked", err)
	}
	if n := rt.hits.Load(); n != 3 {
		t.Fatalf("round-trips=%d want 3 (first request plus MaxRedirects=2)", n)
	}
}

// TestClient_CheckRedirectSharpensRefusal confirms a caller hook still
// surfaces its own error when the envelope refuses redirects outright,
// which is how a caller distinguishes a refused redirect from a 3xx.
func TestClient_CheckRedirectSharpensRefusal(t *testing.T) {
	t.Parallel()

	errRefused := errors.New("redirect refused")
	rt := &redirectingRoundTripper{location: "https://rp.example/elsewhere"}
	c := securefetch.NewClient(securefetch.Policy{
		BaseTransport: rt,
		LookupHook:    publicLookup,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRefused },
	})
	_, _, err := c.Get(context.Background(), "https://rp.example/jwks") //nolint:bodyclose // securefetch.Get drains and closes the body internally.
	if !errors.Is(err, errRefused) {
		t.Fatalf("err=%v want the caller's refusal", err)
	}
	if n := rt.hits.Load(); n != 1 {
		t.Fatalf("round-trips=%d want 1", n)
	}
}
