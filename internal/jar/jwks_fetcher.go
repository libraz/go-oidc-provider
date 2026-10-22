package jar

import (
	"fmt"
	"net"

	"github.com/libraz/go-oidc-provider/internal/netsec"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

// Fetcher fetches a JWKs document from a remote URL. It binds the shared
// relying-party JWKS fetcher (internal/rpjwks) to this package's error
// taxonomy: caching, singleflight collapsing, the SSRF deny-list, the body and
// member caps, conditional revalidation, negative caching, and the
// forced-refresh throttle all live there, so the request-object path cannot
// drift from the token endpoint's or the encryption path's posture.
//
// It is the production resolver behind [Verifier] AND the JWKS source for
// client-assertion verification in internal/clientauth when a client
// registers a jwks_uri.
type Fetcher struct {
	*rpjwks.Fetcher
}

// NewFetcher returns a fetcher with the project defaults applied. The supplied
// clock drives the caches; pass [timex.SystemClock] (or nil — the cache
// normalises) when the OP is not under test.
func NewFetcher(clock timex.Clock) *Fetcher {
	return &Fetcher{Fetcher: rpjwks.New(rpjwks.Config{
		Clock:      clock,
		FetchError: ErrJWKSFetch,
	})}
}

// IsLocalHostname reports whether host is a literal "localhost" string or one
// of its common variants. Forwards to [netsec.IsLocalHostname] so the
// deny-list is centralised; retained as a [jar] export because existing call
// sites (authorizeendpoint, sector, backchannel) reach the helper through this
// package.
func IsLocalHostname(host string) bool {
	return netsec.IsLocalHostname(host)
}

// IsPrivateIP reports whether ip falls inside one of the deny-listed ranges.
// Forwards to [netsec.IsPrivateIP]; retained for the same reason as
// [IsLocalHostname].
func IsPrivateIP(ip net.IP) bool {
	return netsec.IsPrivateIP(ip)
}

// classifyKeyResolution marks a server-side key-source fault with
// [ErrKeySourceUnavailable], keeping the cause; any other failure is
// returned unchanged.
func classifyKeyResolution(err error) error {
	if rpjwks.IsKeySourceUnavailable(err) {
		return fmt.Errorf("%w: %w", ErrKeySourceUnavailable, err)
	}
	return err
}
