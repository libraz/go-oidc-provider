package jar_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

// TestFetcher_JWKSURISchemeIsConstrainedToTheNetwork pins that a
// client-supplied jwks_uri can only ever name something fetched over
// the network.
//
// A JWKS URI is a client's declaration of where its public keys live,
// and the OP dereferences it to decide whether that client's signature
// is genuine. Handing an unrestricted URL to a fetcher makes the scheme
// itself part of the attack surface: "file" reads the OP's own disk,
// "data" carries a payload inline, and each turns key resolution into
// something the client fully controls. The consequence is worse than
// disclosure — whoever decides what bytes come back decides which
// public key the OP will trust, and therefore who it will authenticate.
//
// Tracks: CVE-2026-48522 (PyJWT) — PyJWKClient passed the JWKS URI
// straight to the URL opener with no scheme restriction, so file://,
// ftp:// and data: URIs were dereferenced; the published
// proof-of-concept forged tokens by planting a JWK Set at a path the
// URI named.
func TestFetcher_JWKSURISchemeIsConstrainedToTheNetwork(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		uri  string
	}{
		{"file scheme reaching the OP's own disk", "file:///etc/passwd"},
		{"file scheme with an empty authority", "file://localhost/etc/passwd"},
		{"data scheme carrying an inline keyset", `data:application/json,{"keys":[]}`},
		{"ftp scheme", "ftp://rp.test.invalid/jwks.json"},
		{"gopher scheme", "gopher://rp.test.invalid/1jwks.json"},
		{"no scheme at all", "rp.test.invalid/jwks.json"},
		{"empty", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := jar.NewFetcher(timex.SystemClock)
			// Grant the private-network opt-in so the refusal below is
			// unambiguously about the scheme. A test that left the
			// deny-list engaged could not tell the two apart for a
			// loopback-shaped URI.
			f.SetAllowPrivate(true)

			if _, err := f.Fetch(context.Background(), tc.uri); err == nil {
				t.Fatalf("Fetch(%q) succeeded; the OP dereferenced a non-network URI a client supplied", tc.uri)
			} else if !errors.Is(err, jar.ErrJWKSFetch) {
				t.Errorf("Fetch(%q) err=%v, want ErrJWKSFetch", tc.uri, err)
			}

			// FetchFresh is the rotation-recovery path and reaches the
			// transport through the same client, but it is a separate
			// entry point — a gate installed on only one of them would
			// leave the other open.
			if _, err := f.FetchFresh(context.Background(), tc.uri); err == nil {
				t.Fatalf("FetchFresh(%q) succeeded; the forced-refresh path does not apply the scheme gate", tc.uri)
			}
		})
	}
}
