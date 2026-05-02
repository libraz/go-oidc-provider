package op_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// exampleKeyset returns a fresh ECDSA P-256 [op.Keyset] suitable for
// the runnable Example* functions. Real deployments load signing keys
// from a vault / KMS rather than generating them at boot; the helper
// is intentionally a thin wrapper so the Examples stay focused on the
// option surface they document.
func exampleKeyset() op.Keyset {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("example: generate signing key: %v", err)
	}
	return op.Keyset{{KeyID: "example-1", Signer: priv}}
}

// exampleCookieKey returns a deterministic 32-byte AES-256-GCM key the
// runnable Examples pass to [op.WithCookieKeys]. Production embedders
// pull the key from the same secret backend as the signing keyset; the
// example uses a fixed value so the doc output stays stable across
// godoc regenerations.
func exampleCookieKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// ExampleNew_minimal builds the smallest possible [*op.Provider]: an
// issuer URL, an in-memory store, a single ECDSA P-256 signing key, a
// cookie key, and the default authorization_code + refresh_token grant
// pair. The result is an [http.Handler] the embedder mounts in their
// own router.
func ExampleNew_minimal() {
	provider, err := op.New(
		op.WithIssuer("https://idp.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(exampleKeyset()),
		op.WithCookieKeys(exampleCookieKey()),
		op.WithGrants(grant.AuthorizationCode, grant.RefreshToken),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = provider
}

// ExampleNew_fapi2 layers [op.WithProfile] on top of the minimal
// provider so FAPI 2.0 Baseline auto-enables PAR / JAR. The disjunctive
// sender-constrained-token requirement (DPoP or mTLS) still has to be
// supplied explicitly; this example picks DPoP.
func ExampleNew_fapi2() {
	provider, err := op.New(
		op.WithIssuer("https://idp.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(exampleKeyset()),
		op.WithCookieKeys(exampleCookieKey()),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = provider
}

// ExampleNew_jsonDriver swaps the default HTML driver for
// [interaction.JSONDriver] so a SPA can drive the login / consent /
// chooser ceremonies through JSON envelopes. Embedders that ship a
// server-rendered UI keep the default driver and supply consent /
// chooser templates through [op.WithConsentUI] / [op.WithChooserUI].
func ExampleNew_jsonDriver() {
	provider, err := op.New(
		op.WithIssuer("https://idp.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(exampleKeyset()),
		op.WithCookieKeys(exampleCookieKey()),
		op.WithInteractionDriver(interaction.JSONDriver{}),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = provider
}
