//go:build example

// op.go — OP-side wiring for example 33-token-exchange-delegation.
//
// buildProvider registers the three static clients (frontend,
// service-a, service-b), wires the testkit subject authenticator and
// auto-consent driver so the auth-code flow is programmatically
// driveable, and gates token-exchange behind a [downscopePolicy] that
// caps the granted TTL. The compile-time `var _` assignment at the
// bottom of the file confirms the policy still satisfies
// [op.TokenExchangePolicy] after every refactor.

package main

import (
	"context"
	"time"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// buildProvider assembles the OP option list. The token-exchange
// policy admits every exchange between the two demo clients; a
// production embedder reads tenant / risk context off [req] before
// returning nil. The ephemeral keys are regenerated on every call so
// the probe and the public listener cannot share signing material.
func buildProvider(issuer string) (*op.Provider, error) {
	keys := devkeys.MustEphemeral("token-exchange-1")
	st := inmem.New()

	provider, err := op.New(
		// Issuer is whatever the listener actually serves. The probe
		// uses httptest's ephemeral URL; the public listener uses the
		// fixed :8090 binding the package banner advertises.
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// SubjectAuthenticator + AutoConsentDriver let the example
		// drive the auth-code flow programmatically: the helper POSTs
		// the desired subject onto /interaction; the consent screen
		// auto-approves every requested scope.
		op.WithAuthenticators(testkit.SubjectAuthenticator{}),
		op.WithInteractionDriver(testkit.AutoConsentDriver{}),
		op.WithStaticClients(
			op.ConfidentialClient{
				// frontend uses authorization_code + PKCE to obtain
				// the user's access_token for service-a's audience.
				// Real deployments could substitute a public SPA
				// client; the example pins confidential so the
				// auth-code flow has a fixed secret to bind.
				ID:           frontendID,
				Secret:       frontendSecret,
				AuthMethod:   op.AuthClientSecretPost,
				RedirectURIs: []string{rpRedirectURI},
				GrantTypes:   []string{"authorization_code"},
				Scopes:       []string{"openid", "api:read", "api:write"},
				Resources:    []string{serviceAResource},
			},
			op.ConfidentialClient{
				// service-a is the exchanger. It authenticates via
				// client_secret_post when calling /token under the
				// token-exchange grant. Resources lists both
				// audiences so the OP's allowlist accepts the
				// downscoped audience=service-b on the exchange.
				ID:           serviceAID,
				Secret:       serviceASecret,
				AuthMethod:   op.AuthClientSecretPost,
				RedirectURIs: []string{rpRedirectURI},
				GrantTypes:   []string{tokenExchangeGrantType},
				Scopes:       []string{"openid", "api:read", "api:write"},
				Resources:    []string{serviceAResource, serviceBResource},
			},
			op.ConfidentialClient{
				// service-b only needs to exist as a registered
				// resource owner; the OP looks up audience names
				// against the union of registered Resources. The
				// client itself never visits /token in this example.
				ID:           serviceBID,
				Secret:       "tx-svc-b-secret-rotate-me",
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: []string{rpRedirectURI},
				GrantTypes:   []string{"authorization_code"},
				Scopes:       []string{"api:read", "api:write"},
				Resources:    []string{serviceBResource},
			},
		),
		// The example's downscope policy: every exchange between
		// service-a and service-b is admitted with the OP-computed
		// defaults; the dispatcher caps the TTL at the global
		// access-token ceiling (1 h by default), and we narrow further
		// here to keep the chain short-lived.
		op.RegisterTokenExchange(downscopePolicy{
			maxTTL: tokenExchangeMaxLifetime,
		}),
		// Register the public scopes service-b serves so the auth-code
		// flow can request them. The default catalogue covers
		// openid / profile / email; api:* is example-specific.
		op.WithScope(op.PublicScope("api:read", "Read api resources on your behalf")),
		op.WithScope(op.PublicScope("api:write", "Write api resources on your behalf")),
	)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// downscopePolicy is the example's [op.TokenExchangePolicy]. The
// policy admits every exchange between the two demo clients and
// returns a [op.TokenExchangeDecision] capping the granted TTL at
// maxTTL — the OP would otherwise fall back to the global access-
// token ceiling, which is intentionally too long for short-lived
// service-mesh delegation.
type downscopePolicy struct {
	maxTTL time.Duration
}

func (p downscopePolicy) Allow(_ context.Context, _ op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	// A nil decision means "use the OP-computed defaults"; a non-nil
	// decision narrows them. The example narrows TTL only — scope
	// and audience are left to the OP's structural intersection
	// against the subject_token's values.
	return &op.TokenExchangeDecision{GrantedTTL: p.maxTTL}, nil //nolint:exhaustruct // optional fields default to "no override"
}

// Compile-time confirmation that the example's policy satisfies the
// public seam. The variable is unused at runtime — the assignment is
// purely for linker-time verification.
var _ op.TokenExchangePolicy = downscopePolicy{}
