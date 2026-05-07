//go:build example

// op.go — OP-side wiring for example 32-ciba-pos.
//
// buildProvider enables [op.WithCIBA] in poll mode, registers a
// [op.HintResolver] that maps the demo login_hint to a stable
// subject, and statically registers the POS terminal as a CIBA-only
// confidential client. The substore returned alongside the provider
// is also returned so the device-side approve simulation can flip a
// pending CIBA request directly.

package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func buildProvider() (http.Handler, *inmem.Store, error) {
	keys := devkeys.MustEphemeral("ciba-poll-1")

	st := inmem.New()

	resolver := op.HintResolverFunc(func(_ context.Context, _ op.HintKind, value string) (string, error) {
		if value == loginHint {
			return demoSubject, nil
		}
		return "", op.ErrUnknownCIBAUser
	})

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithCIBA(
			op.WithCIBAHintResolver(resolver),
			op.WithCIBAPollInterval(pollInterval),
		),
		op.WithStaticClients(op.ConfidentialClient{
			ID:         clientID,
			Secret:     clientSecret,
			AuthMethod: op.AuthClientSecretBasic,
			// CIBA clients never visit /authorize; RedirectURIs may be
			// empty. The grant set is overridden so the registration
			// only carries the CIBA URN — embedders that also need
			// authorization_code add it back here.
			GrantTypes: []string{cibaGrantURN},
			Scopes:     []string{"openid", "profile"},
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("op.New: %w", err)
	}
	return provider, st, nil
}
