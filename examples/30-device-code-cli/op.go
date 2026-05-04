//go:build example

// op.go — OP-side wiring for example 30-device-code-cli.
//
// buildProvider seeds the demo end-user, enables
// [op.WithDeviceCodeGrant], and registers the public CLI client.
// Both the self-verify probe and the user-facing CLI flow call this
// same helper, so any wiring change surfaces in both phases.

package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// buildProvider constructs a fresh [op.Provider] + paired
// [inmem.Store] for one example run. Both the self-verify probe
// and the CLI flow call this helper so they exercise an identical
// configuration path; the only difference between the two phases
// is the listener that sits in front of the handler.
func buildProvider() (http.Handler, *inmem.Store, error) {
	keys := devkeys.MustEphemeral("device-code-1")
	st := inmem.New()
	// Seed the user record so the access token's sub/profile claims
	// resolve cleanly. The simulated browser approval calls
	// DeviceCodeStore.Approve with this subject directly.
	st.PutUser(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Alice",
			"email": "alice@example.com",
		},
	})
	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithDeviceCodeGrant(),
		op.WithStaticClients(op.PublicClient{
			ID: clientID,
			// Device-code clients never visit /authorize so
			// RedirectURIs may stay empty. The grant set is
			// overridden so the registration only carries the
			// device_code URN — embedders that also need
			// authorization_code add it back here.
			GrantTypes: []string{deviceCodeGrantURN},
			Scopes:     []string{"openid", "profile", "offline_access"},
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("op.New: %w", err)
	}
	return provider, st, nil
}
