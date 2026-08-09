//go:build example

// op.go — OP-side wiring for example 34-pairwise-saas.
//
// buildProvider seeds the pairwise salt and the shared end-user,
// registers the two tenant clients with subject_type=pairwise, and
// returns the configured Provider together with the in-memory store and
// the salt itself (the salt is exposed so the run banner can log its
// length, and so the test contract is observable end-to-end).

package main

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func buildProvider() (*op.Provider, *inmem.Store, []byte, error) {
	keys := devkeys.MustEphemeral("pairwise-saas-1")

	salt, err := newPairwiseSalt()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate pairwise salt: %w", err)
	}

	st := inmem.New()
	if err := seedUser(st); err != nil {
		return nil, nil, nil, fmt.Errorf("seed demo user: %w", err)
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// Both tenants sign the same end-user in through the
		// authorization-code flow; the pairwise generator then splits
		// that one internal identity into a per-sector "sub". The
		// password step is what produces the internal identity in the
		// first place.
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		}),
		op.WithPairwiseSubject(salt),
		op.WithStaticClients(
			op.ConfidentialClient{
				ID:           tenantAClientID,
				Secret:       tenantAClientSecret,
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: []string{tenantARedirectURI},
				Scopes:       []string{"openid", "profile"},
				SubjectType:  "pairwise",
			},
			op.ConfidentialClient{
				ID:           tenantBClientID,
				Secret:       tenantBClientSecret,
				AuthMethod:   op.AuthClientSecretBasic,
				RedirectURIs: []string{tenantBRedirectURI},
				Scopes:       []string{"openid", "profile"},
				SubjectType:  "pairwise",
			},
		),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("op.New: %w", err)
	}
	return provider, st, salt, nil
}

// seedUser plants the single internal identity both tenants resolve to.
// The probe derives its sub values from [internalUserID] directly, so
// the record matters at issuance time: it is the user a tenant's
// authorization request signs in as before the generator runs.
func seedUser(st *inmem.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: internalUserID,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}, demoUsername, hash)
	return nil
}

// newPairwiseSalt returns a 32-byte cryptographically random salt
// suitable for [op.WithPairwiseSubject]. Production embedders pull the
// salt from a KMS or secret manager so it survives across restarts;
// the demo regenerates it on every boot, which is why the printed sub
// values are not stable across runs.
func newPairwiseSalt() ([]byte, error) {
	salt := make([]byte, pairwiseSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}
