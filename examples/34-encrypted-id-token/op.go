//go:build example

// op.go — OP-side wiring for example 34-encrypted-id-token.
//
// buildProvider seeds the demo end-user, generates the OP's signing
// keyset, and registers the example RP as a confidential client whose
// metadata declares both `id_token_encrypted_response_alg=RSA-OAEP-256`
// and the inline JWKs document carrying the RP's public encryption
// key. The token endpoint resolves the RP's JWKs to wrap every issued
// id_token in a JWE addressed to the RP. This file also owns
// rsaPublicJWKSetJSON, the helper that marshals the RP key into the
// shape `store.Client.JWKs` expects.

package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func buildProvider(opEncPriv *rsa.PrivateKey, rpEncPub *rsa.PublicKey) (*op.Provider, error) {
	keys := devkeys.MustEphemeral("encrypted-id-token-1")

	rpJWKS, err := rsaPublicJWKSetJSON(rpEncPub, clientKID)
	if err != nil {
		return nil, fmt.Errorf("marshal RP JWKS: %w", err)
	}

	st := inmem.New()
	if err := seedUser(st); err != nil {
		return nil, err
	}

	// Register the RP with id_token_encrypted_response_alg /
	// id_token_encrypted_response_enc set. The typed builders
	// (PublicClient / ConfidentialClient) do not yet expose the JWE
	// metadata fields, so we project onto store.Client directly.
	secretHash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		return nil, fmt.Errorf("hash client secret: %w", err)
	}
	if err := st.RegisterClient(context.Background(), &store.Client{
		ID:                          clientID,
		RedirectURIs:                []string{redirectURI},
		Scopes:                      []string{"openid", "profile", "email"},
		GrantTypes:                  []string{"authorization_code"},
		ResponseTypes:               []string{"code"},
		TokenEndpointAuthMethod:     op.AuthClientSecretBasic.String(),
		SecretHash:                  secretHash,
		Source:                      store.ClientSourceStatic,
		JWKs:                        rpJWKS,
		IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc: "A256GCM",
	}); err != nil {
		return nil, fmt.Errorf("register client: %w", err)
	}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: st.UserPasswords()},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		// WithEncryptionKeyset publishes the OP's use=enc key on
		// /.well-known/jwks.json and wires the inbound JWE
		// decrypter. The same option also unlocks outbound JWE
		// emission: when a client registers
		// id_token_encrypted_response_alg / _enc, the token endpoint
		// wraps the signed id_token in a JWE addressed to the RP's
		// own use=enc key (resolved via the client metadata's JWKs).
		op.WithEncryptionKeyset(op.EncryptionKeyset{{
			KeyID:      opEncKID,
			PrivateKey: opEncPriv,
		}}),
	)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

func seedUser(st *inmem.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}, demoUsername, hash)
	return nil
}

// rsaPublicJWKSetJSON serialises pub as a one-key JSON Web Key Set
// suitable for store.Client.JWKs. The library's encryption recipient
// resolver picks a key with use=enc whose alg matches the client's
// IDTokenEncryptedResponseAlg.
func rsaPublicJWKSetJSON(pub *rsa.PublicKey, kid string) ([]byte, error) {
	jwk := josev4.JSONWebKey{
		Key:       pub,
		KeyID:     kid,
		Use:       "enc",
		Algorithm: "RSA-OAEP-256",
	}
	return json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{jwk}})
}
