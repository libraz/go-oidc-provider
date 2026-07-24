package authorizeendpoint

import (
	"context"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/op/store"
)

// errJARMEncryptionFailed signals that the JARM JWT was signed but
// the JWE wrap failed against a client that registered
// authorization_encrypted_response_alg / _enc. The wire layer
// branches on this sentinel via [errors.Is] to refuse the legacy
// "?code=..." downgrade — the client demanded an encrypted response,
// so leaking the code in plaintext would be a worse outcome than
// signalling server_error.
var errJARMEncryptionFailed = errors.New("authorizeendpoint: jarm response encryption failed")

// maybeEncryptJARM wraps an already-signed JARM JWT in a JWE addressed
// to the client when the client registered
// authorization_encrypted_response_alg / _enc (FAPI 2.0 Message
// Signing §5.5; "JARM"). The function is a no-op only when the
// resolved client positively declares no authorization-response
// encryption metadata.
//
// A nil client or resolver is a hard error when encryption metadata
// cannot be ruled out. Any resolver error or [jose.EncryptNestedJWT] failure is
// returned to the caller wrapped as [errJARMEncryptionFailed]; the
// call sites in [jarmEmitSuccess] / [jarmEmitError] decide on the
// fail-closed wire response.
func maybeEncryptJARM(
	ctx context.Context,
	resolver *clientencjwks.Resolver,
	client *store.Client,
	signed string,
) (string, error) {
	if client == nil {
		return "", errors.Join(errJARMEncryptionFailed, errors.New("authorizeendpoint: JARM client metadata unavailable"))
	}
	if client.AuthorizationEncryptedResponseAlg == "" && client.AuthorizationEncryptedResponseEnc == "" {
		return signed, nil
	}
	if resolver == nil {
		return "", errors.Join(errJARMEncryptionFailed, errors.New("authorizeendpoint: JARM encryption resolver unavailable"))
	}
	recipient, err := resolver.ResolveRecipient(
		ctx,
		client,
		client.AuthorizationEncryptedResponseAlg,
		client.AuthorizationEncryptedResponseEnc,
	)
	if err != nil {
		return "", errors.Join(errJARMEncryptionFailed, err)
	}
	out, err := jose.EncryptNestedJWT(signed, recipient)
	if err != nil {
		return "", errors.Join(errJARMEncryptionFailed, err)
	}
	return out, nil
}

// lookupClientForJARM resolves the client metadata the JARM emit path
// needs to decide whether to encrypt. A signed-only response is safe
// only after a successful lookup proves that the client did not request
// encryption, so missing dependencies and lookup failures are surfaced.
func lookupClientForJARM(ctx context.Context, clients store.ClientStore, clientID string) (*store.Client, error) {
	if clients == nil {
		return nil, errors.New("authorizeendpoint: JARM client store unavailable")
	}
	if clientID == "" {
		return nil, errors.New("authorizeendpoint: JARM client id missing")
	}
	client, err := clients.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("authorizeendpoint: lookup JARM client: %w", err)
	}
	if client == nil {
		return nil, errors.New("authorizeendpoint: JARM client lookup returned nil")
	}
	return client, nil
}
