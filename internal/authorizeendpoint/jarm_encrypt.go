package authorizeendpoint

import (
	"context"
	"errors"

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
// Signing §5.5; "JARM"). The function is a no-op (returns signed
// verbatim) when:
//
//   - the resolver is nil (the OP did not wire outbound encryption);
//   - the client is nil (the lookup the caller did failed and we have
//     no metadata to consult);
//   - the client did not register encryption metadata (the resolver
//     surfaces [clientencjwks.ErrNoEncryptionConfigured]).
//
// Any other resolver error or [jose.EncryptNestedJWT] failure is
// returned to the caller wrapped as [errJARMEncryptionFailed]; the
// call sites in [jarmEmitSuccess] / [jarmEmitError] decide on the
// failure-mode policy (see those functions for the documented split).
func maybeEncryptJARM(
	ctx context.Context,
	resolver *clientencjwks.Resolver,
	client *store.Client,
	signed string,
) (string, error) {
	if resolver == nil || client == nil {
		return signed, nil
	}
	recipient, err := resolver.ResolveRecipient(
		ctx,
		client,
		client.AuthorizationEncryptedResponseAlg,
		client.AuthorizationEncryptedResponseEnc,
	)
	if errors.Is(err, clientencjwks.ErrNoEncryptionConfigured) {
		return signed, nil
	}
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
// needs to decide whether to encrypt. The function tolerates a nil
// store and a missing client by returning (nil, nil): the caller then
// emits the signed-only JARM response, matching the no-encryption
// policy for any client the OP cannot positively identify as
// encryption-enrolled.
func lookupClientForJARM(ctx context.Context, clients store.ClientStore, clientID string) *store.Client {
	if clients == nil || clientID == "" {
		return nil
	}
	client, err := clients.GetClient(ctx, clientID)
	if err != nil {
		return nil
	}
	return client
}
