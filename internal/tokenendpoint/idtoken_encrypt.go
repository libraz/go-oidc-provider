package tokenendpoint

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/op/store"
)

// maybeEncryptIDToken wraps a signed id_token in a JWE addressed to
// the RP's `use=enc` key (OIDC Core 1.0 §10.2) when the client
// registered id_token_encrypted_response_alg / _enc. The function
// returns signed verbatim when:
//
//   - The resolver is unwired ([Deps.ClientEncJWKs] is nil); the
//     embedder did not opt into outbound id_token encryption.
//   - The resolver returns [clientencjwks.ErrNoEncryptionConfigured];
//     the client did not register encryption metadata for this
//     response path.
//
// Any other resolver error (alg-not-allowed, JWKS misconfigured,
// JWKS fetch failed, no matching key) is propagated to the caller.
// The token endpoint MUST surface those as server_error per RFC 6749
// §5.2 because the client registered encryption but the OP cannot
// honour the request — silently falling back to the signed form
// would be a downgrade-attack surface.
//
// The returned compact JWE is a five-segment dot-separated string
// the RP decrypts with the private half of the resolved
// recipient key; the protected header carries `cty=JWT` so the RP
// knows to verify the inner JWS.
func maybeEncryptIDToken(
	ctx context.Context,
	deps Deps,
	client *store.Client,
	signed string,
) (string, error) {
	if deps.ClientEncJWKs == nil || client == nil {
		return signed, nil
	}
	recipient, err := deps.ClientEncJWKs.ResolveRecipient(
		ctx,
		client,
		client.IDTokenEncryptedResponseAlg,
		client.IDTokenEncryptedResponseEnc,
	)
	if errors.Is(err, clientencjwks.ErrNoEncryptionConfigured) {
		return signed, nil
	}
	if err != nil {
		return "", err
	}
	return jose.EncryptNestedJWT(signed, recipient)
}
