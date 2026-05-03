package introspectendpoint

import (
	"context"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/op/store"
)

// maybeEncryptIntrospection wraps the supplied signed JWT in a JWE
// addressed to client when the client registered
// introspection_encrypted_response_alg / _enc (RFC 9701 §5). The
// function returns signed unchanged in three structurally-equivalent
// "encryption not in play" situations:
//
//   - deps.ClientEncJWKs is nil (the OP did not wire a resolver),
//   - the client did not register encryption metadata
//     ([clientencjwks.ErrNoEncryptionConfigured]).
//
// Any other resolver error is propagated to the caller. The wrapper
// MUST NOT silently fall back to an unencrypted body when the client
// did register encryption metadata: silently emitting a signed-only
// response in that case is a confidentiality downgrade. See RFC 9701
// §5 — encryption is opt-in but, once opted in, mandatory.
//
// Successful resolution feeds [jose.EncryptNestedJWT], which stamps
// `cty=JWT` so a recipient that decrypts the outer JWE knows to verify
// the inner JWS. The wire content-type stays
// "application/token-introspection+jwt" per RFC 9701 §5: the JWE is
// itself a JWT (just nested).
func maybeEncryptIntrospection(
	ctx context.Context,
	deps Deps,
	client *store.Client,
	signed string,
) (string, error) {
	if deps.ClientEncJWKs == nil {
		return signed, nil
	}
	if client == nil {
		return signed, nil
	}
	recipient, err := deps.ClientEncJWKs.ResolveRecipient(
		ctx,
		client,
		client.IntrospectionEncryptedResponseAlg,
		client.IntrospectionEncryptedResponseEnc,
	)
	if errors.Is(err, clientencjwks.ErrNoEncryptionConfigured) {
		return signed, nil
	}
	if err != nil {
		return "", fmt.Errorf("introspect: resolve encryption recipient: %w", err)
	}
	out, err := jose.EncryptNestedJWT(signed, recipient)
	if err != nil {
		return "", fmt.Errorf("introspect: encrypt nested jwt: %w", err)
	}
	return out, nil
}
