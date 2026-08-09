//go:build example

// op.go — OP-side wiring for example 30-custom-grant.
//
// This file holds the [op.New] construction and the
// [op.CustomGrantHandler] implementation the OP dispatches to when a
// /token request carries grant_type=urn:example:libraz:service-token-
// exchange. It is the half a real embedder lifts into production:
// service registration metadata, the handler that interprets the
// request body, and the verifier that authenticates the inbound
// service-token JWS.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// buildProvider wires the OP with op.WithCustomGrant pointing at a
// serviceTokenExchange handler. The wiring is shared between the
// self-verify probe and the public listener so a regression in one
// surface always fails the other.
func buildProvider(keys *devkeys.Material, servicePub *ecdsa.PublicKey) (*op.Provider, error) {
	st := inmem.New()

	handler := &serviceTokenExchange{verifier: servicePub}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// Custom grants are registered outside the built-in grant set,
		// so WithGrants governs only the built-ins this OP still serves.
		// The exchange has no end user and no browser, which rules out
		// authorization_code; refresh_token stays because a custom
		// handler may set CustomGrantResponse.IssueRefreshToken (this one
		// does not) and WithGrants requires at least one built-in.
		op.WithGrants(grant.RefreshToken),
		op.WithCustomGrant(handler),
		op.WithStaticClients(op.ConfidentialClient{
			ID:         clientID,
			Secret:     clientSecret,
			AuthMethod: op.AuthClientSecretPost,
			// Custom-grant clients never visit /authorize; the
			// GrantTypes set is overridden so the registration
			// only carries the custom URN. The dispatcher rejects
			// any client that asks for a grant_type not listed
			// here with unauthorized_client.
			GrantTypes: []string{grantURN},
			Scopes:     []string{"api:read"},
			// Resources gate the BoundAccessToken.Audience subset
			// check the dispatcher applies before issuance.
			Resources: []string{resourceAudience},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("op.New: %w", err)
	}
	return provider, nil
}

// serviceTokenExchange implements op.CustomGrantHandler for the
// demo's "exchange a service-issued JWT for an OP-minted access
// token" flow. The verifier is the public half of an out-of-band
// ES256 key the embedder's KMS would normally hold; the demo
// generates it ephemerally at boot and trusts it directly.
type serviceTokenExchange struct {
	verifier *ecdsa.PublicKey
}

// Name implements op.CustomGrantHandler.
func (h *serviceTokenExchange) Name() string { return grantURN }

// ParamPolicy implements op.CustomGrantHandler. Only the handler-
// specific extras are listed; the shared RFC 6749 §3.2 parameters
// (grant_type, client_id, client_secret, scope) are implicit.
func (h *serviceTokenExchange) ParamPolicy() op.ParamPolicy {
	return op.ParamPolicy{Allowed: []string{"service_token", "scope"}}
}

// Handle implements op.CustomGrantHandler. The OP has already
// authenticated the client and parsed the form per ParamPolicy by the
// time this runs; the handler verifies the supplied service_token,
// extracts the service identity, and asks the OP to mint a JWT access
// token bound to the request's DPoP / mTLS credential when present.
func (h *serviceTokenExchange) Handle(_ context.Context, req op.CustomGrantRequest) (op.CustomGrantResponse, error) {
	form := url.Values(req.Form)
	rawToken := form.Get("service_token")
	if rawToken == "" {
		// Generic Go errors are mapped to invalid_grant by the
		// dispatcher with the message redacted from the response body
		// (so internal diagnostics never leak). Embedders that want to
		// surface a specific RFC 6749 §5.2 wire code construct an
		// [*op.Error] directly.
		return op.CustomGrantResponse{}, errors.New("service_token form parameter is required")
	}
	subject, err := verifyServiceToken(h.verifier, rawToken)
	if err != nil {
		return op.CustomGrantResponse{}, fmt.Errorf("service_token verification failed: %w", err)
	}
	return op.CustomGrantResponse{
		BoundAccessToken: &op.BoundAccessToken{
			Subject:  op.Subject(subject),
			Audience: []string{resourceAudience},
			TTL:      accessTokenTTL,
			ExtraClaims: map[string]any{
				"svc_id": subject,
			},
		},
		Scope: []string{"api:read"},
	}, nil
}

// verifyServiceToken parses the supplied compact JWS, checks the
// alg=ES256 header, verifies the signature against pub, and returns
// the "sub" claim. The demo intentionally skips exp / nbf / aud
// enforcement to keep the verifier surface small; a production handler
// MUST validate every standard claim.
func verifyServiceToken(pub *ecdsa.PublicKey, raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("expected 3 segments, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("decode header json: %w", err)
	}
	if header.Alg != "ES256" {
		return "", fmt.Errorf("unsupported alg %q, want ES256", header.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != 64 {
		return "", fmt.Errorf("ES256 signature length=%d want 64", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return "", errors.New("ecdsa verify failed")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", fmt.Errorf("decode claims: %w", err)
	}
	if claims.Sub == "" {
		return "", errors.New("sub claim missing")
	}
	return claims.Sub, nil
}
