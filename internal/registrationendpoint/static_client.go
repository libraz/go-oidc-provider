package registrationendpoint

import (
	"errors"
	"strings"

	"github.com/libraz/go-oidc-provider/op/store"
)

// StaticClientValidationOptions carry the policy knobs the
// [ValidateStaticClient] entry point threads into [validatePolicy] so
// the structural rules DCR enforces on /register payloads also apply
// to embedder-supplied static seeds.
//
// The fields mirror the corresponding [Deps] fields used by the
// /register handler. Every field is optional: a zero value is the
// safe default that keeps the validator at the library ceiling.
type StaticClientValidationOptions struct {
	// AllowedGrantTypes mirrors [Deps.AllowedGrantTypes]: the
	// grant_types whitelist a registration may request. Empty applies
	// the library default {"authorization_code", "refresh_token"}.
	AllowedGrantTypes []string

	// AllowedResponseTypes mirrors [Deps.AllowedResponseTypes]: the
	// response_types whitelist a registration may request. Empty
	// applies the library default {"code"}.
	AllowedResponseTypes []string

	// PairwiseEnabled mirrors [Deps.PairwiseEnabled]. When false,
	// "subject_type": "pairwise" is rejected.
	PairwiseEnabled bool

	// AllowLocalhostLoopback mirrors [Deps.AllowLocalhostLoopback]:
	// widens the RFC 8252 §7.3 loopback redirect_uri carve-out to
	// admit the textual "localhost" host in addition to the IP
	// literals 127.0.0.1 and [::1]. The default false keeps the
	// IP-only posture.
	AllowLocalhostLoopback bool

	// AllowInsecureBackchannelLogoutForDev mirrors
	// [Deps.AllowInsecureBackchannelLogoutForDev]: under the dev
	// opt-in plain-http loopback URLs are admitted for the
	// `backchannel_logout_uri` field so example demos can boot
	// without TLS termination. The default false keeps the
	// production https-only posture.
	AllowInsecureBackchannelLogoutForDev bool
}

// StaticClientValidationError reports a structural rule violation a
// [ValidateStaticClient] call detected on an embedder-supplied static
// seed. The wire-stable Code value mirrors the RFC 7591 §3.2.2 token
// the /register handler emits for the same failure shape so embedders
// see a single error vocabulary across the static-seed and DCR paths.
//
// Description carries the operator-facing hint validatePolicy attached
// to the failure; the value is safe to embed in startup logs but does
// not carry sensitive material.
type StaticClientValidationError struct {
	Code        string
	Description string
}

// Error implements error. The string is wire-stable so callers can pin
// it in tests; the description is operator-facing.
func (e *StaticClientValidationError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Description
}

// ValidateStaticClient runs the same structural validator DCR drives
// on inbound /register payloads against the supplied [store.Client].
// The library wires it from op.New so embedder-supplied static client
// seeds and dynamically-registered clients share a single rule set:
// invalid redirect_uri / backchannel_logout_uri / grant_type /
// response_type / subject_type values surface at construction time
// instead of the first request that touches the offending field.
//
// Scope catalogue checks are intentionally skipped: the embedder
// authoritatively names the scopes their static clients carry, and the
// runtime intersection at /authorize already rejects unregistered
// values.
//
// The redirect_uris-required gate validatePolicy enforces is also
// suppressed for static seeds that participate only in non-redirect
// grants (CIBA, client_credentials, token-exchange) — those clients
// never visit /authorize and have no redirect_uri to register, while
// their DCR counterparts are blocked from registering by
// [Deps.AllowedGrantTypes] policy in the first place. Every other
// validatePolicy gate runs unchanged.
//
// On success the function returns nil. On rejection it returns a
// [*StaticClientValidationError] whose Code is the RFC 7591 §3.2.2
// token the DCR handler uses for the same failure shape.
func ValidateStaticClient(c store.Client, opts StaticClientValidationOptions) error {
	metadata := staticClientToMetadata(c)
	allowedResponseTypes := opts.AllowedResponseTypes
	if !grantTypesUseRedirect(metadata.GrantTypes) {
		// Static seeds whose grants do not visit /authorize (CIBA,
		// client_credentials, token-exchange, device_code) have no
		// meaningful RedirectURIs / ResponseTypes to validate. The
		// PublicClient / ConfidentialClient / PrivateKeyJWTClient
		// builders nevertheless default ResponseTypes to "code" so the
		// store.Client carries a value that has no /authorize-side
		// consumer. Clearing both the metadata value and the resolved
		// whitelist lets validatePolicy skip the redirect / consistency
		// gates that would otherwise fail on a CIBA-only seed (a
		// "code" response_type without an authorization_code grant
		// trips validateGrantResponseTypeConsistency). The redirect
		// URI placeholder satisfies the redirect_uris-required gate
		// without producing a value that flows back to the wire —
		// op.New does not propagate these adjustments into
		// [config.staticClients].
		if len(metadata.RedirectURIs) == 0 {
			metadata.RedirectURIs = []string{"https://static-client.invalid/placeholder"}
		}
		metadata.ResponseTypes = nil
		allowedResponseTypes = nil
	}
	_, err := validatePolicy(
		metadata,
		opts.AllowedGrantTypes,
		allowedResponseTypes,
		nil,   // iatScopes: static clients are not IAT-scoped.
		false, // openRegistration: static clients are not /register flow.
		nil,   // openRegistrationDefaultScopes: same.
		nil,   // scopes: skip the scope-registry check; the embedder
		// authoritatively names the scopes their static clients carry.
		opts.PairwiseEnabled,
		opts.AllowLocalhostLoopback,
		opts.AllowInsecureBackchannelLogoutForDev,
	)
	if err == nil {
		return nil
	}
	if ve, ok := asValidationError(err); ok {
		return &StaticClientValidationError{
			Code:        ve.code,
			Description: ve.description,
		}
	}
	// validatePolicy currently only emits *validationError; the
	// fallback exists so a future refactor that introduces a new error
	// type still produces a stable wrapper at this seam.
	return &StaticClientValidationError{
		Code:        codeInvalidClientMetadata,
		Description: err.Error(),
	}
}

// grantTypesUseRedirect reports whether the supplied grant_types slice
// contains at least one grant that requires a registered redirect_uri.
// authorization_code / implicit / hybrid all funnel through /authorize;
// CIBA / client_credentials / token-exchange / device_code do not.
// refresh_token is intentionally NOT in the list because a client may
// pair refresh_token with a non-redirect grant (CIBA + refresh_token,
// device_code + refresh_token); requiring a redirect_uri whenever
// refresh_token appears would lock out those embedder-driven shapes.
//
// The function returns true for an empty slice so a seed that
// inherits the library default ({"authorization_code", "refresh_token"})
// is held to the redirect_uris-required rule. The common case is
// therefore validated like DCR; the carve-out fires only when the
// embedder explicitly opted into a non-redirect grant set.
func grantTypesUseRedirect(grants []string) bool {
	if len(grants) == 0 {
		return true
	}
	for _, g := range grants {
		if grantUsesRedirect(g) {
			return true
		}
	}
	return false
}

// grantUsesRedirect reports whether a single grant_type wire value
// requires a registered redirect_uri. The list mirrors the OAuth 2.0 /
// OIDC grants that visit /authorize: authorization_code (RFC 6749
// §4.1) and the implicit / hybrid response-mode flows (OIDC Core 1.0
// §3.1 / §3.2 / §3.3).
func grantUsesRedirect(g string) bool {
	switch g {
	case "authorization_code", "implicit":
		return true
	default:
		return false
	}
}

// AsStaticClientValidationError reports whether err is a
// [*StaticClientValidationError] and, if so, returns its (Code,
// Description) pair. The helper exists so callers can branch on the
// typed error without importing this package twice.
func AsStaticClientValidationError(err error) (*StaticClientValidationError, bool) {
	var sve *StaticClientValidationError
	if errors.As(err, &sve) {
		return sve, true
	}
	return nil, false
}

// staticClientToMetadata projects the persistent [store.Client] shape
// onto the wire-shape [ClientMetadata] the validator consumes. Slice
// fields are passed by reference (cloneStrings is unnecessary because
// validatePolicy never mutates the input — applyMetadataDefaults
// returns a fresh struct on the populated path).
//
// store.Client.Scopes is a slice but ClientMetadata.Scope is a single
// space-separated string. The conversion preserves the embedder's
// choice for the (skipped) scope-registry check and for the
// validateRequestedScopes invocation; the latter is a no-op when the
// scopes registry argument is nil.
func staticClientToMetadata(c store.Client) ClientMetadata {
	return ClientMetadata{
		RedirectURIs:                      c.RedirectURIs,
		GrantTypes:                        c.GrantTypes,
		ResponseTypes:                     c.ResponseTypes,
		Scope:                             strings.Join(c.Scopes, " "),
		TokenEndpointAuthMethod:           c.TokenEndpointAuthMethod,
		ApplicationType:                   c.ApplicationType,
		SubjectType:                       c.SubjectType,
		IDTokenSignedResponseAlg:          c.IDTokenSignedResponseAlg,
		SectorIdentifierURI:               c.SectorIdentifierURI,
		ClientName:                        c.ClientName,
		ClientURI:                         c.ClientURI,
		LogoURI:                           c.LogoURI,
		PolicyURI:                         c.PolicyURI,
		TosURI:                            c.TosURI,
		JWKsURI:                           c.JWKsURI,
		JWKs:                              c.JWKs,
		Contacts:                          c.Contacts,
		DefaultMaxAge:                     c.DefaultMaxAge,
		RequireAuthTime:                   c.RequireAuthTime,
		DefaultACRValues:                  c.DefaultACRValues,
		InitiateLoginURI:                  c.InitiateLoginURI,
		RequestURIs:                       c.RequestURIs,
		RequestObjectSigningAlg:           c.RequestObjectSigningAlg,
		RequestObjectEncryptionAlg:        c.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc:        c.RequestObjectEncryptionEnc,
		IDTokenEncryptedResponseAlg:       c.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:       c.IDTokenEncryptedResponseEnc,
		UserInfoEncryptedResponseAlg:      c.UserInfoEncryptedResponseAlg,
		UserInfoEncryptedResponseEnc:      c.UserInfoEncryptedResponseEnc,
		AuthorizationEncryptedResponseAlg: c.AuthorizationEncryptedResponseAlg,
		AuthorizationEncryptedResponseEnc: c.AuthorizationEncryptedResponseEnc,
		IntrospectionEncryptedResponseAlg: c.IntrospectionEncryptedResponseAlg,
		IntrospectionEncryptedResponseEnc: c.IntrospectionEncryptedResponseEnc,
		PostLogoutRedirectURIs:            c.PostLogoutRedirectURIs,
		BackchannelLogoutURI:              c.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:  c.BackchannelLogoutSessionRequired,
	}
}
