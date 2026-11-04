package op

import (
	"slices"
	"strconv"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/registrationendpoint"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
)

// validateFirstPartyClients enforces the cross-cutting invariants
// between [WithFirstPartyClients] and the static-client surface:
//   - every advertised client_id MUST appear in [config.staticClients]
//     after every option has been applied (the option site cannot
//     enforce this because the two options are order-independent);
//   - no FAPI 2.0 profile MAY be active simultaneously. FAPI 2.0
//     forbids auto-consent because the profile mandates explicit
//     user authorization for every protected resource.
func (c *config) validateFirstPartyClients() error {
	if len(c.firstPartyClients) == 0 {
		return nil
	}
	for _, p := range c.profiles {
		if isFAPI2Profile(p) {
			return newConfigurationError("WithFirstPartyClients is incompatible with FAPI 2.0 profile "+profileOptionName(p), nil)
		}
	}
	known := make(map[string]struct{}, len(c.staticClients))
	for _, sc := range c.staticClients {
		known[sc.ID] = struct{}{}
	}
	for _, id := range c.firstPartyClients {
		if _, ok := known[id]; !ok {
			return newConfigurationError("WithFirstPartyClients: unknown client_id "+id, nil)
		}
	}
	return nil
}

// validateStaticClients runs the same structural validator DCR drives
// on inbound /register payloads against every embedder-supplied static
// seed. The check closes the gap where an invalid redirect_uri /
// backchannel_logout_uri / grant_type / response_type / subject_type
// value persisted by [WithStaticClients] would only surface at the
// first request that touched the offending field; running the
// validator at construction time forces the misconfiguration to land
// at op.New so embedders see it during boot.
//
// Scope catalogue checks are intentionally skipped — the embedder
// authoritatively names the scopes their static clients carry, and
// the runtime intersection at /authorize already rejects unregistered
// values.
//
// The seam between this method and the registration-endpoint package
// flows through a thin shim function so internal/* never imports op/
// while op/ continues to own the wire-error wrapping.
func (c *config) validateStaticClients() error {
	if len(c.staticClients) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(c.staticClients))
	opts := registrationendpoint.StaticClientValidationOptions{
		AllowedGrantTypes:                    c.staticClientAllowedGrantTypes(),
		AllowedResponseTypes:                 c.staticClientAllowedResponseTypes(),
		AllowedClientAuthMethods:             c.allowedClientAuthMethods(),
		ActiveProfile:                        c.authMethodProfileNames(),
		AllowedClientSigningAlgs:             c.clientSigningJOSEAlgs(),
		PairwiseEnabled:                      c.pairwiseEnabled(),
		AllowLocalhostLoopback:               c.allowLocalhostRedirectURIs,
		AllowInsecureBackchannelLogoutForDev: c.allowInsecureBackchannelLogoutForDev,
		JWEPolicy:                            c.jwePolicy(),
		SigningAlg:                           string(c.issuingAlg()),
		MTLSClientAuth:                       c.mtlsClientAuthEnabled(),
		ProfileAdmitsMTLSClientAuth:          c.profileAdmitsMTLSClientAuth(),
	}
	for i := range c.staticClients {
		seed := c.staticClients[i]
		if _, duplicate := seen[seed.ID]; duplicate {
			return newConfigurationError("WithStaticClients["+strconv.Itoa(i)+
				"]: duplicate client_id "+seed.ID, nil)
		}
		seen[seed.ID] = struct{}{}
		if err := c.validateStaticClientSecretFormat(i, seed); err != nil {
			return err
		}
		if err := registrationendpoint.ValidateStaticClient(seed, opts); err != nil {
			return newConfigurationError("WithStaticClients["+strconv.Itoa(i)+
				"] (client_id "+seed.ID+"): "+err.Error(), err)
		}
	}
	return nil
}

// validateStaticClientSecretFormat enforces the promise
// [WithHighEntropyClientSecrets] is built on: with that option set,
// no client may be stored under the password KDF.
//
// The check runs against the projected record rather than the seed's
// input fields, so it catches a hash that arrived any way at all —
// [ConfidentialClient.Secret], a pre-computed [ConfidentialClient.SecretHash]
// produced by the wrong helper, or a builder added later. Refusing at
// construction is the point: the alternative is an OP that boots, runs,
// and quietly answers an unknown client_id in microseconds while
// answering this one in ninety milliseconds.
func (c *config) validateStaticClientSecretFormat(index int, seed store.Client) error {
	if !c.highEntropyClientSecrets {
		return nil
	}
	if seed.PreviousSecretHash != "" && !clientauth.IsHighEntropyEncoding(seed.PreviousSecretHash) {
		return newConfigurationError("WithStaticClients["+strconv.Itoa(index)+
			"] (client_id "+seed.ID+"): WithHighEntropyClientSecrets requires a previous secret "+
			"provisioned through NewClientSecret or HashHighEntropyClientSecret; "+
			"set ConfidentialClient.PreviousSecretHash, not PreviousSecret", nil)
	}
	if seed.SecretHash == "" || clientauth.IsHighEntropyEncoding(seed.SecretHash) {
		return nil
	}
	return newConfigurationError("WithStaticClients["+strconv.Itoa(index)+
		"] (client_id "+seed.ID+"): WithHighEntropyClientSecrets requires a secret "+
		"provisioned through NewClientSecret or HashHighEntropyClientSecret; "+
		"ConfidentialClient.Secret hashes with Argon2id, which this option does not admit", nil)
}

// staticClientAllowedGrantTypes returns the grant_type whitelist the
// static-client validator runs against. Static clients are trusted
// configuration: the embedder authoritatively names the grants their
// clients participate in. The validator therefore admits every
// grant_type the library implements plus any custom grant the embedder
// wired through [WithCustomGrant], so a seed listing
// `["authorization_code", "refresh_token"]` flows through cleanly even
// when the OP only mounts the CIBA grant at runtime — the runtime
// dispatcher rejects an unsupported grant on the wire side, and the
// static-client gate stays focused on structural rules (malformed
// values, unknown wire form).
//
// The library half comes from [builtinGrantTypeWireList] rather than a
// second transcription of the same wires: a grant added to the library
// is admitted here with no parallel edit. Membership is unconditional,
// independent of which grants this deployment enabled — a seed naming
// a grant the OP does not mount still receives unsupported_grant_type
// at /token, which is the surface where "configured but not enabled"
// belongs.
func (c *config) staticClientAllowedGrantTypes() []string {
	allowed := builtinGrantTypeWireList()
	for _, h := range c.customGrants {
		if h == nil {
			continue
		}
		name := h.Name()
		if name != "" && !slices.Contains(allowed, name) {
			allowed = append(allowed, name)
		}
	}
	return allowed
}

// staticClientAllowedResponseTypes returns the response_type whitelist
// the static-client validator runs against. v1.0 ships with "code"
// only at the authorization endpoint, so the helper hard-codes the
// single value.
func (c *config) staticClientAllowedResponseTypes() []string {
	return []string{"code"}
}

// authMethodProfileNames renders the active profiles that narrow the
// client-authentication methods, for example "profile.FAPI2Baseline",
// joined with " + " when several do.
func (c *config) authMethodProfileNames() string {
	var names []string
	for _, p := range c.profiles {
		if profile.AllowedClientAuthMethods(p) != nil {
			names = append(names, profileOptionName(p))
		}
	}
	return strings.Join(names, " + ")
}

// profileAdmitsMTLSClientAuth reports whether the active profiles would
// admit tls_client_auth once [feature.MTLS] is on.
func (c *config) profileAdmitsMTLSClientAuth() bool {
	allowed := c.profileIntersection(profile.AllowedClientAuthMethods)
	return allowed != nil && slices.Contains(allowed, AuthTLSClientAuth.String())
}

// validateMTLSClientAuth refuses an OP on which a client may authenticate
// with tls_client_auth through [WithMTLSProxy] while no [WithMTLSRootCAs]
// is configured. RFC 8705 §2.1 PKI authentication needs a verified chain;
// a forwarded certificate is verified only against those anchors, so every
// such client would fail at runtime.
//
// tls_client_auth is reachable when [feature.MTLS] is on and either a
// static seed registers it or dynamic registration may admit it. Direct
// TLS is judged per request from the handshake's verified chains, which
// construction cannot see.
func (c *config) validateMTLSClientAuth() error {
	if !c.mtlsClientAuthEnabled() || c.mtlsProxy.header == "" || c.mtlsRootCAs != nil {
		return nil
	}
	for _, seed := range c.staticClients {
		if seed.TokenEndpointAuthMethod == AuthTLSClientAuth.String() {
			return newConfigurationError("WithStaticClients (client_id "+seed.ID+
				"): tls_client_auth behind WithMTLSProxy requires WithMTLSRootCAs, "+
				"because a forwarded certificate is chain-verified only against those anchors", nil)
		}
	}
	if c.dcr != nil {
		allowed := c.allowedClientAuthMethods()
		if allowed == nil || slices.Contains(allowed, clientauth.MethodTLSClientAuth) {
			return newConfigurationError("WithDynamicRegistration admits tls_client_auth, which behind "+
				"WithMTLSProxy requires WithMTLSRootCAs: a forwarded certificate is chain-verified only "+
				"against those anchors", nil)
		}
	}
	return nil
}
