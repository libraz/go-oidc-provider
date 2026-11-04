package clientauth

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/op/store"
)

// CertificateVerifier authenticates a client by the certificate its
// request presented (RFC 8705 §2). method is [MethodTLSClientAuth] or
// [MethodSelfSignedTLSClientAuth]; every client-side failure satisfies
// errors.Is(err, [ErrCredentialsInvalid]).
type CertificateVerifier interface {
	VerifyCertificate(ctx context.Context, r *http.Request, method Method, client *store.Client) error
}

// CertificateSource yields the client certificate RFC 8705 §2 judges for a
// client registered with method, and whether its chain is verified.
// [*mtls.Verifier] implements it.
type CertificateSource interface {
	ClientAuthCertificate(r *http.Request, method string) (*x509.Certificate, bool, error)
}

// MTLSVerifier is the production [CertificateVerifier].
//
// Certificates must be the same source the token endpoint binds
// cnf.x5t#S256 from, so the authenticating certificate and the binding
// certificate are one. Resolver resolves a self_signed_tls_client_auth
// client's jwks / jwks_uri, and is the resolver private_key_jwt uses.
type MTLSVerifier struct {
	Certificates CertificateSource
	Resolver     JWKSResolver
}

// VerifyCertificate implements [CertificateVerifier].
func (v *MTLSVerifier) VerifyCertificate(ctx context.Context, r *http.Request, method Method, client *store.Client) error {
	if v == nil || v.Certificates == nil || client == nil {
		return ErrCredentialsInvalid
	}
	cert, chainVerified, err := v.Certificates.ClientAuthCertificate(r, string(method))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCredentialsInvalid, err)
	}
	switch method {
	case MethodTLSClientAuth:
		return verifyPKICertificate(cert, chainVerified, client)
	case MethodSelfSignedTLSClientAuth:
		return v.verifySelfSignedCertificate(ctx, cert, client)
	default:
		return ErrCredentialsInvalid
	}
}

// verifyPKICertificate applies RFC 8705 §2.1: a chain-verified cert whose
// subject DN or SAN equals the client's single registered matcher.
func verifyPKICertificate(cert *x509.Certificate, chainVerified bool, client *store.Client) error {
	if !chainVerified {
		return fmt.Errorf("%w: %w", ErrCredentialsInvalid, mtls.ErrCertChainUnverified)
	}
	matcher := ClientMatcher(client)
	if err := matcher.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrCredentialsInvalid, err)
	}
	if err := mtls.VerifyTLSClientAuth(cert, matcher); err != nil {
		return fmt.Errorf("%w: %w", ErrCredentialsInvalid, err)
	}
	return nil
}

// verifySelfSignedCertificate applies RFC 8705 §2.2: the cert's public
// key is one of the client's registered keys. A miss on a jwks_uri client
// refetches once, as a private_key_jwt kid miss does, so a rotated-in
// certificate key authenticates.
func (v *MTLSVerifier) verifySelfSignedCertificate(ctx context.Context, cert *x509.Certificate, client *store.Client) error {
	if v.Resolver == nil {
		return ErrCredentialsInvalid
	}
	keys, err := v.Resolver.JWKS(ctx, client.ID)
	if err != nil {
		return classifyKeyResolution(err)
	}
	err = mtls.VerifySelfSignedTLSClientAuthKeySet(cert, keys)
	if err == nil {
		return nil
	}
	if !errors.Is(err, mtls.ErrNoMatchingJWK) {
		return fmt.Errorf("%w: %w", ErrCredentialsInvalid, err)
	}
	fresh, ok, err := refreshedKeysOnCertMiss(ctx, v.Resolver, client.ID, keys)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %w", ErrCredentialsInvalid, mtls.ErrNoMatchingJWK)
	}
	if err := mtls.VerifySelfSignedTLSClientAuthKeySet(cert, fresh); err != nil {
		return fmt.Errorf("%w: %w", ErrCredentialsInvalid, err)
	}
	return nil
}

// refreshedKeysOnCertMiss refetches the keyset once when the resolver
// supports it and the refetch differs from tried. A server-side refetch
// failure is returned as an error; any other failure reports ok=false.
func refreshedKeysOnCertMiss(
	ctx context.Context,
	resolver JWKSResolver,
	clientID string,
	tried *josev4.JSONWebKeySet,
) (*josev4.JSONWebKeySet, bool, error) {
	refresher, ok := resolver.(jwksRefresher)
	if !ok {
		return nil, false, nil
	}
	fresh, err := refresher.RefreshJWKS(ctx, clientID)
	if err != nil {
		if keySourceUnavailable(err) {
			return nil, false, classifyKeyResolution(err)
		}
		return nil, false, nil
	}
	if fresh == nil || len(fresh.Keys) == 0 || rpjwks.SameKeySet(fresh, tried) {
		return nil, false, nil
	}
	return fresh, true, nil
}

// ClientMatcher projects the client's RFC 8705 §2.1.2 metadata onto the
// matcher internal/mtls compares certificates against.
func ClientMatcher(client *store.Client) mtls.ClientMatcher {
	return mtls.ClientMatcher{
		SubjectDN: client.TLSClientAuthSubjectDN,
		SANDNS:    client.TLSClientAuthSANDNS,
		SANURI:    client.TLSClientAuthSANURI,
		SANIP:     client.TLSClientAuthSANIP,
		SANEmail:  client.TLSClientAuthSANEmail,
	}
}

// IsCertificateMethod reports whether m is one of the RFC 8705 §2
// methods, which carry no credential in the request body.
func IsCertificateMethod(m Method) bool {
	return m == MethodTLSClientAuth || m == MethodSelfSignedTLSClientAuth
}

// EffectiveMethod returns the method creds authenticate client with. A
// request carrying no body credential from a confidential client
// registered for an RFC 8705 §2 method authenticates with that method;
// every other request keeps the method its shape implies.
func EffectiveMethod(creds *Credentials, client *store.Client) Method {
	if creds == nil {
		return ""
	}
	if creds.Method != MethodNone || client == nil || client.PublicClient {
		return creds.Method
	}
	if registered := Method(client.TokenEndpointAuthMethod); IsCertificateMethod(registered) {
		return registered
	}
	return creds.Method
}
