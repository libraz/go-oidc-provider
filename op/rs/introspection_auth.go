package rs

import (
	"crypto"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
)

// clientAssertionTTL is the lifetime of a private_key_jwt assertion. Each
// request signs a fresh one, so it only has to outlast the round trip.
const clientAssertionTTL = 60 * time.Second

// clientAssertion signs the RFC 7523 §2.2 assertions that authenticate
// introspection requests under private_key_jwt.
type clientAssertion struct {
	key      crypto.Signer
	alg      jose.Algorithm
	keyID    string
	clientID string
	audience string
}

// assertionAlg maps a private key to the JWS alg its assertions use:
// ES256 for ECDSA P-256, PS256 for RSA, EdDSA for Ed25519.
func assertionAlg(key crypto.Signer) (jose.Algorithm, bool) {
	shape, _, _, ok := jose.KeyShape(key.Public())
	if !ok {
		return jose.AlgUnspecified, false
	}
	switch jose.Algorithm(shape) {
	case jose.AlgES256, jose.AlgEdDSA:
		return jose.Algorithm(shape), true
	case jose.AlgRS256:
		return jose.AlgPS256, true
	default:
		return jose.AlgUnspecified, false
	}
}

// newClientAssertion builds the signer for clientID's assertions. The
// audience is the issuer identifier alone, the form FAPI 2.0 requires and
// every profile of the OP accepts.
func newClientAssertion(clientID, keyID, issuer string, key crypto.Signer) (*clientAssertion, error) {
	alg, ok := assertionAlg(key)
	if !ok {
		return nil, jose.ErrUnsupportedKeyShape
	}
	return &clientAssertion{key: key, alg: alg, keyID: keyID, clientID: clientID, audience: issuer}, nil
}

// sign returns a fresh assertion issued at now.
func (a *clientAssertion) sign(now time.Time) (string, error) {
	jti, err := keys.RandomBase64URL(keys.IdentifierBytes)
	if err != nil {
		return "", fmt.Errorf("rs: client assertion jti: %w", err)
	}
	claims := map[string]any{
		"iss": a.clientID,
		"sub": a.clientID,
		"aud": a.audience,
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(clientAssertionTTL).Unix(),
	}
	out, err := jose.SignCompact(a.key, a.alg, a.keyID, claims)
	if err != nil {
		return "", fmt.Errorf("rs: sign client assertion: %w", err)
	}
	return out, nil
}

// newIntrospectFetch returns the client introspection requests go
// through. It accepts the RFC 9701 JWT media type besides JSON and, when
// in authenticates with mutual TLS, presents the certificate.
func newIntrospectFetch(in IntrospectionConfig, policy securefetch.Policy) *securefetch.Client {
	policy.AcceptContentTypes = []string{mediaTypeIntrospectionJWT, "application/json"}
	if in.TLSCertificate != nil {
		policy.BaseTransport = mtlsTransport(policy.BaseTransport, in.TLSCertificate)
	}
	return securefetch.NewClient(policy)
}

// mtlsTransport returns a transport that presents cert on every TLS
// handshake. base is cloned when it is an [*http.Transport]; otherwise a
// clone of [http.DefaultTransport] stands in, without the environment
// proxy the SSRF guard does not inherit by default. The SSRF guard is
// layered over the result exactly as over any configured transport.
func mtlsTransport(base http.RoundTripper, cert *tls.Certificate) *http.Transport {
	t, ok := base.(*http.Transport)
	if !ok {
		t, ok = http.DefaultTransport.(*http.Transport)
		if !ok {
			t = &http.Transport{}
		}
		t = t.Clone()
		t.Proxy = nil
	} else {
		t = t.Clone()
	}
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	// Present the certificate whatever CA hints the server sends: a
	// self-signed certificate matches none of them.
	t.TLSClientConfig.Certificates = []tls.Certificate{*cert}
	t.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return cert, nil
	}
	return t
}
