package op_test

import (
	"crypto/x509"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// TestNew_TLSClientAuthBehindProxyRequiresRootCAs pins that op.New refuses
// a configuration on which a client can use tls_client_auth through
// WithMTLSProxy while no WithMTLSRootCAs verifies the forwarded chain, and
// accepts it once the anchors are configured or the proxy is absent.
func TestNew_TLSClientAuthBehindProxyRequiresRootCAs(t *testing.T) {
	t.Parallel()

	seed := op.WithStaticClients(op.TLSClientAuthClient{
		ID:           "pki-rp",
		SANDNS:       "pki-rp.example.com",
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid"},
	})
	proxy := op.WithMTLSProxy(op.MTLSProxy{HeaderName: "X-Client-Cert", TrustedProxies: []string{"10.0.0.0/8"}})
	roots := op.WithMTLSRootCAs(x509.NewCertPool())
	selfSigned := op.WithStaticClients(op.SelfSignedTLSClientAuthClient{
		ID:           "self-rp",
		JWKS:         validStaticJWKS(t),
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid"},
	})
	cases := []struct {
		name    string
		opts    []op.Option
		wantErr []string
	}{
		{"static seed behind proxy without root CAs", []op.Option{seed, proxy}, []string{"pki-rp", "WithMTLSRootCAs"}},
		{"dynamic registration behind proxy without root CAs", []op.Option{
			proxy, op.WithDynamicRegistration(op.DynamicRegistration{}),
		}, []string{"WithDynamicRegistration", "WithMTLSRootCAs"}},
		{"static seed behind proxy with root CAs", []op.Option{seed, proxy, roots}, nil},
		{"static seed over direct TLS", []op.Option{seed}, nil},
		{"self-signed seed behind proxy", []op.Option{selfSigned, proxy}, nil},
		{"dynamic registration under OAuth21 behind proxy without root CAs", []op.Option{
			proxy, op.WithDynamicRegistration(op.DynamicRegistration{}),
			op.WithProfile(profile.OAuth21),
		}, []string{"WithMTLSRootCAs"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := append(validBaseOptsWithInmem(t), op.WithFeature(feature.MTLS))
			_, err := op.New(append(opts, tc.opts...)...)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("op.New: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("op.New accepted the configuration")
			}
			assertErrorMentions(t, err, tc.wantErr...)
		})
	}
}

// TestNew_MTLSSeedShape pins the static seed rules: a TLSClientAuthClient
// sets exactly one matcher, and a SelfSignedTLSClientAuthClient exactly one
// of JWKS and JWKSURI.
func TestNew_MTLSSeedShape(t *testing.T) {
	t.Parallel()

	jwks := validStaticJWKS(t)
	cb := []string{"https://app.example.com/cb"}
	cases := []struct {
		name    string
		seed    op.ClientSeed
		wantErr []string
	}{
		{"one matcher", op.TLSClientAuthClient{ID: "c", RedirectURIs: cb, SubjectDN: "CN=c"}, nil},
		{"no matcher", op.TLSClientAuthClient{ID: "c", RedirectURIs: cb}, []string{"TLSClientAuthClient c", "exactly one of SubjectDN"}},
		{"two matchers", op.TLSClientAuthClient{ID: "c", RedirectURIs: cb, SubjectDN: "CN=c", SANEmail: "c@example.com"}, []string{"exactly one of SubjectDN"}},
		{"san_ip not an IP", op.TLSClientAuthClient{ID: "c", RedirectURIs: cb, SANIP: "c.example.com"}, []string{"TLSClientAuthClient c"}},
		{"self-signed jwks", op.SelfSignedTLSClientAuthClient{ID: "c", RedirectURIs: cb, JWKS: jwks}, nil},
		{"self-signed jwks_uri", op.SelfSignedTLSClientAuthClient{ID: "c", RedirectURIs: cb, JWKSURI: "https://rp.example.com/jwks.json"}, nil},
		{"self-signed neither", op.SelfSignedTLSClientAuthClient{ID: "c", RedirectURIs: cb}, []string{"SelfSignedTLSClientAuthClient c", "neither is set"}},
		{"self-signed both", op.SelfSignedTLSClientAuthClient{
			ID: "c", RedirectURIs: cb, JWKS: jwks, JWKSURI: "https://rp.example.com/jwks.json",
		}, []string{"both are set"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := append(validBaseOptsWithInmem(t), op.WithFeature(feature.MTLS))
			_, err := op.New(append(opts, op.WithStaticClients(tc.seed))...)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("op.New: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("op.New accepted the seed")
			}
			assertErrorMentions(t, err, tc.wantErr...)
		})
	}
}
