package op_test

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
)

// TestNew_RejectsMTLSOptionsWithoutTheFeature covers the combination that
// reads as certificate binding and behaves as none at all. Without
// [feature.MTLS] the OP builds no verifier, so a configured proxy
// allow-list or trust-anchor pool is never consulted: the forwarded
// certificate is ignored and the access token is issued as a plain bearer
// with no cnf.x5t#S256. Construction refuses it, naming the option.
func TestNew_RejectsMTLSOptionsWithoutTheFeature(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		opt    op.Option
		option string
	}{
		{
			"WithMTLSProxy",
			op.WithMTLSProxy(op.MTLSProxy{HeaderName: "X-Client-Cert", TrustedProxies: []string{"10.0.0.0/8"}}),
			"WithMTLSProxy",
		},
		{"WithMTLSRootCAs", op.WithMTLSRootCAs(x509.NewCertPool()), "WithMTLSRootCAs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t), tc.opt)...)
			if err == nil {
				t.Fatal("op.New accepted an mTLS option without feature.MTLS")
			}
			if !strings.Contains(err.Error(), "the mTLS feature is not enabled") {
				t.Errorf("err = %v, want it to name the missing feature", err)
			}
			if !strings.Contains(err.Error(), tc.option) {
				t.Errorf("err = %v, want it to name %s", err, tc.option)
			}
		})
	}
}

// TestNew_AcceptsMTLSOptionsWithTheFeatureEnabled is the half that keeps
// the refusal worth reading. With the feature on, both options are wired
// into a real verifier.
func TestNew_AcceptsMTLSOptionsWithTheFeatureEnabled(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t),
		op.WithFeature(feature.MTLS),
		op.WithMTLSProxy(op.MTLSProxy{HeaderName: "X-Client-Cert", TrustedProxies: []string{"10.0.0.0/8"}}),
		op.WithMTLSRootCAs(x509.NewCertPool()),
	)...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
}

// TestNew_AcceptsWithoutMTLSOptions pins the other trigger condition: an OP
// that never mentions mTLS is not affected.
func TestNew_AcceptsWithoutMTLSOptions(t *testing.T) {
	t.Parallel()

	if _, err := op.New(validBaseOpts(t)...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
}
