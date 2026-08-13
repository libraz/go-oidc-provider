package op_test

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
)

// mtlsWarningFragment is the phrase both partial-wiring warnings share.
// Matching on it rather than on a whole sentence keeps the assertions
// from re-pinning the wording, while still failing if the warning stops
// naming the reason.
const mtlsWarningFragment = "the mTLS feature is not enabled"

// TestNew_WarnsWhenMTLSProxyIsConfiguredWithoutTheFeature covers the
// combination that reads as certificate binding and behaves as none at
// all. Without [feature.MTLS] the OP builds no verifier, so the recorded
// proxy allow-list is never consulted: the forwarded certificate is
// ignored and the access token is issued as a plain bearer with no
// cnf.x5t#S256. Nothing fails, and [op.MTLSProxyConfig] reads the
// configured value back unchanged, so the deployment has no way to
// notice from its own configuration.
func TestNew_WarnsWhenMTLSProxyIsConfiguredWithoutTheFeature(t *testing.T) {
	t.Parallel()

	logged := warnings(t, append(validBaseOpts(t),
		op.WithMTLSProxy("X-Client-Cert", []string{"10.0.0.0/8"}),
	)...)
	if !strings.Contains(logged, mtlsWarningFragment) {
		t.Fatalf("no warning about the missing mTLS feature; got:\n%s", logged)
	}
	if !strings.Contains(logged, "WithMTLSProxy") {
		t.Errorf("warning does not name WithMTLSProxy; got:\n%s", logged)
	}
}

// TestNew_WarnsWhenMTLSRootCAsAreConfiguredWithoutTheFeature is the
// sibling condition: trust anchors installed for a chain check that
// never runs.
func TestNew_WarnsWhenMTLSRootCAsAreConfiguredWithoutTheFeature(t *testing.T) {
	t.Parallel()

	logged := warnings(t, append(validBaseOpts(t),
		op.WithMTLSRootCAs(x509.NewCertPool()),
	)...)
	if !strings.Contains(logged, mtlsWarningFragment) {
		t.Fatalf("no warning about the missing mTLS feature; got:\n%s", logged)
	}
	if !strings.Contains(logged, "WithMTLSRootCAs") {
		t.Errorf("warning does not name WithMTLSRootCAs; got:\n%s", logged)
	}
}

// TestNew_DoesNotWarnAboutMTLSOptionsWithTheFeatureEnabled is the half
// that keeps the warning worth reading. With the feature on, both
// options are wired into a real verifier and there is nothing to say.
func TestNew_DoesNotWarnAboutMTLSOptionsWithTheFeatureEnabled(t *testing.T) {
	t.Parallel()

	logged := warnings(t, append(validBaseOpts(t),
		op.WithFeature(feature.MTLS),
		op.WithMTLSProxy("X-Client-Cert", []string{"10.0.0.0/8"}),
		op.WithMTLSRootCAs(x509.NewCertPool()),
	)...)
	if strings.Contains(logged, mtlsWarningFragment) {
		t.Fatalf("warned about mTLS options on an mTLS-enabled OP; got:\n%s", logged)
	}
}

// TestNew_DoesNotWarnAboutMTLSWithoutTheOptions pins the other trigger
// condition: an OP that never mentions mTLS says nothing about it.
func TestNew_DoesNotWarnAboutMTLSWithoutTheOptions(t *testing.T) {
	t.Parallel()

	logged := warnings(t, validBaseOpts(t)...)
	if strings.Contains(logged, mtlsWarningFragment) {
		t.Fatalf("warned with no mTLS option configured; got:\n%s", logged)
	}
}
