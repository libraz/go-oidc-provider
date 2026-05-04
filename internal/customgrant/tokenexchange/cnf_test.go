// Test file pins the id_token cnf binding the assembleResponse path
// stamps when the request was DPoP- or mTLS-bound. The helper itself
// is tested first; the assemble integration follows so a future change
// to either side does not silently desynchronise the access_token cnf
// from the id_token cnf.
//
//nolint:testpackage // exercises unexported helpers
package tokenexchange

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/op/store"
)

// fixtureLeafCertDER is a minimal DER blob that mtls.Thumbprint will
// hash. The bytes are not parsed as a real cert anywhere in this
// package — Thumbprint reads cert.Raw verbatim — so a fabricated
// payload is sufficient to exercise the SHA-256 path.
var fixtureLeafCertDER = []byte("test-cert-raw-bytes-for-thumbprint")

// fixtureLeafCert returns an x509.Certificate whose Raw field carries
// fixtureLeafCertDER so mtls.Thumbprint produces a deterministic
// thumbprint. The other certificate fields are zero — none of the
// thumbprint paths consult them.
func fixtureLeafCert() *x509.Certificate {
	return &x509.Certificate{Raw: append([]byte(nil), fixtureLeafCertDER...)}
}

func TestBuildCnfClaim_DPoPOnly(t *testing.T) {
	t.Parallel()
	req := customgrant.Request{DPoPJKT: "abc-jkt"}
	got := buildCnfClaim(req)
	if got == nil {
		t.Fatalf("buildCnfClaim = nil, want cnf.jkt")
	}
	if got["jkt"] != "abc-jkt" {
		t.Errorf("cnf.jkt=%q, want %q", got["jkt"], "abc-jkt")
	}
	if _, present := got["x5t#S256"]; present {
		t.Errorf("cnf.x5t#S256 present alongside cnf.jkt: %v", got)
	}
}

func TestBuildCnfClaim_MTLSOnly(t *testing.T) {
	t.Parallel()
	cert := fixtureLeafCert()
	req := customgrant.Request{MTLSCert: cert}
	got := buildCnfClaim(req)
	if got == nil {
		t.Fatalf("buildCnfClaim = nil, want cnf.x5t#S256")
	}
	wantThumb := mtls.Thumbprint(cert)
	if got["x5t#S256"] != wantThumb {
		t.Errorf("cnf.x5t#S256=%q, want %q", got["x5t#S256"], wantThumb)
	}
	if _, present := got["jkt"]; present {
		t.Errorf("cnf.jkt present alongside cnf.x5t#S256: %v", got)
	}
}

func TestBuildCnfClaim_DPoPWinsOverMTLS(t *testing.T) {
	t.Parallel()
	// FAPI 2.0 collapses dual-binding requests to DPoP at the access-
	// token layer; the id_token MUST follow the same precedence so the
	// two carriers do not diverge.
	req := customgrant.Request{
		DPoPJKT:  "win-jkt",
		MTLSCert: fixtureLeafCert(),
	}
	got := buildCnfClaim(req)
	if got == nil {
		t.Fatalf("buildCnfClaim = nil, want cnf.jkt (DPoP wins)")
	}
	if got["jkt"] != "win-jkt" {
		t.Errorf("cnf.jkt=%q, want %q", got["jkt"], "win-jkt")
	}
	if _, present := got["x5t#S256"]; present {
		t.Errorf("cnf carries x5t#S256 even though DPoP was present: %v", got)
	}
}

func TestBuildCnfClaim_BearerReturnsNil(t *testing.T) {
	t.Parallel()
	got := buildCnfClaim(customgrant.Request{})
	if got != nil {
		t.Errorf("buildCnfClaim = %v, want nil for unbound request", got)
	}
}

func TestBuildCnfClaim_EmptyMTLSCertRawReturnsNil(t *testing.T) {
	t.Parallel()
	// A Raw-empty cert is the corner case mtls.Thumbprint guards: a
	// zero-length DER blob produces a meaningless hash. The helper
	// MUST return nil so the id_token does not surface a synthesised
	// cnf the access-token side would never carry.
	req := customgrant.Request{MTLSCert: &x509.Certificate{}}
	got := buildCnfClaim(req)
	if got != nil {
		t.Errorf("buildCnfClaim = %v, want nil for cert with empty Raw", got)
	}
}

// TestAssembleResponse_IDTokenCarriesCnfWhenDPoPBound pins the
// integration: when the policy emits an openid-scoped exchange and the
// request carries a verified DPoP proof, the id_token claim map MUST
// include cnf.jkt matching the request's thumbprint. The access-token
// cnf is stamped by the wire layer (internal/tokenendpoint/binding.go);
// this test is the id_token-side guarantee.
func TestAssembleResponse_IDTokenCarriesCnfWhenDPoPBound(t *testing.T) {
	t.Parallel()
	h := newAssembleHandler(t)
	req := customgrant.Request{
		Client:  &store.Client{ID: "caller"},
		DPoPJKT: "dpop-jkt-value",
	}
	subjectView := TokenView{Subject: "user-1"}
	resp := h.assembleResponse(
		req, subjectView,
		[]string{"openid", "read"}, // grantedScope
		nil,                        // grantedAudience
		time.Minute,                // ttl
		nil,                        // actChain
		nil,                        // extraClaims
		true,                       // issueIDToken
	)
	cnf, ok := resp.ExtraClaims["cnf"].(map[string]string)
	if !ok {
		t.Fatalf("id_token ExtraClaims missing cnf map: ExtraClaims=%v", resp.ExtraClaims)
	}
	if cnf["jkt"] != "dpop-jkt-value" {
		t.Errorf("id_token cnf.jkt=%q, want %q", cnf["jkt"], "dpop-jkt-value")
	}
}

// TestAssembleResponse_IDTokenCarriesCnfWhenMTLSBound is the mTLS
// twin of the DPoP case. The thumbprint is computed via the same
// helper the access-token wire mint uses so the two carriers agree
// byte-for-byte.
func TestAssembleResponse_IDTokenCarriesCnfWhenMTLSBound(t *testing.T) {
	t.Parallel()
	h := newAssembleHandler(t)
	cert := fixtureLeafCert()
	req := customgrant.Request{
		Client:   &store.Client{ID: "caller"},
		MTLSCert: cert,
	}
	subjectView := TokenView{Subject: "user-1"}
	resp := h.assembleResponse(
		req, subjectView,
		[]string{"openid", "read"},
		nil, time.Minute, nil, nil, true,
	)
	cnf, ok := resp.ExtraClaims["cnf"].(map[string]string)
	if !ok {
		t.Fatalf("id_token ExtraClaims missing cnf map: ExtraClaims=%v", resp.ExtraClaims)
	}
	wantThumb := mtls.Thumbprint(cert)
	if cnf["x5t#S256"] != wantThumb {
		t.Errorf("id_token cnf.x5t#S256=%q, want %q", cnf["x5t#S256"], wantThumb)
	}
}

// TestAssembleResponse_IDTokenOmitsCnfWhenUnbound pins the negative:
// a bearer request MUST NOT see a cnf claim on the issued id_token.
// Polluting an unbound id_token with a synthesised cnf would mislead
// downstream verifiers into expecting proof-of-possession the token
// holder cannot supply.
func TestAssembleResponse_IDTokenOmitsCnfWhenUnbound(t *testing.T) {
	t.Parallel()
	h := newAssembleHandler(t)
	req := customgrant.Request{Client: &store.Client{ID: "caller"}}
	subjectView := TokenView{Subject: "user-1"}
	resp := h.assembleResponse(
		req, subjectView,
		[]string{"openid", "read"},
		nil, time.Minute, nil, nil, true,
	)
	if _, present := resp.ExtraClaims["cnf"]; present {
		t.Errorf("unbound id_token carries cnf=%v; want absent", resp.ExtraClaims["cnf"])
	}
}

// TestAssembleResponse_HandlerInjectedCnfStripped pins the reserved-
// claim filter against an embedder attempting to inject a forged cnf
// via the policy decision's ExtraClaims. The OP-built cnf (from the
// request's verified binding) MUST win, and the forged value MUST NOT
// appear under any key.
func TestAssembleResponse_HandlerInjectedCnfStripped(t *testing.T) {
	t.Parallel()
	h := newAssembleHandler(t)
	req := customgrant.Request{
		Client:  &store.Client{ID: "caller"},
		DPoPJKT: "real-jkt",
	}
	subjectView := TokenView{Subject: "user-1"}
	forged := map[string]any{
		"cnf": map[string]string{"jkt": "forged-jkt"},
	}
	resp := h.assembleResponse(
		req, subjectView,
		[]string{"openid", "read"},
		nil, time.Minute, nil, forged, true,
	)
	cnf, ok := resp.ExtraClaims["cnf"].(map[string]string)
	if !ok {
		t.Fatalf("id_token ExtraClaims missing cnf map: ExtraClaims=%v", resp.ExtraClaims)
	}
	if cnf["jkt"] == "forged-jkt" {
		t.Errorf("forged cnf.jkt survived reserved-claim filter: %v", cnf)
	}
	if cnf["jkt"] != "real-jkt" {
		t.Errorf("id_token cnf.jkt=%q, want %q", cnf["jkt"], "real-jkt")
	}
}

// newAssembleHandler builds a Handler suitable for assembleResponse-
// only tests. The clock is fixed so resp.AuthTime is deterministic;
// the keyset and audit fields are unused on the assemble path.
func newAssembleHandler(_ *testing.T) *Handler {
	return &Handler{
		clock: fixedClock{now: time.Unix(1_700_000_000, 0).UTC()},
	}
}

// fixedClock is the minimal Clock the Handler.now method consults.
type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }
