package scenarios_test

import (
	"strings"
	"testing"
)

// mtlsPairwiseCases is a pairwise covering set over endpoint × method ×
// topology × certificate validity × matcher kind, generated under the
// constraints that only tls_client_auth carries a matcher kind and an
// untrusted proxy source exists only on the proxy topology.
var mtlsPairwiseCases = []string{
	"token tls direct valid subject_dn",
	"token self proxy mismatch -",
	"par tls proxy unverified san_dns",
	"par self direct nocert -",
	"introspect tls direct mismatch san_uri",
	"revoke tls proxy nocert san_ip",
	"ciba tls proxy untrusted_proxy san_email",
	"introspect self proxy valid -",
	"revoke self direct unverified -",
	"device tls direct valid san_dns",
	"device self proxy untrusted_proxy -",
	"grantmgmt tls direct valid san_ip",
	"grantmgmt tls proxy mismatch subject_dn",
	"token tls direct unverified san_email",
	"token tls proxy nocert san_uri",
	"ciba tls direct valid san_uri",
	"token tls proxy untrusted_proxy san_dns",
	"par tls direct valid san_email",
	"par tls direct mismatch san_ip",
	"par tls proxy untrusted_proxy subject_dn",
	"introspect tls direct unverified subject_dn",
	"introspect tls direct nocert san_dns",
	"introspect tls proxy untrusted_proxy san_ip",
	"revoke tls direct mismatch san_dns",
	"revoke tls proxy untrusted_proxy san_uri",
	"ciba tls direct unverified san_ip",
	"ciba tls direct nocert subject_dn",
	"ciba self direct mismatch -",
	"device tls direct mismatch san_email",
	"device tls direct unverified san_uri",
	"grantmgmt tls direct nocert san_email",
	"grantmgmt self direct unverified -",
	"revoke tls direct valid subject_dn",
	"device tls direct nocert subject_dn",
	"grantmgmt tls proxy untrusted_proxy san_dns",
	"token tls direct valid san_ip",
	"par tls direct valid san_uri",
	"introspect tls direct valid san_email",
	"revoke tls direct valid san_email",
	"ciba tls direct valid san_dns",
	"device tls direct valid san_ip",
	"grantmgmt tls direct valid san_uri",
}

// TestMTLSClientAuth_EndpointMatrix drives RFC 8705 §2 client
// authentication through every client-authenticating endpoint. A full
// grid proves each endpoint × method × topology authenticates a valid
// certificate (and, at /token, binds the access token to it); the
// pairwise set adds the negatives: wrong SAN / subject, a key outside the
// JWKS, an unverified chain under tls_client_auth, no certificate, and a
// forwarded header from an untrusted source.
func TestMTLSClientAuth_EndpointMatrix(t *testing.T) {
	t.Parallel()
	f := newMTLSFixture(t)

	cases := make([]mtlsCase, 0, 28+len(mtlsPairwiseCases))
	for i, endpoint := range []string{"token", "par", "introspect", "revoke", "ciba", "device", "grantmgmt"} {
		for _, method := range []string{"tls", "self"} {
			for j, topology := range []string{"direct", "proxy"} {
				matcher := "-"
				if method == "tls" {
					matcher = mtlsMatcherKinds[(i+j)%len(mtlsMatcherKinds)]
				}
				cases = append(cases, mtlsCase{endpoint, method, topology, mtlsValid, matcher})
			}
		}
	}
	for _, row := range mtlsPairwiseCases {
		v := strings.Fields(row)
		cases = append(cases, mtlsCase{v[0], v[1], v[2], v[3], v[4]})
	}
	for _, c := range cases {
		t.Run(strings.Join([]string{c.endpoint, c.method, c.topology, c.validity, c.matcher}, "/"), func(t *testing.T) {
			t.Parallel()
			f.run(t, c)
		})
	}
}

// TestMTLSClientAuth_SelfSignedRootCAsExemptionIsPerClient pins that
// op.WithMTLSRootCAs is waived only for a client registered for
// self_signed_tls_client_auth. Under the anchors, on both topologies, that
// client authenticates and binds its self-signed certificate; the same kind
// of certificate presented by a tls_client_auth client, or bound by a
// private_key_jwt client, is still refused.
func TestMTLSClientAuth_SelfSignedRootCAsExemptionIsPerClient(t *testing.T) {
	t.Parallel()
	f := newMTLSFixture(t)
	// A self-signed certificate carrying the tls_client_auth client's
	// matcher values: only its chain is wrong.
	forged := mtlsSelfSigned(t, "pki-san-dns")
	issued := f.pki.leafFor(t, "pki-san-dns")

	for name, topo := range map[string]mtlsTopology{"direct": f.directRoots, "proxy": f.proxyPKI} {
		srv := topo.requesting
		t.Run(name+"/self_signed client", func(t *testing.T) {
			t.Parallel()
			res := topo.send(t, mtlsEndpointRequest(t, "token", topo.base(srv), mtlsSelfClientID), srv, &f.selfCert)
			mtlsAssertAuthenticated(t, "token", res, &f.selfCert)
		})
		t.Run(name+"/tls_client_auth client", func(t *testing.T) {
			t.Parallel()
			res := topo.send(t, mtlsEndpointRequest(t, "token", topo.base(srv), "pki-san-dns"), srv, &forged)
			mtlsAssertInvalidClient(t, res)
		})
		t.Run(name+"/private_key_jwt client, self-signed certificate", func(t *testing.T) {
			t.Parallel()
			res := topo.send(t, f.pkjwtTokenRequest(t, topo.base(srv)), srv, &f.selfCert)
			mtlsAssertInvalidClient(t, res)
		})
		t.Run(name+"/private_key_jwt client, issued certificate", func(t *testing.T) {
			t.Parallel()
			res := topo.send(t, f.pkjwtTokenRequest(t, topo.base(srv)), srv, &issued)
			mtlsAssertAuthenticated(t, "token", res, &issued)
		})
	}
}

// TestMTLSClientAuth_SelfSignedWithoutRootCAs keeps the anchor-free
// direct deployment covered now that the matrix runs self-signed clients
// under op.WithMTLSRootCAs.
func TestMTLSClientAuth_SelfSignedWithoutRootCAs(t *testing.T) {
	t.Parallel()
	f := newMTLSFixture(t)
	srv := f.direct.requesting
	res := f.direct.send(t, mtlsEndpointRequest(t, "token", srv.URL, mtlsSelfClientID), srv, &f.selfCert)
	mtlsAssertAuthenticated(t, "token", res, &f.selfCert)
	res = f.direct.send(t, mtlsEndpointRequest(t, "token", srv.URL, mtlsSelfClientID), srv, &f.otherSelf)
	mtlsAssertInvalidClient(t, res)
}
