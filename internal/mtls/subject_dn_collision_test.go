package mtls_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// TestVerifyTLSClientAuth_SubjectDN_CraftedNameDoesNotCollideOnceRendered
// pins that a certificate is identified by the bytes its issuer signed,
// not by how those bytes look once printed.
//
// A distinguished name is a structure — a sequence of typed attributes
// — and RFC 4514 defines a reversible text form for it. The text form
// needs escapes precisely because attribute values may contain the very
// characters that separate attributes, and an implementation that
// compares the rendered strings while splitting on those characters
// reads a boundary that is not there. The result is that a value the
// requester chose (a CN they were issued) is read as structure they did
// not have, and a certificate the truststore legitimately trusts starts
// naming somebody else.
//
// This is only reachable where the truststore is broad — an internal
// CA that will issue a certificate to anyone in the organisation, with
// the subject DN as the whole of the identity. That is the common
// enterprise mTLS deployment, so the DN comparison has to be exact at
// the encoding level rather than the display level.
//
// Tracks: CVE-2026-22747 (Spring Security) — SubjectX500PrincipalExtractor
// mishandled certain malformed CN values and read the wrong value as
// the username, letting a crafted certificate impersonate another user.
// CVE-2026-47838 is the continuation covering the same defect in the
// deprecated SubjectDnX509PrincipalExtractor.
func TestVerifyTLSClientAuth_SubjectDN_CraftedNameDoesNotCollideOnceRendered(t *testing.T) {
	t.Parallel()

	// The registered identity the attacker wants to reach.
	const registered = "CN=rp.example,O=Example Org"

	cases := []struct {
		name string
		// subject is the DN actually placed in the attacker's
		// certificate. Each is a single attribute whose *value*
		// contains the separators that would make it read as several
		// attributes if the comparison parsed the rendered text.
		subject pkix.Name
	}{
		{
			// CN literally contains "rp.example,O=Example Org".
			// RFC 4514 renders it as CN=rp.example\,O\=Example Org;
			// unescaping-then-splitting yields the registered DN.
			name: "separators inside the common name",
			subject: pkix.Name{
				CommonName: "rp.example,O=Example Org",
			},
		},
		{
			// The same trick with the escape character itself, so a
			// comparison that strips one level of backslashes lands on
			// the registered spelling.
			name: "escaped escape before the separator",
			subject: pkix.Name{
				CommonName: `rp.example\,O\=Example Org`,
			},
		},
		{
			// A trailing attribute smuggled into the organisation
			// value rather than the common name.
			name: "separators inside the organisation",
			subject: pkix.Name{
				CommonName:   "rp.example",
				Organization: []string{"Example Org,CN=admin"},
			},
		},
		{
			// Leading and trailing whitespace is insignificant in some
			// DN renderings and significant in others, which is
			// exactly the kind of disagreement a text comparison
			// inherits.
			name: "padded common name",
			subject: pkix.Name{
				CommonName:   " rp.example ",
				Organization: []string{"Example Org"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cert := generateLeafWith(t, func(c *x509.Certificate) {
				c.Subject = tc.subject
			})
			err := mtls.VerifyTLSClientAuth(cert, mtls.ClientMatcher{SubjectDN: registered})
			if !errors.Is(err, mtls.ErrSubjectMismatch) {
				t.Fatalf("certificate with subject %+v authenticated as %q: err=%v, want ErrSubjectMismatch",
					tc.subject, registered, err)
			}
		})
	}

	// The control: the genuinely matching DN still authenticates, so
	// the refusals above are about the crafted names and not about the
	// matcher having stopped working.
	t.Run("the registered DN still authenticates", func(t *testing.T) {
		t.Parallel()

		cert := generateLeafWith(t, func(c *x509.Certificate) {
			c.Subject = pkix.Name{
				CommonName:   "rp.example",
				Organization: []string{"Example Org"},
			}
		})
		if err := mtls.VerifyTLSClientAuth(cert, mtls.ClientMatcher{SubjectDN: registered}); err != nil {
			t.Fatalf("the registered DN was refused: %v", err)
		}
	})
}
