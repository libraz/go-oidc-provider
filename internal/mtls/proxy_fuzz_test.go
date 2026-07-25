package mtls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// FuzzCertificateFromHeader exercises the proxy-header decode path of
// [mtls.CertificateFromRequest] with arbitrary header payloads. The
// harness asserts five structural invariants:
//
//  1. CertificateFromRequest never panics, regardless of input.
//  2. The result is exactly one of (cert, nil) or (nil, error) — never
//     (nil, nil) and never (cert, err). Both forbidden shapes would let
//     callers mistake "no cert" for "valid cert" or vice versa.
//  3. Every error returned MUST wrap [mtls.ErrNoClientCert] or
//     [mtls.ErrCertMalformed]. A naked third-party error class would
//     mean the HTTP layer's wire-code mapping silently degrades.
//  4. On success the returned cert MUST have a non-empty Raw byte slice
//     so downstream thumbprint computation is well-defined.
//  5. A payload carrying more than one PEM block MUST NOT succeed. The
//     forwarding contract is one field, one certificate; anything else
//     leaves the choice of leaf to whoever composed the header. The
//     invariant is stated over the payload as received because none of
//     the accepted decodings can erase a literal block marker — they
//     only shorten the bytes around it.
//
// Seed rationale:
//   - empty header: the not-present path; ErrNoClientCert.
//   - canonical PEM (built once from a fresh ECDSA key): success path.
//   - URL-encoded canonical PEM: nginx ssl_client_escaped_cert shape.
//   - PEM with trailing garbage: ErrCertMalformed; ambiguous suffixes
//     must not be ignored on a security-sensitive identity header.
//   - two concatenated PEM blocks, raw and URL-encoded: the chain
//     shape, from which no leaf may be selected.
//   - PEM with a wrong type ("PRIVATE KEY"): ErrCertMalformed.
//   - "not a pem block": ErrCertMalformed.
//   - 4 KiB of "A": oversize garbage; must not allocate-and-crash.
//   - PEM with embedded NUL bytes inside the base64 body: malformed.
func FuzzCertificateFromHeader(f *testing.F) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz.invalid"},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		f.Fatalf("CreateCertificate: %v", err)
	}
	goodPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	wrongType := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-key")}))
	bigBlob := make([]byte, 4*1024)
	for i := range bigBlob {
		bigBlob[i] = 'A'
	}

	f.Add("")
	f.Add(goodPEM)
	f.Add(url.QueryEscape(goodPEM))
	f.Add(goodPEM + "\ntrailing garbage\n")
	f.Add(goodPEM + goodPEM)
	f.Add(url.QueryEscape(goodPEM + goodPEM))
	f.Add(wrongType)
	f.Add("not a pem block")
	f.Add(string(bigBlob))
	f.Add("-----BEGIN CERTIFICATE-----\nAAAA\x00BBBB\n-----END CERTIFICATE-----\n")

	f.Fuzz(func(t *testing.T, header string) {
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"https://op.example/token",
			http.NoBody,
		)
		// Header.Set rejects values containing NUL or CR/LF, so write
		// directly into the underlying map to keep the fuzz body
		// permissive — the parser is what we want to exercise.
		req.Header[http.CanonicalHeaderKey("X-Client-Cert")] = []string{header}

		cert, err := mtls.CertificateFromRequest(req, mtls.ProxyConfig{
			HeaderName:     "X-Client-Cert",
			TrustedProxies: mustParsePrefixes(t, "192.0.2.0/24"),
		})
		if err != nil {
			if cert != nil {
				t.Fatalf("CertificateFromRequest returned non-nil cert alongside error %v", err)
			}
			switch {
			case errors.Is(err, mtls.ErrNoClientCert),
				errors.Is(err, mtls.ErrCertMalformed):
				// allowed
			default:
				t.Fatalf("CertificateFromRequest returned unrecognised error class: %v", err)
			}
			return
		}

		// Success path. cert must be populated and have raw DER bytes.
		if cert == nil {
			t.Fatalf("CertificateFromRequest returned (nil, nil) — forbidden shape")
		}
		if len(cert.Raw) == 0 {
			t.Fatalf("CertificateFromRequest returned cert with empty Raw bytes")
		}
		if n := strings.Count(header, "-----BEGIN "); n > 1 {
			t.Fatalf("CertificateFromRequest accepted a payload carrying %d PEM blocks", n)
		}
	})
}
