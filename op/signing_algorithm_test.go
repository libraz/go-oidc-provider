package op_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// testRSAKeys generates each RSA size at most once per test binary; RSA
// generation dominates the cost of every test that needs one.
var testRSAKeys = map[int]func() (*rsa.PrivateKey, error){
	2047: sync.OnceValues(func() (*rsa.PrivateKey, error) {
		return rsa.GenerateKey(rand.Reader, 2047) //nolint:gosec // deliberately below the 2048-bit floor
	}),
	2048: sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }),
	4096: sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 4096) }),
}

// testRSAKey returns the shared RSA key of the given size.
func testRSAKey(tb testing.TB, bits int) *rsa.PrivateKey {
	tb.Helper()
	gen, ok := testRSAKeys[bits]
	if !ok {
		tb.Fatalf("no shared RSA key of %d bits", bits)
	}
	k, err := gen()
	if err != nil {
		tb.Fatalf("generate RSA %d: %v", bits, err)
	}
	return k
}

func newRSATestKey(tb testing.TB, kid string, bits int) op.SigningKey {
	tb.Helper()
	return op.SigningKey{KeyID: kid, Signer: testRSAKey(tb, bits)}
}

func newP384TestKey(tb testing.TB, kid string) op.SigningKey {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate P-384: %v", err)
	}
	return op.SigningKey{KeyID: kid, Signer: priv}
}

func newEd25519TestKey(tb testing.TB, kid string) op.SigningKey {
	tb.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("generate Ed25519: %v", err)
	}
	return op.SigningKey{KeyID: kid, Signer: priv}
}

// opaqueSigner exposes a public key of a type no JWS algorithm uses.
type opaqueSigner struct{}

func (opaqueSigner) Public() crypto.PublicKey { return "opaque" }

func (opaqueSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("opaqueSigner cannot sign")
}

// retiring returns k with a NotAfter far beyond any clock the tests run.
func retiring(k op.SigningKey) op.SigningKey {
	k.NotAfter = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	return k
}

// wantConfigurationError asserts err is a configuration_error whose
// description contains want.
func wantConfigurationError(t *testing.T, err error, want string) {
	t.Helper()
	var opErr *op.Error
	if !errors.As(err, &opErr) {
		t.Fatalf("err = %v, want *op.Error", err)
	}
	if opErr.Code != "configuration_error" {
		t.Fatalf("code = %q, want configuration_error (err %v)", opErr.Code, err)
	}
	if !strings.Contains(opErr.Description, want) {
		t.Fatalf("description = %q, want it to contain %q", opErr.Description, want)
	}
}

func TestWithSigningAlgorithm(t *testing.T) {
	t.Parallel()

	es := func(kid string) op.SigningKey { return newTestKey(t, kid) }
	rs := func(kid string) op.SigningKey { return newRSATestKey(t, kid, 2048) }

	type signingAlgCase struct {
		name   string
		opts   func() []op.Option
		wantIs error
		want   string // empty means New succeeds
	}
	fapiCase := func(p profile.Profile) signingAlgCase {
		return signingAlgCase{
			name: "RS256 with " + p.String(),
			opts: func() []op.Option {
				return []op.Option{
					op.WithSigningAlgorithm(op.AlgRS256),
					op.WithKeyset(op.Keyset{rs("rsa")}),
					op.WithProfile(p),
				}
			},
			want: "WithProfile " + p.String() + " does not permit WithSigningAlgorithm(RS256); " +
				"FAPI 2.0 Security Profile §5.4.1 allows PS256, ES256 or EdDSA",
		}
	}
	cases := []signingAlgCase{
		{
			name: "unset defaults to ES256",
			opts: func() []op.Option { return []op.Option{op.WithKeyset(op.Keyset{es("ec")})} },
		},
		{
			name: "explicit ES256",
			opts: func() []op.Option {
				return []op.Option{op.WithSigningAlgorithm(op.AlgES256), op.WithKeyset(op.Keyset{es("ec")})}
			},
		},
		{
			name: "RS256 with RSA 2048",
			opts: func() []op.Option {
				return []op.Option{op.WithSigningAlgorithm(op.AlgRS256), op.WithKeyset(op.Keyset{rs("rsa")})}
			},
		},
		{
			name: "RS256 with RSA 4096",
			opts: func() []op.Option {
				return []op.Option{
					op.WithSigningAlgorithm(op.AlgRS256),
					op.WithKeyset(op.Keyset{newRSATestKey(t, "rsa", 4096)}),
				}
			},
		},
		{name: "empty value", opts: algOnly(""), want: `WithSigningAlgorithm: unsupported algorithm ""; use AlgES256 or AlgRS256`},
		{name: "PS256", opts: algOnly("PS256"), want: `WithSigningAlgorithm: unsupported algorithm "PS256"; use AlgES256 or AlgRS256`},
		{name: "EdDSA", opts: algOnly("EdDSA"), want: `WithSigningAlgorithm: unsupported algorithm "EdDSA"; use AlgES256 or AlgRS256`},
		{name: "none", opts: algOnly("none"), want: `WithSigningAlgorithm: unsupported algorithm "none"; use AlgES256 or AlgRS256`},
		{name: "lower case", opts: algOnly("rs256"), want: `WithSigningAlgorithm: unsupported algorithm "rs256"; use AlgES256 or AlgRS256`},
		{name: "full width", opts: algOnly("ＲＳ256"), want: `WithSigningAlgorithm: unsupported algorithm "ＲＳ256"; use AlgES256 or AlgRS256`},
		{
			name: "twice with the same value",
			opts: func() []op.Option {
				return []op.Option{op.WithSigningAlgorithm(op.AlgES256), op.WithSigningAlgorithm(op.AlgES256)}
			},
			want: "WithSigningAlgorithm may be called at most once",
		},
		{
			name: "twice with different values",
			opts: func() []op.Option {
				return []op.Option{
					op.WithSigningAlgorithm(op.AlgRS256),
					op.WithKeyset(op.Keyset{rs("rsa")}),
					op.WithSigningAlgorithm(op.AlgES256),
				}
			},
			want: "WithSigningAlgorithm may be called at most once",
		},
		{
			name:   "empty keyset",
			opts:   func() []op.Option { return []op.Option{op.WithKeyset(op.Keyset{})} },
			wantIs: op.ErrKeysetRequired,
		},
		{
			name: "ES256 with an RSA active key",
			opts: func() []op.Option { return []op.Option{op.WithKeyset(op.Keyset{rs("rsa")})} },
			want: "keyset entry rsa is RSA 2048 bits; the OP signs with ES256, which requires ECDSA P-256 for the active key",
		},
		{
			name: "RS256 with a P-256 active key",
			opts: func() []op.Option {
				return []op.Option{op.WithSigningAlgorithm(op.AlgRS256), op.WithKeyset(op.Keyset{es("ec")})}
			},
			want: "keyset entry ec is ECDSA P-256; the OP signs with RS256, which requires RSA of 2048 bits or more for the active key",
		},
		{
			name: "P-384 active key",
			opts: func() []op.Option { return []op.Option{op.WithKeyset(op.Keyset{newP384TestKey(t, "p384")})} },
			want: "keyset entry p384 is ECDSA P-384; the OP signs with ES256, which requires ECDSA P-256 for the active key",
		},
		{
			name: "Ed25519 active key",
			opts: func() []op.Option { return []op.Option{op.WithKeyset(op.Keyset{newEd25519TestKey(t, "ed")})} },
			want: "keyset entry ed is Ed25519; the OP signs with ES256, which requires ECDSA P-256 for the active key",
		},
		{
			name: "unsupported key type",
			opts: func() []op.Option {
				return []op.Option{op.WithKeyset(op.Keyset{{KeyID: "opaque", Signer: opaqueSigner{}}})}
			},
			want: "keyset entry opaque is an unsupported key type; the OP signs with ES256, which requires ECDSA P-256 for the active key",
		},
		{
			name: "RS256 with RSA 2047",
			opts: func() []op.Option {
				return []op.Option{
					op.WithSigningAlgorithm(op.AlgRS256),
					op.WithKeyset(op.Keyset{newRSATestKey(t, "rsa", 2047)}),
				}
			},
			want: "keyset entry rsa is RSA 2047 bits; the OP signs with RS256, which requires RSA of 2048 bits or more for the active key",
		},
		{
			name: "RS256 with a retiring P-256 key",
			opts: func() []op.Option {
				return []op.Option{
					op.WithSigningAlgorithm(op.AlgRS256),
					op.WithKeyset(op.Keyset{rs("rsa"), retiring(es("ec"))}),
				}
			},
		},
		{
			name: "RS256 with a P-256 key lacking NotAfter",
			opts: func() []op.Option {
				return []op.Option{
					op.WithSigningAlgorithm(op.AlgRS256),
					op.WithKeyset(op.Keyset{rs("rsa"), es("ec")}),
				}
			},
			want: "keyset entry ec is ECDSA P-256 but the OP signs with RS256; a key of the other type must set NotAfter",
		},
		{
			name: "RS256 with a retiring P-384 key",
			opts: func() []op.Option {
				return []op.Option{
					op.WithSigningAlgorithm(op.AlgRS256),
					op.WithKeyset(op.Keyset{rs("rsa"), retiring(newP384TestKey(t, "p384"))}),
				}
			},
			want: "keyset entry p384 is ECDSA P-384; only ECDSA P-256 and RSA of 2048 bits or more are accepted",
		},
		{
			name: "retiring RSA 2047",
			opts: func() []op.Option {
				return []op.Option{op.WithKeyset(op.Keyset{es("ec"), retiring(newRSATestKey(t, "rsa", 2047))})}
			},
			want: "keyset entry rsa is RSA 2047 bits; only ECDSA P-256 and RSA of 2048 bits or more are accepted",
		},
		{
			name: "ES256 with a retiring RSA key",
			opts: func() []op.Option {
				return []op.Option{op.WithKeyset(op.Keyset{es("ec"), retiring(rs("rsa"))})}
			},
		},
		{
			name: "ES256 with an RSA key lacking NotAfter",
			opts: func() []op.Option { return []op.Option{op.WithKeyset(op.Keyset{es("ec"), rs("rsa")})} },
			want: "keyset entry rsa is RSA 2048 bits but the OP signs with ES256; a key of the other type must set NotAfter",
		},
		{
			name: "RS256 with Baseline",
			opts: func() []op.Option {
				return []op.Option{
					op.WithSigningAlgorithm(op.AlgRS256),
					op.WithKeyset(op.Keyset{rs("rsa")}),
					op.WithProfile(profile.Baseline),
				}
			},
		},
		fapiCase(profile.FAPI2Baseline),
		fapiCase(profile.FAPI2MessageSigning),
		fapiCase(profile.FAPICIBA),
	}

	for _, tc := range cases {
		// Built here so key generation fails the parent test, not a subtest.
		opts := tc.opts()
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := op.New(append(validBaseOptsWithInmem(t), opts...)...)
			switch {
			case tc.wantIs != nil:
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("New = %v, want %v", err, tc.wantIs)
				}
			case tc.want == "":
				if err != nil {
					t.Fatalf("New: %v", err)
				}
			default:
				wantConfigurationError(t, err, tc.want)
			}
		})
	}
}

// algOnly returns an option list that sets only the algorithm.
func algOnly(alg string) func() []op.Option {
	return func() []op.Option { return []op.Option{op.WithSigningAlgorithm(op.SigningAlgorithm(alg))} }
}

func TestWithEncryptionKeyset_RejectsSigningKeyReuse(t *testing.T) {
	t.Parallel()

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256: %v", err)
	}
	otherEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256: %v", err)
	}
	rsaKey := testRSAKey(t, 2048)

	cases := []struct {
		name    string
		alg     op.SigningAlgorithm
		signing op.Keyset
		enc     op.EncryptionKeyset
		want    string
	}{
		{
			name:    "same RSA key",
			alg:     op.AlgRS256,
			signing: op.Keyset{{KeyID: "sig", Signer: rsaKey}},
			enc:     op.EncryptionKeyset{{KeyID: "enc", PrivateKey: rsaKey}},
			want:    "WithEncryptionKeyset entry enc reuses the public key of signing key sig; signing and encryption keys must be distinct",
		},
		{
			name:    "same EC key",
			alg:     op.AlgES256,
			signing: op.Keyset{{KeyID: "sig", Signer: ec}},
			enc:     op.EncryptionKeyset{{KeyID: "enc", PrivateKey: ec}},
			want:    "WithEncryptionKeyset entry enc reuses the public key of signing key sig; signing and encryption keys must be distinct",
		},
		{
			name:    "same key as a retiring signing key",
			alg:     op.AlgES256,
			signing: op.Keyset{{KeyID: "sig", Signer: otherEC}, retiring(op.SigningKey{KeyID: "old", Signer: rsaKey})},
			enc:     op.EncryptionKeyset{{KeyID: "enc", PrivateKey: rsaKey}},
			want:    "WithEncryptionKeyset entry enc reuses the public key of signing key old; signing and encryption keys must be distinct",
		},
		{
			name:    "distinct keys",
			alg:     op.AlgES256,
			signing: op.Keyset{{KeyID: "sig", Signer: ec}},
			enc:     op.EncryptionKeyset{{KeyID: "enc", PrivateKey: otherEC}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := op.New(append(validBaseOptsWithInmem(t),
				op.WithSigningAlgorithm(tc.alg),
				op.WithKeyset(tc.signing),
				op.WithEncryptionKeyset(tc.enc),
			)...)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				return
			}
			wantConfigurationError(t, err, tc.want)
		})
	}
}

func TestAuditStartupProfile_SigningAlg(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		opts []op.Option
		want string
	}{
		{name: "default", want: "ES256"},
		{
			name: "RS256",
			opts: []op.Option{
				op.WithSigningAlgorithm(op.AlgRS256),
				op.WithKeyset(op.Keyset{newRSATestKey(t, "rsa", 2048)}),
			},
			want: "RS256",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := captureStartupProfile(t, tc.opts...)
			if got := rec.Extras["signing_alg"]; got != tc.want {
				t.Fatalf("signing_alg = %v, want %s", got, tc.want)
			}
		})
	}
}
