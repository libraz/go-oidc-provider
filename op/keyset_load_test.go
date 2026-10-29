package op_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

func klWrite(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func klECKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return k
}

func klPEM(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func klPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	return der
}

// klECJWK renders an EC private JWK; an empty kid omits the member.
func klECJWK(t *testing.T, k *ecdsa.PrivateKey, kid string) (body []byte, d string) {
	t.Helper()
	pub, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("public bytes: %v", err)
	}
	priv, err := k.Bytes()
	if err != nil {
		t.Fatalf("private bytes: %v", err)
	}
	size := len(priv)
	enc := base64.RawURLEncoding
	m := map[string]string{
		"kty": "EC",
		"crv": k.Curve.Params().Name,
		"x":   enc.EncodeToString(pub[1 : 1+size]),
		"y":   enc.EncodeToString(pub[1+size:]),
		"d":   enc.EncodeToString(priv),
	}
	if kid != "" {
		m["kid"] = kid
	}
	body, err = json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal JWK: %v", err)
	}
	return body, m["d"]
}

// klThumbprint is RFC 7638 section 3: the required members in
// lexicographic order, no whitespace, SHA-256, base64url without padding.
func klThumbprint(k *ecdsa.PrivateKey) string {
	raw, err := k.PublicKey.Bytes()
	if err != nil || len(raw) != 65 {
		panic("klThumbprint: not an uncompressed P-256 point")
	}
	x, y := raw[1:33], raw[33:]
	members := `{"crv":"P-256","kty":"EC","x":"` + base64.RawURLEncoding.EncodeToString(x) +
		`","y":"` + base64.RawURLEncoding.EncodeToString(y) + `"}`
	sum := sha256.Sum256([]byte(members))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func klRequireConfigError(t *testing.T, err error, path string, forbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var oe *op.Error
	if !errors.As(err, &oe) {
		t.Fatalf("want *op.Error, got %T: %v", err, err)
	}
	if oe.Code != "configuration_error" {
		t.Fatalf("code = %q, want configuration_error", oe.Code)
	}
	if path != "" && !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q does not name %q", err.Error(), path)
	}
	for _, f := range forbidden {
		if f != "" && strings.Contains(err.Error(), f) {
			t.Fatalf("error leaks key material %q: %v", f, err)
		}
	}
}

func TestLoadSigningKey_Formats(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name  string
		enc   string
		curve string
		kid   bool
	}{
		{"pkcs8_p256", "pkcs8", "p256", false},
		{"pkcs8_p384", "pkcs8", "p384", false},
		{"pkcs8_rsa2048", "pkcs8", "rsa2048", false},
		{"sec1_p256", "sec1", "p256", false},
		{"sec1_p384", "sec1", "p384", false},
		{"jwk_p256", "jwk", "p256", false},
		{"jwk_p256_kid", "jwk", "p256", true},
		{"jwk_p384", "jwk", "p384", false},
		{"jwk_p384_kid", "jwk", "p384", true},
		{"jwk_rsa2048", "jwk", "rsa2048", false},
		{"jwk_rsa2048_kid", "jwk", "rsa2048", true},
		{"encrypted_p256", "encrypted", "p256", false},
		{"encrypted_p384", "encrypted", "p384", false},
		{"encrypted_rsa2048", "encrypted", "rsa2048", false},
		{"garbage_p256", "garbage", "p256", false},
	}
	const wantKid = "row-kid-1"

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			var (
				content  []byte
				fragment string
				ec       *ecdsa.PrivateKey
			)
			switch row.curve {
			case "p256":
				ec = klECKey(t, elliptic.P256())
			case "p384":
				ec = klECKey(t, elliptic.P384())
			}
			var rsaKey *rsa.PrivateKey
			if row.curve == "rsa2048" {
				var err error
				rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("generate RSA key: %v", err)
				}
			}
			var anyKey any = ec
			if rsaKey != nil {
				anyKey = rsaKey
			}
			kid := ""
			if row.kid {
				kid = wantKid
			}

			switch row.enc {
			case "pkcs8":
				der := klPKCS8(t, anyKey)
				content = klPEM("PRIVATE KEY", der)
				fragment = base64.StdEncoding.EncodeToString(der)[20:44]
			case "sec1":
				der, err := x509.MarshalECPrivateKey(ec)
				if err != nil {
					t.Fatalf("marshal SEC1: %v", err)
				}
				content = klPEM("EC PRIVATE KEY", der)
				fragment = base64.StdEncoding.EncodeToString(der)[20:44]
			case "jwk":
				if ec != nil {
					content, fragment = klECJWK(t, ec, kid)
				} else {
					m := map[string]string{
						"kty": "RSA",
						"n":   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
						"e":   "AQAB",
						"d":   base64.RawURLEncoding.EncodeToString(rsaKey.D.Bytes()),
					}
					if kid != "" {
						m["kid"] = kid
					}
					b, err := json.Marshal(m)
					if err != nil {
						t.Fatalf("marshal RSA JWK: %v", err)
					}
					content, fragment = b, m["d"]
				}
			case "encrypted":
				body := make([]byte, 64)
				if _, err := rand.Read(body); err != nil {
					t.Fatalf("rand: %v", err)
				}
				content = klPEM("ENCRYPTED PRIVATE KEY", body)
				fragment = base64.StdEncoding.EncodeToString(body)[20:44]
			case "garbage":
				content = []byte("this is not a key, merely some leftover text")
				fragment = "merely some leftover text"
			}

			path := klWrite(t, "key.txt", content)
			got, err := op.LoadSigningKey(path)

			wantOK := row.curve == "p256" && (row.enc == "pkcs8" || row.enc == "sec1" || row.enc == "jwk")
			if !wantOK {
				klRequireConfigError(t, err, path, fragment)
				return
			}
			if err != nil {
				t.Fatalf("LoadSigningKey: %v", err)
			}
			wantID := klThumbprint(ec)
			if row.kid {
				wantID = wantKid
			}
			if got.KeyID != wantID {
				t.Fatalf("KeyID = %q, want %q", got.KeyID, wantID)
			}
			if !got.NotAfter.IsZero() {
				t.Fatalf("NotAfter = %v, want zero", got.NotAfter)
			}
			loaded, ok := got.Signer.(*ecdsa.PrivateKey)
			if !ok || !loaded.Equal(ec) {
				t.Fatal("loaded signer is not the written key")
			}
		})
	}
}

func TestLoadSigningKey_Inputs(t *testing.T) {
	t.Parallel()

	ec := klECKey(t, elliptic.P256())
	jwk, d := klECJWK(t, ec, "")
	var pubOnly map[string]string
	if err := json.Unmarshal(jwk, &pubOnly); err != nil {
		t.Fatal(err)
	}
	delete(pubOnly, "d")
	pubJWK, err := json.Marshal(pubOnly)
	if err != nil {
		t.Fatal(err)
	}
	other := klECKey(t, elliptic.P256())
	otherJWK, _ := klECJWK(t, other, "")
	var mismatch map[string]string
	if err := json.Unmarshal(jwk, &mismatch); err != nil {
		t.Fatal(err)
	}
	var otherM map[string]string
	if err := json.Unmarshal(otherJWK, &otherM); err != nil {
		t.Fatal(err)
	}
	mismatch["x"], mismatch["y"] = otherM["x"], otherM["y"]
	mismatchJWK, err := json.Marshal(mismatch)
	if err != nil {
		t.Fatal(err)
	}
	var withKid map[string]string
	if err := json.Unmarshal(jwk, &withKid); err != nil {
		t.Fatal(err)
	}
	withKid["kid"] = ""
	emptyKidJWK, err := json.Marshal(withKid)
	if err != nil {
		t.Fatal(err)
	}
	der := klPKCS8(t, ec)
	pkcs8 := klPEM("PRIVATE KEY", der)
	frag := base64.StdEncoding.EncodeToString(der)[20:44]

	cases := []struct {
		name      string
		content   []byte
		wantErr   bool
		forbidden string
	}{
		{"empty", nil, true, ""},
		{"whitespace_only", []byte(" \n\t\n"), true, ""},
		{"public_jwk_without_d", pubJWK, true, ""},
		{"jwk_xy_mismatch", mismatchJWK, true, d},
		{"empty_kid_uses_thumbprint", emptyKidJWK, false, ""},
		{"surrounding_whitespace_pem", append(append([]byte("\n\n  "), pkcs8...), '\n', '\n'), false, ""},
		{"surrounding_whitespace_jwk", append(append([]byte("\n"), jwk...), '\n', ' '), false, ""},
		{"truncated_pem", pkcs8[:len(pkcs8)/2], true, frag},
		{"proc_type_encrypted", []byte("-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nQUJDREVGR0hJSktMTU5PUA==\n-----END EC PRIVATE KEY-----\n"), true, "QUJDREVGR0hJSktMTU5PUA"},
		{"public_key_pem", klPEM("PUBLIC KEY", func() []byte {
			b, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}()), true, ""},
		{"leading_text_before_pem", append([]byte("note\n"), pkcs8...), true, frag},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := klWrite(t, "k", tc.content)
			got, err := op.LoadSigningKey(path)
			if tc.wantErr {
				klRequireConfigError(t, err, path, tc.forbidden)
				return
			}
			if err != nil {
				t.Fatalf("LoadSigningKey: %v", err)
			}
			if got.KeyID != klThumbprint(ec) {
				t.Fatalf("KeyID = %q, want thumbprint", got.KeyID)
			}
		})
	}

	t.Run("missing_file", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(t.TempDir(), "absent.pem")
		_, err := op.LoadSigningKey(p)
		klRequireConfigError(t, err, p)
	})
	t.Run("unreadable_file", func(t *testing.T) {
		t.Parallel()
		if os.Geteuid() == 0 {
			t.Skip("root bypasses file permissions")
		}
		p := klWrite(t, "locked.pem", pkcs8)
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		_, err := op.LoadSigningKey(p)
		klRequireConfigError(t, err, p, frag)
	})
}

func TestLoadKeyset_DuplicateRejected(t *testing.T) {
	t.Parallel()

	ec := klECKey(t, elliptic.P256())
	pemBytes := klPEM("PRIVATE KEY", klPKCS8(t, ec))
	a := klWrite(t, "a.pem", pemBytes)
	b := klWrite(t, "b.pem", pemBytes)

	t.Run("same_key_twice_collides_on_thumbprint", func(t *testing.T) {
		t.Parallel()
		_, err := op.LoadKeyset(a, b)
		klRequireConfigError(t, err, b)
	})

	t.Run("explicit_kid_collides", func(t *testing.T) {
		t.Parallel()
		j1, _ := klECJWK(t, klECKey(t, elliptic.P256()), "dup")
		j2, _ := klECJWK(t, klECKey(t, elliptic.P256()), "dup")
		p1 := klWrite(t, "1.jwk", j1)
		p2 := klWrite(t, "2.jwk", j2)
		_, err := op.LoadKeyset(p1, p2)
		klRequireConfigError(t, err, p2)
	})

	t.Run("same_key_as_jwk_with_kid_collides", func(t *testing.T) {
		t.Parallel()
		j, _ := klECJWK(t, ec, "named")
		pj := klWrite(t, "named.jwk", j)
		_, err := op.LoadKeyset(a, pj)
		klRequireConfigError(t, err, pj)
	})

	t.Run("no_paths", func(t *testing.T) {
		t.Parallel()
		_, err := op.LoadKeyset()
		klRequireConfigError(t, err, "")
	})

	t.Run("bad_second_file_names_it", func(t *testing.T) {
		t.Parallel()
		bad := klWrite(t, "bad.pem", []byte("junk"))
		_, err := op.LoadKeyset(a, bad)
		klRequireConfigError(t, err, bad)
	})
}

func TestLoadKeyset_ThumbprintKid(t *testing.T) {
	t.Parallel()

	k1 := klECKey(t, elliptic.P256())
	k2 := klECKey(t, elliptic.P256())
	p1 := klWrite(t, "one.pem", klPEM("PRIVATE KEY", klPKCS8(t, k1)))
	sec1, err := x509.MarshalECPrivateKey(k2)
	if err != nil {
		t.Fatal(err)
	}
	p2 := klWrite(t, "two.pem", klPEM("EC PRIVATE KEY", sec1))

	ks, err := op.LoadKeyset(p1, p2)
	if err != nil {
		t.Fatalf("LoadKeyset: %v", err)
	}
	if len(ks) != 2 {
		t.Fatalf("len = %d, want 2", len(ks))
	}
	if ks[0].KeyID != klThumbprint(k1) || ks[1].KeyID != klThumbprint(k2) {
		t.Fatalf("kids = %q, %q; want thumbprints in argument order", ks[0].KeyID, ks[1].KeyID)
	}
	if ks[0].KeyID == ks[1].KeyID {
		t.Fatal("distinct keys share a kid")
	}
}

func TestLoadKeyset_JWKKidPreserved(t *testing.T) {
	t.Parallel()

	k := klECKey(t, elliptic.P256())
	body, _ := klECJWK(t, k, "2026-10-active")
	path := klWrite(t, "active.jwk", body)

	got, err := op.LoadSigningKey(path)
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	if got.KeyID != "2026-10-active" {
		t.Fatalf("KeyID = %q, want the JWK kid", got.KeyID)
	}
	ks, err := op.LoadKeyset(path)
	if err != nil {
		t.Fatalf("LoadKeyset: %v", err)
	}
	if len(ks) != 1 || ks[0].KeyID != "2026-10-active" {
		t.Fatalf("keyset = %+v", ks)
	}
}

func TestLoadKeyset_AcceptedByNew(t *testing.T) {
	t.Parallel()

	active := klWrite(t, "active.pem", klPEM("PRIVATE KEY", klPKCS8(t, klECKey(t, elliptic.P256()))))
	retiring, _ := klECJWK(t, klECKey(t, elliptic.P256()), "old")
	old := klWrite(t, "old.jwk", retiring)
	ck1 := klWrite(t, "cookie1.hex", []byte(hex.EncodeToString(newRandomCookieKey(t))+"\n"))
	ck2 := klWrite(t, "cookie2.raw", func() []byte {
		b := newRandomCookieKey(t)
		b[0] = 0x00
		return b
	}())

	ks, err := op.LoadKeyset(active, old)
	if err != nil {
		t.Fatalf("LoadKeyset: %v", err)
	}
	cookies, err := op.LoadSymmetricKeys(ck1, ck2)
	if err != nil {
		t.Fatalf("LoadSymmetricKeys: %v", err)
	}
	provider, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(ks),
		op.WithCookieKeys(cookies...),
		fixtureAuthenticator(),
	)
	if err != nil {
		t.Fatalf("op.New rejected the loaded keys: %v", err)
	}
	if provider == nil {
		t.Fatal("nil provider")
	}
}

func TestLoadSymmetricKeys_Inputs(t *testing.T) {
	t.Parallel()

	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	// 0xfb 0xff yields "+" and "/" in the standard alphabet.
	tricky := make([]byte, 32)
	for i := range tricky {
		tricky[i] = []byte{0xfb, 0xff, 0xfe}[i%3]
	}
	if base64.StdEncoding.EncodeToString(tricky) == base64.URLEncoding.EncodeToString(tricky) {
		t.Fatal("test key does not distinguish the base64 alphabets")
	}
	hexLower := hex.EncodeToString(raw)
	hexUpper := strings.ToUpper(hexLower)

	cases := []struct {
		name    string
		content []byte
		want    []byte // nil means an error is expected
	}{
		{"raw_32_non_printable", raw, raw},
		{"raw_1_byte", []byte{0x00}, nil},
		{"raw_31_bytes", raw[:31], nil},
		{"raw_33_bytes", append(append([]byte(nil), raw...), 0x01), nil},
		{"printable_32_hex_chars", []byte("00112233445566778899aabbccddeeff"), nil},
		{"printable_32_letters", []byte("abcdefghijklmnopqrstuvwxyzABCDEF"), nil},
		{"printable_31_chars_and_newline", []byte("abcdefghijklmnopqrstuvwxyzABCDE\n"), nil},
		{"hex_64_lower", []byte(hexLower), raw},
		{"hex_64_upper", []byte(hexUpper), raw},
		{"hex_64_trailing_newline", []byte(hexLower + "\n"), raw},
		{"hex_64_crlf_and_spaces", []byte("  " + hexLower + "\r\n"), raw},
		{"base64_std_padded", []byte(base64.StdEncoding.EncodeToString(tricky)), tricky},
		{"base64_std_unpadded", []byte(base64.RawStdEncoding.EncodeToString(tricky)), tricky},
		{"base64_url_padded", []byte(base64.URLEncoding.EncodeToString(tricky)), tricky},
		{"base64_url_unpadded", []byte(base64.RawURLEncoding.EncodeToString(tricky)), tricky},
		{"base64_with_newline", []byte(base64.StdEncoding.EncodeToString(tricky) + "\n"), tricky},
		{"base64_of_31_bytes", []byte(base64.StdEncoding.EncodeToString(raw[:31])), nil},
		{"base64_of_33_bytes", []byte(base64.StdEncoding.EncodeToString(append(append([]byte(nil), raw...), 1))), nil},
		{"hex_of_31_bytes", []byte(hex.EncodeToString(raw[:31])), nil},
		{"hex_64_non_hex_chars", []byte(strings.Repeat("z", 64)), nil},
		{"invalid_base64", []byte(strings.Repeat("!", 44)), nil},
		{"non_ascii_text", []byte(strings.Repeat("é", 22)), nil},
		{"empty", nil, nil},
		{"whitespace_only", []byte(" \n\t\r\n"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := klWrite(t, "sym", tc.content)
			got, err := op.LoadSymmetricKeys(path)
			if tc.want == nil {
				forbidden := ""
				if s := strings.TrimSpace(string(tc.content)); len(s) >= 8 && !strings.ContainsAny(s, "\x00\r\n") {
					forbidden = s
				}
				klRequireConfigError(t, err, path, forbidden)
				return
			}
			if err != nil {
				t.Fatalf("LoadSymmetricKeys: %v", err)
			}
			if len(got) != 1 || string(got[0]) != string(tc.want) {
				t.Fatalf("decoded key mismatch (len=%d)", len(got))
			}
		})
	}

	t.Run("no_paths", func(t *testing.T) {
		t.Parallel()
		_, err := op.LoadSymmetricKeys()
		klRequireConfigError(t, err, "")
		if !strings.Contains(err.Error(), "at least one path") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("missing_file", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(t.TempDir(), "absent.key")
		_, err := op.LoadSymmetricKeys(p)
		klRequireConfigError(t, err, p)
	})
	t.Run("unreadable_file", func(t *testing.T) {
		t.Parallel()
		if os.Geteuid() == 0 {
			t.Skip("root bypasses file permissions")
		}
		p := klWrite(t, "locked.key", raw)
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		_, err := op.LoadSymmetricKeys(p)
		klRequireConfigError(t, err, p)
	})
	t.Run("order_is_argument_order", func(t *testing.T) {
		t.Parallel()
		a := klWrite(t, "a", []byte(hexLower))
		b := klWrite(t, "b", []byte(base64.StdEncoding.EncodeToString(tricky)))
		got, err := op.LoadSymmetricKeys(a, b)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || string(got[0]) != string(raw) || string(got[1]) != string(tricky) {
			t.Fatal("keys are not in argument order")
		}
	})
	t.Run("same_file_twice_is_allowed", func(t *testing.T) {
		t.Parallel()
		a := klWrite(t, "a", []byte(hexLower))
		got, err := op.LoadSymmetricKeys(a, a)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
	})
	t.Run("bad_second_file_names_it", func(t *testing.T) {
		t.Parallel()
		a := klWrite(t, "a", []byte(hexLower))
		bad := klWrite(t, "bad", []byte("short"))
		_, err := op.LoadSymmetricKeys(a, bad)
		klRequireConfigError(t, err, bad)
	})
	t.Run("returned_keys_are_independent_copies", func(t *testing.T) {
		t.Parallel()
		a := klWrite(t, "a", raw)
		got1, err := op.LoadSymmetricKeys(a)
		if err != nil {
			t.Fatal(err)
		}
		got1[0][0] ^= 0xff
		got2, err := op.LoadSymmetricKeys(a)
		if err != nil {
			t.Fatal(err)
		}
		if got2[0][0] != raw[0] {
			t.Fatal("second load observed the first load's mutation")
		}
	})
}

func TestLoadSigningKey_PEMBlockSelection(t *testing.T) {
	t.Parallel()

	ec := klECKey(t, elliptic.P256())
	sec1, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	params := klPEM("EC PARAMETERS", []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07})
	key := klPEM("EC PRIVATE KEY", sec1)

	t.Run("ec_parameters_block_is_skipped", func(t *testing.T) {
		t.Parallel()
		got, err := op.LoadSigningKey(klWrite(t, "k.pem", append(append([]byte{}, params...), key...)))
		if err != nil {
			t.Fatalf("LoadSigningKey: %v", err)
		}
		if got.KeyID != klThumbprint(ec) {
			t.Fatalf("KeyID = %q, want thumbprint", got.KeyID)
		}
	})
	t.Run("two_private_key_blocks_rejected", func(t *testing.T) {
		t.Parallel()
		path := klWrite(t, "k.pem", append(append([]byte{}, key...), key...))
		_, err := op.LoadSigningKey(path)
		klRequireConfigError(t, err, path)
	})
}
