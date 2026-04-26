package keys_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

func mustECDSAKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	return priv
}

func TestNewSet_AcceptsSingleKey(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{{KeyID: "sig-1", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	if got := set.Active().KeyID; got != "sig-1" {
		t.Errorf("Active().KeyID=%q want sig-1", got)
	}
	jwks := set.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("JWKS keys=%d want 1", len(jwks.Keys))
	}
	if jwks.Keys[0].KeyID != "sig-1" {
		t.Errorf("kid=%q want sig-1", jwks.Keys[0].KeyID)
	}
	if jwks.Keys[0].Algorithm != "ES256" {
		t.Errorf("alg=%q want ES256", jwks.Keys[0].Algorithm)
	}
	if jwks.Keys[0].Use != "sig" {
		t.Errorf("use=%q want sig", jwks.Keys[0].Use)
	}
}

func TestNewSet_RejectsEmptyAndDuplicate(t *testing.T) {
	t.Parallel()

	_, err := keys.NewSet(nil)
	if !errors.Is(err, keys.ErrInvalidKey) {
		t.Errorf("nil entries: err=%v want ErrInvalidKey", err)
	}

	priv := mustECDSAKey(t)
	_, err = keys.NewSet([]keys.Entry{
		{KeyID: "k", Signer: priv},
		{KeyID: "k", Signer: priv},
	})
	if !errors.Is(err, keys.ErrInvalidKey) {
		t.Errorf("duplicate kid: err=%v want ErrInvalidKey", err)
	}
}

func TestNewSet_RejectsBadShape(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}

	cases := []struct {
		name  string
		entry keys.Entry
	}{
		{"empty kid", keys.Entry{KeyID: "", Signer: priv}},
		{"nil signer", keys.Entry{KeyID: "x", Signer: nil}},
		{"non-p256", keys.Entry{KeyID: "x", Signer: rsaPriv}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := keys.NewSet([]keys.Entry{tc.entry})
			if !errors.Is(err, keys.ErrInvalidKey) {
				t.Errorf("err=%v want ErrInvalidKey", err)
			}
		})
	}
}

func TestSet_FindReturnsEntryByKeyID(t *testing.T) {
	t.Parallel()

	priv1 := mustECDSAKey(t)
	priv2 := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{
		{KeyID: "active", Signer: priv1},
		{KeyID: "retiring", Signer: priv2},
	})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	got, ok := set.Find("retiring")
	if !ok {
		t.Fatal("Find(retiring) ok=false, want true")
	}
	if got.KeyID != "retiring" {
		t.Errorf("Find(retiring).KeyID=%q want retiring", got.KeyID)
	}
	if got.Signer != priv2 {
		t.Error("Find(retiring) returned the wrong Signer")
	}

	if got, ok := set.Find("active"); !ok || got.KeyID != "active" {
		t.Errorf("Find(active)=(%+v,%v) want active key", got, ok)
	}
}

func TestSet_FindReturnsFalseForUnknownKeyID(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{{KeyID: "active", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	got, ok := set.Find("missing")
	if ok {
		t.Errorf("Find(missing) ok=true want false (got=%+v)", got)
	}
	if got.KeyID != "" || got.Signer != nil {
		t.Errorf("Find(missing) returned non-zero Entry=%+v", got)
	}

	if _, ok := set.Find(""); ok {
		t.Error("Find(\"\") ok=true want false for empty kid lookup")
	}
}

func TestSet_JWKSIsDefensiveCopy(t *testing.T) {
	t.Parallel()

	priv := mustECDSAKey(t)
	set, err := keys.NewSet([]keys.Entry{{KeyID: "k", Signer: priv}})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	a := set.JWKS()
	b := set.JWKS()
	a.Keys[0].KeyID = "tampered"
	if b.Keys[0].KeyID != "k" {
		t.Errorf("JWKS shared mutable state: second view kid=%q", b.Keys[0].KeyID)
	}
	if got := set.JWKS().Keys[0].KeyID; got != "k" {
		t.Errorf("set view mutated: kid=%q", got)
	}
}
