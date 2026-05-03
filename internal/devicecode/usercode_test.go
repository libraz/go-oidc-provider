package devicecode_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/devicecode"
)

func TestNewUserCode_Length(t *testing.T) {
	t.Parallel()
	for range 16 {
		got, err := devicecode.NewUserCode()
		if err != nil {
			t.Fatalf("NewUserCode: %v", err)
		}
		if len(got) != devicecode.UserCodeLength {
			t.Errorf("len = %d, want %d (got %q)", len(got), devicecode.UserCodeLength, got)
		}
	}
}

func TestNewUserCode_Charset(t *testing.T) {
	t.Parallel()
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for range 32 {
		got, err := devicecode.NewUserCode()
		if err != nil {
			t.Fatalf("NewUserCode: %v", err)
		}
		for i, r := range got {
			if !strings.ContainsRune(alphabet, r) {
				t.Errorf("position %d in %q is %q, outside Crockford Base32 alphabet", i, got, r)
			}
		}
	}
}

func TestNormaliseUserCode_RoundTrip(t *testing.T) {
	t.Parallel()
	got, err := devicecode.NewUserCode()
	if err != nil {
		t.Fatalf("NewUserCode: %v", err)
	}
	canon, err := devicecode.NormaliseUserCode(got)
	if err != nil {
		t.Fatalf("NormaliseUserCode(%q): %v", got, err)
	}
	if canon != got {
		t.Errorf("NormaliseUserCode(%q) = %q, want %q (round-trip should be identity)", got, canon, got)
	}
}

func TestNormaliseUserCode_StripSeparators(t *testing.T) {
	t.Parallel()
	canon, err := devicecode.NormaliseUserCode("ABCD-EFGH")
	if err != nil {
		t.Fatalf("NormaliseUserCode: %v", err)
	}
	if canon != "ABCDEFGH" {
		t.Errorf("strip dash: got %q, want ABCDEFGH", canon)
	}
	canon, err = devicecode.NormaliseUserCode("abcd efgh")
	if err != nil {
		t.Fatalf("NormaliseUserCode: %v", err)
	}
	if canon != "ABCDEFGH" {
		t.Errorf("uppercase + strip space: got %q, want ABCDEFGH", canon)
	}
}

func TestNormaliseUserCode_AmbiguousFolding(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"OOOO0000":        "00000000",
		"IIIL1111":        "11111111",
		"i-l-O-0-1-2-3-4": "11001234",
	}
	for in, want := range cases {
		got, err := devicecode.NormaliseUserCode(in)
		if err != nil {
			t.Fatalf("NormaliseUserCode(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("NormaliseUserCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormaliseUserCode_Length(t *testing.T) {
	t.Parallel()
	if _, err := devicecode.NormaliseUserCode("ABCD"); !errors.Is(err, devicecode.ErrUserCodeLength) {
		t.Errorf("short code: got %v, want ErrUserCodeLength", err)
	}
	if _, err := devicecode.NormaliseUserCode("ABCDEFGHIJ"); !errors.Is(err, devicecode.ErrUserCodeLength) {
		t.Errorf("long code (after I→1): got %v, want ErrUserCodeLength", err)
	}
}

func TestNormaliseUserCode_Charset(t *testing.T) {
	t.Parallel()
	// 'U' is NOT in Crockford Base32 (the alphabet skips U to avoid
	// "U/V" pair; only V is in the alphabet).
	if _, err := devicecode.NormaliseUserCode("ABCDUFGH"); !errors.Is(err, devicecode.ErrUserCodeCharset) {
		t.Errorf("non-Crockford char: got %v, want ErrUserCodeCharset", err)
	}
}
