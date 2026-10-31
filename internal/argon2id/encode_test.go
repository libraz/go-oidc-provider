package argon2id_test

import (
	"bytes"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/argon2id"
)

func TestEncode_RoundTripsThroughParsePHC(t *testing.T) {
	t.Parallel()
	d := argon2id.DefaultParams()
	in := argon2id.PHCParams{
		Memory:      d.Memory,
		Iterations:  d.Iterations,
		Parallelism: d.Parallelism,
		Salt:        bytes.Repeat([]byte{0xA5}, int(d.SaltLength)),
		Hash:        bytes.Repeat([]byte{0x5A}, int(d.KeyLength)),
	}
	enc := argon2id.Encode(in)
	out, err := argon2id.ParsePHC(enc, argon2id.DefaultPolicy())
	if err != nil {
		t.Fatalf("ParsePHC(%q): %v", enc, err)
	}
	if out.Memory != in.Memory || out.Iterations != in.Iterations || out.Parallelism != in.Parallelism ||
		!bytes.Equal(out.Salt, in.Salt) || !bytes.Equal(out.Hash, in.Hash) {
		t.Errorf("round trip mismatch: got %+v want %+v", out, in)
	}
}

func TestDefaultParams_PinnedValues(t *testing.T) {
	t.Parallel()
	want := argon2id.Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	if got := argon2id.DefaultParams(); got != want {
		t.Errorf("DefaultParams() = %+v, want %+v", got, want)
	}
}
