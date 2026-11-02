package argon2id

import (
	"encoding/base64"
	"fmt"
)

// Params is the parameter set a hasher derives under: the cost
// parameters plus the salt and derived-key sizes it generates.
type Params struct {
	// Memory is the memory cost in KiB.
	Memory uint32
	// Iterations is the time cost.
	Iterations uint32
	// Parallelism is the lanes count.
	Parallelism uint8
	// SaltLength is the salt size in bytes.
	SaltLength uint32
	// KeyLength is the derived-key size in bytes.
	KeyLength uint32
}

// DefaultParams returns the library's hashing parameters, which follow
// OWASP's 2024 password-hashing guidance: m=64MiB, t=3, p=1, 16-byte
// salt, 32-byte key. Every built-in credential hasher mints under them.
func DefaultParams() Params {
	return Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Encode renders p as the PHC string `$argon2id$v=..$m=..,t=..,p=..$salt$hash`
// ([ParsePHC] is its inverse). The salt and hash use unpadded standard
// base64.
func Encode(p PHCParams) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		Version,
		p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(p.Salt),
		base64.RawStdEncoding.EncodeToString(p.Hash),
	)
}

// Hash derives the key for plain under salt and p through the gated [Key]
// and renders it as a PHC string.
func Hash(plain, salt []byte, p Params) string {
	return Encode(PHCParams{
		Memory:      p.Memory,
		Iterations:  p.Iterations,
		Parallelism: p.Parallelism,
		Salt:        salt,
		Hash:        Key(plain, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength),
	})
}
