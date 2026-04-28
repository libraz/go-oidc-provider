package op

import (
	"github.com/libraz/go-oidc-provider/internal/clientauth"
)

// HashClientSecret returns an argon2id encoding of secret suitable for
// [store.Client.SecretHash]. Embedders use it to seed confidential
// clients with a stored hash; the OP's default verifier accepts the
// format produced here verbatim.
//
// The function uses the library's default Argon2id parameters
// (memory 64 MiB, 3 iterations, parallelism 1, 32-byte hash + 16-byte
// salt). The OP's default secret verifier accepts these parameters; an
// embedder that has overridden the verifier through their own pipeline
// should hash with that pipeline instead.
//
// The error path is the underlying [crypto/rand] failure that drives
// salt generation; in practice it is fatal at process startup.
func HashClientSecret(secret string) (string, error) {
	return (&clientauth.Argon2id{}).Hash(secret)
}

// HashPassword returns an Argon2id PHC encoding of plain suitable for
// [store.UserPasswordStore.ReadPasswordHash]. Embedders use it to seed
// or rotate user passwords with a stored hash the built-in
// [PrimaryPassword] Step's verifier accepts verbatim.
//
// The function uses the same Argon2id parameters as [HashClientSecret]
// (memory 64 MiB, 3 iterations, parallelism 1, 32-byte hash + 16-byte
// salt) — the parameter floor matches OWASP 2024 password-hashing
// guidance. Embedders with stricter requirements produce hashes
// outside this helper; the verifier accepts any valid PHC argon2id
// encoding regardless of the originating tool.
//
// Returning a byte slice rather than a string mirrors
// [store.UserPasswordStore.ReadPasswordHash]'s shape so embedders
// pipe the value through the seed path without a string→byte
// conversion every record.
//
// The error path is the underlying [crypto/rand] failure that drives
// salt generation; in practice it is fatal at process startup.
func HashPassword(plain string) ([]byte, error) {
	enc, err := (&clientauth.Argon2id{}).Hash(plain)
	if err != nil {
		return nil, err
	}
	return []byte(enc), nil
}
