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
