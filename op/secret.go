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

// NewClientSecret mints a client_secret together with the stored
// encoding [WithHighEntropyClientSecrets] expects, and is the
// provisioning path that option is designed around.
//
// The plaintext carries 256 bits from crypto/rand. That matters
// because the fast verification the option enables rests entirely on
// the secret being beyond guessing, and a secret this function minted
// satisfies that by construction rather than by anyone's assurance.
//
// The returned plaintext is for delivery to the client and is the only
// copy: the library stores the encoding and never the secret.
//
//	secret, hash, err := op.NewClientSecret()
//	// hand `secret` to the client, seed the OP with `hash`
//	op.WithStaticClients(op.ConfidentialClient{ID: "svc", SecretHash: hash})
func NewClientSecret() (secret, hash string, err error) {
	return clientauth.NewHighEntropySecret()
}

// HashHighEntropyClientSecret returns the stored encoding
// [WithHighEntropyClientSecrets] expects for a secret the caller
// already has — one issued by an existing provisioning system, say,
// that cannot be re-minted because the client already holds it.
//
// The function refuses a plaintext under 32 characters. That is a
// length check standing in for an entropy requirement it cannot
// measure: no function can tell 32 random bytes from 32 identical
// ones. It filters out the hand-written secret, and the caller carries
// the rest of the assurance. Callers free to mint should use
// [NewClientSecret], which needs no assurance at all.
func HashHighEntropyClientSecret(secret string) (string, error) {
	hash, err := clientauth.HashHighEntropySecret(secret)
	if err != nil {
		return "", &Error{
			Code:        codeConfiguration,
			Description: "HashHighEntropyClientSecret: " + err.Error(),
			Cause:       err,
		}
	}
	return hash, nil
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
