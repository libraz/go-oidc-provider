package clientauth

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/libraz/go-oidc-provider/op/store"
)

// VerifyOpts collects the dependencies VerifyClient needs to verify
// credentials beyond what [Credentials] carries. The struct is exposed
// so the HTTP layer can wire its own SecretVerifier / AssertionVerifier.
type VerifyOpts struct {
	// SecretVerifier verifies plaintext-secret methods. Required when
	// the request uses MethodSecretBasic / MethodSecretPost. The library
	// installs an [Argon2id] verifier by default; embedders MAY swap it
	// for a bcrypt or scrypt implementation.
	SecretVerifier SecretVerifier

	// AssertionVerifier verifies private_key_jwt assertions. Required
	// when the request uses MethodPrivateKeyJWT.
	AssertionVerifier AssertionVerifier

	// AllowedMethods optionally restricts the [Method] values
	// VerifyClient will accept. Empty means "no policy override; the
	// registered client's method governs"; non-empty means a method
	// outside the list is rejected with [ErrCredentialsInvalid] before
	// any cryptographic check runs (after the dummy-verify timing
	// shim, so the latency channel still tells the caller nothing).
	//
	// The list is the OP-level intersection of every active
	// [profile.Profile]'s allowed-methods set, translated into the
	// [Method] enum: profile-only values such as "tls_client_auth" do
	// not appear because they are handled outside this package.
	// Encoding the policy here lets every endpoint that calls
	// [VerifyClient] enforce FAPI 2.0 §3.1.3 without duplicating the
	// switch.
	AllowedMethods []Method
}

// VerifyClient cross-checks the parsed credentials against the
// registered client. On success it returns the method actually used; on
// failure it returns one of the package's sentinel errors.
//
// The verifier always evaluates the entire credential pathway (even on
// known-bad inputs) so the timing channel does not reveal whether the
// client_id exists, whether the registered method matches, or whether
// the secret was wrong.
func VerifyClient(ctx context.Context, creds *Credentials, client *store.Client, opts VerifyOpts) (Method, error) {
	if creds == nil {
		return "", ErrNoCredentials
	}
	if client == nil {
		runDummyVerify(creds, opts)
		return "", ErrCredentialsInvalid
	}
	if creds.ClientID != client.ID {
		runDummyVerify(creds, opts)
		return "", ErrClientMismatch
	}
	if !methodAllowedForClient(creds.Method, client) {
		runDummyVerify(creds, opts)
		return "", ErrCredentialsInvalid
	}
	if !methodAllowedByPolicy(creds.Method, opts.AllowedMethods) {
		runDummyVerify(creds, opts)
		return "", ErrCredentialsInvalid
	}

	switch creds.Method {
	case MethodNone:
		// "none" requires the client be registered as public. Method
		// matching is already enforced above; nothing else to do.
		return MethodNone, nil

	case MethodSecretBasic:
		if err := verifySecret(opts, creds.SecretBasic, client.SecretHash); err != nil {
			return "", err
		}
		return MethodSecretBasic, nil

	case MethodSecretPost:
		if err := verifySecret(opts, creds.SecretPost, client.SecretHash); err != nil {
			return "", err
		}
		return MethodSecretPost, nil

	case MethodPrivateKeyJWT:
		if opts.AssertionVerifier == nil {
			return "", errors.New("authn: AssertionVerifier required for private_key_jwt")
		}
		if err := opts.AssertionVerifier.Verify(ctx, client.ID, creds.AssertionJWT); err != nil {
			return "", err
		}
		return MethodPrivateKeyJWT, nil

	default:
		return "", ErrUnsupportedMethod
	}
}

// methodAllowedForClient reports whether the registered client may use
// the parsed method. The library cross-checks against the client's
// TokenEndpointAuthMethod; mismatches are treated as invalid credentials
// rather than a separate error so attackers cannot tell which client
// supports which method via timing or error code.
func methodAllowedForClient(m Method, c *store.Client) bool {
	if m == MethodNone {
		return c.PublicClient
	}
	if c.PublicClient {
		// Public clients MUST use "none"; rejecting any secret method
		// here is the structural counterpart to the registration-time
		// rule that public clients carry no secret.
		return false
	}
	return string(m) == c.TokenEndpointAuthMethod
}

// methodAllowedByPolicy reports whether the OP-level allow-list (set
// by [VerifyOpts.AllowedMethods]) admits m. An empty list means "no
// policy override"; the registered client's method governs.
func methodAllowedByPolicy(m Method, allowed []Method) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == m {
			return true
		}
	}
	return false
}

// verifySecret runs the configured SecretVerifier. The function returns
// [ErrCredentialsInvalid] both when the verifier rejects and when the
// stored hash is missing — leaking which one is unsafe.
func verifySecret(opts VerifyOpts, presented, stored string) error {
	if opts.SecretVerifier == nil {
		return errors.New("authn: SecretVerifier required for confidential methods")
	}
	if stored == "" {
		// Run the dummy hash anyway so timing leaks nothing about which
		// confidential client lacks a hash.
		burnSecretVerifyCost(opts.SecretVerifier, presented)
		return ErrCredentialsInvalid
	}
	if err := opts.SecretVerifier.Verify(presented, stored); err != nil {
		// Collapse onto the public sentinel; never echo the wrapped
		// implementation cause to the caller.
		_ = err
		return ErrCredentialsInvalid
	}
	return nil
}

// runDummyVerify performs a constant-time hash on the presented secret
// (or a fixed-cost ECDSA verify on a synthetic signature) when the
// credentials are about to be rejected for a structural reason
// (unknown client, mismatched id, disallowed method). Without it the
// "unknown client" path completes much faster than the "wrong secret /
// wrong signature" path and an attacker can enumerate clients by
// latency alone.
//
// Errors from the dummy verifier are intentionally ignored — the
// function exists to consume time, not to produce a result.
//
// MethodNone has no cryptographic check on the verify branch, so the
// dummy is a no-op there: padding it would create a timing channel in
// the opposite direction.
func runDummyVerify(creds *Credentials, opts VerifyOpts) {
	switch creds.Method {
	case MethodSecretBasic:
		if opts.SecretVerifier != nil {
			dummyVerifyRuns.Add(1)
			burnSecretVerifyCost(opts.SecretVerifier, creds.SecretBasic)
		}
	case MethodSecretPost:
		if opts.SecretVerifier != nil {
			dummyVerifyRuns.Add(1)
			burnSecretVerifyCost(opts.SecretVerifier, creds.SecretPost)
		}
	case MethodPrivateKeyJWT:
		// Fixed-cost ECDSA P-256 verify: matches the work factor a
		// real AssertionVerifier would burn on signature verification
		// before any claim check, so unknown-client rejection takes
		// roughly the same wall-clock as wrong-signature rejection.
		// The shim runs even when AssertionVerifier is nil because the
		// timing oracle exists independent of the embedder's
		// configuration choice.
		dummyVerifyRuns.Add(1)
		dummyJWTVerify()
	default:
		// MethodNone — no cryptographic check on the verify branch.
	}
}

// burnSecretVerifyCost spends whatever the configured verifier says a
// secret check costs, and returns nothing.
//
// Asking the verifier rather than hard-coding argon2id is what keeps
// the shim honest across configurations. The cost the shim has to
// match is the cost of the check it stands in for, and an embedder
// that swapped the verifier moved that figure — a shim pinned to the
// library's own default would then be either far longer or far
// shorter than the thing it is hiding, and a shim of the wrong length
// is a timing channel, not a defence against one.
//
// A verifier that declines to state its cost gets the argon2id
// derivation, which is the most expensive check the library ships and
// therefore the safe assumption: a shim longer than the real check
// leaks nothing, while one shorter than it leaks everything.
func burnSecretVerifyCost(verifier SecretVerifier, presented string) {
	if dummy, ok := verifier.(DummyVerifier); ok {
		dummy.VerifyDummy(presented)
		return
	}
	dummyVerify(presented)
}

// dummyVerifyRuns counts the shims [runDummyVerify] has completed.
//
// The shim is unobservable by construction: it consumes a work factor
// and returns nothing, so no assertion on a response can tell whether
// it ran. That is precisely why it went missing once — a caller
// returned before reaching [VerifyClient] and every test still passed.
// A counter is the only way to pin "this path still pays" without
// asserting on wall-clock, which would make the check flaky in exactly
// the conditions (loaded CI) where it matters least.
//
//nolint:gochecknoglobals // process-wide by nature: the shim's only observable effect.
var dummyVerifyRuns atomic.Uint64

// DummyVerifyRuns reports how many dummy-verify shims have run since
// process start. It exists for tests in sibling internal packages that
// need to prove a rejection path burned the same work as the accepting
// one; production code has no reason to read it.
func DummyVerifyRuns() uint64 { return dummyVerifyRuns.Load() }
