package clientauth

import (
	"context"
	"errors"

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
		dummyVerify(presented)
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
// when the credentials are about to be rejected for a structural reason
// (unknown client, mismatched id, disallowed method). Without it the
// "unknown client" path completes much faster than the "wrong secret"
// path and an attacker can enumerate clients by latency alone.
//
// Errors from the dummy verifier are intentionally ignored — the
// function exists to consume time, not to produce a result.
func runDummyVerify(creds *Credentials, opts VerifyOpts) {
	if opts.SecretVerifier == nil {
		return
	}
	switch creds.Method {
	case MethodSecretBasic:
		dummyVerify(creds.SecretBasic)
	case MethodSecretPost:
		dummyVerify(creds.SecretPost)
	default:
		// MethodNone, MethodPrivateKeyJWT — no secret to cushion. The
		// verifiers for those methods have their own constant-time
		// pathways (signature verification, no-op acceptance), so we
		// don't need to fabricate work here.
	}
}
