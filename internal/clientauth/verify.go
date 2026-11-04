package clientauth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

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
	// [Method] enum. Encoding the policy here lets every endpoint that calls
	// [VerifyClient] enforce FAPI 2.0 §3.1.3 without duplicating the
	// switch.
	AllowedMethods []Method

	// CertificateVerifier verifies the RFC 8705 §2 methods against
	// Request. Nil rejects both methods.
	CertificateVerifier CertificateVerifier

	// Request is the inbound request whose client certificate
	// CertificateVerifier judges.
	Request *http.Request

	// Now is the wall-clock reading that bounds the previous secret's
	// acceptance window. The zero value never accepts the previous
	// secret, so a caller that forgets it fails closed.
	Now time.Time
}

// Verified is the outcome of a successful [VerifyClient] call.
type Verified struct {
	// Method is the authentication method the credentials used.
	Method Method

	// PreviousSecret reports that a secret method matched the client's
	// previous secret rather than its current one.
	PreviousSecret bool
}

// VerifyClient cross-checks the parsed credentials against the
// registered client. On success it returns the method actually used and
// whether the previous secret matched; on failure it returns one of the
// package's sentinel errors. creds is never written.
//
// A request with no body credential from a client registered for an
// RFC 8705 §2 method is judged under that method (see [EffectiveMethod]).
//
// The verifier always evaluates the entire credential pathway (even on
// known-bad inputs) so the timing channel does not reveal whether the
// client_id exists, whether the registered method matches, or whether
// the secret was wrong.
func VerifyClient(ctx context.Context, creds *Credentials, client *store.Client, opts VerifyOpts) (Verified, error) {
	method, err := admitMethod(creds, client, opts)
	if err != nil {
		return Verified{}, err
	}

	switch method {
	case MethodNone:
		// "none" requires the client be registered as public. Method
		// matching is already enforced above; nothing else to do.
		return Verified{Method: MethodNone}, nil

	case MethodSecretBasic:
		previous, err := verifyClientSecret(opts, creds.SecretBasic, client)
		if err != nil {
			return Verified{}, err
		}
		return Verified{Method: MethodSecretBasic, PreviousSecret: previous}, nil

	case MethodSecretPost:
		previous, err := verifyClientSecret(opts, creds.SecretPost, client)
		if err != nil {
			return Verified{}, err
		}
		return Verified{Method: MethodSecretPost, PreviousSecret: previous}, nil

	case MethodPrivateKeyJWT:
		if opts.AssertionVerifier == nil {
			return Verified{}, errors.New("authn: AssertionVerifier required for private_key_jwt")
		}
		if err := opts.AssertionVerifier.Verify(ctx, client.ID, creds.AssertionJWT); err != nil {
			return Verified{}, err
		}
		return Verified{Method: MethodPrivateKeyJWT}, nil

	case MethodTLSClientAuth, MethodSelfSignedTLSClientAuth:
		if err := verifyCertificateMethod(ctx, method, client, opts); err != nil {
			return Verified{}, err
		}
		return Verified{Method: method}, nil

	default:
		return Verified{}, ErrUnsupportedMethod
	}
}

// admitMethod runs the structural checks that precede verification and
// returns the method the credentials authenticate with. Every rejection
// except missing credentials burns the dummy verify first.
func admitMethod(creds *Credentials, client *store.Client, opts VerifyOpts) (Method, error) {
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
	method := EffectiveMethod(creds, client)
	if !methodAllowedForClient(method, client) || !methodAllowedByPolicy(method, opts.AllowedMethods) {
		runDummyVerify(creds, opts)
		return "", ErrCredentialsInvalid
	}
	return method, nil
}

// verifyCertificateMethod runs the RFC 8705 §2 check for method, failing
// closed when no certificate verifier or request is wired.
func verifyCertificateMethod(ctx context.Context, method Method, client *store.Client, opts VerifyOpts) error {
	if opts.CertificateVerifier == nil || opts.Request == nil {
		return ErrCredentialsInvalid
	}
	return opts.CertificateVerifier.VerifyCertificate(ctx, opts.Request, method, client)
}

// verifyClientSecret checks presented against the current secret and,
// failing that, against the previous secret while its window is open.
// It reports previous=true when only the previous secret matched.
//
// Whether the second check runs depends on the client's stored state,
// which is not secret, so the extra latency it adds is not a leak.
func verifyClientSecret(opts VerifyOpts, presented string, client *store.Client) (bool, error) {
	err := verifySecret(opts, presented, client.SecretHash)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, ErrCredentialsInvalid) || !previousSecretActive(client, opts.Now) {
		return false, err
	}
	if prevErr := verifySecret(opts, presented, client.PreviousSecretHash); prevErr != nil {
		return false, prevErr
	}
	return true, nil
}

// previousSecretActive reports whether the client's previous secret is
// still accepted at now. A hash without an expiry, or a zero now, fails
// closed; the expiry instant itself is already outside the window.
func previousSecretActive(client *store.Client, now time.Time) bool {
	if client.PreviousSecretHash == "" || client.PreviousSecretExpiresAt.IsZero() || now.IsZero() {
		return false
	}
	return now.Before(client.PreviousSecretExpiresAt)
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
	return slices.Contains(allowed, m)
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
	if opts.SecretVerifier.Verify(presented, stored) != nil {
		// Collapse onto the public sentinel; never echo the wrapped
		// implementation cause to the caller.
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
