package clientauth_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
)

// argon2Allocation is the floor a single Argon2id derivation at the
// library's parameters allocates: m=64 MiB, minus room for the
// collector to have reclaimed part of it mid-measurement. Assertions
// use it as a threshold rather than an expected value — the question
// each one asks is "did this run the KDF", and 64 MiB against a few
// hundred bytes leaves no ambiguity to tune around.
const argon2Allocation = 32 << 20

// allocatedBytes reports how many bytes fn allocated.
//
// Allocation is the observable this file leans on instead of wall
// clock. The property under test is a cost, and measuring cost by
// timing makes an assertion that fails on a loaded machine — which is
// precisely where these tests run. Argon2id's 64 MiB is a structural
// consequence of the work factor, not a speed, so it reports the same
// number on a busy CI box as on an idle laptop.
func allocatedBytes(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestNewHighEntropySecret_RoundTrips covers the provisioning path end
// to end: what the minter returns must be exactly what the verifier
// accepts, and nothing else.
func TestNewHighEntropySecret_RoundTrips(t *testing.T) {
	t.Parallel()

	secret, stored, err := clientauth.NewHighEntropySecret()
	if err != nil {
		t.Fatalf("NewHighEntropySecret: %v", err)
	}
	if !clientauth.IsHighEntropyEncoding(stored) {
		t.Fatalf("minted encoding is not recognised as high-entropy: %q", stored)
	}
	if err := (clientauth.HighEntropy{}).Verify(secret, stored); err != nil {
		t.Fatalf("verifying the minted secret: %v", err)
	}
	if err := (clientauth.HighEntropy{}).Verify(secret+"x", stored); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
		t.Fatalf("wrong secret: got %v, want ErrCredentialsInvalid", err)
	}
}

// TestNewHighEntropySecret_MintsDistinctValues guards the one failure
// that would be invisible in every other test here: a minter that
// returned a fixed secret would round-trip perfectly and hand every
// client the same credential.
func TestNewHighEntropySecret_MintsDistinctValues(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 32)
	for range 32 {
		secret, stored, err := clientauth.NewHighEntropySecret()
		if err != nil {
			t.Fatalf("NewHighEntropySecret: %v", err)
		}
		if _, dup := seen[secret]; dup {
			t.Fatal("NewHighEntropySecret repeated a secret")
		}
		seen[secret] = struct{}{}
		if _, dup := seen[stored]; dup {
			t.Fatal("NewHighEntropySecret repeated a stored encoding")
		}
		seen[stored] = struct{}{}
	}
}

// TestHashHighEntropySecret_RefusesShortSecrets pins the floor. The
// format's entire security argument is that the plaintext is beyond
// guessing, and a hand-written secret is the case where that is false
// — so the helper has to refuse rather than produce a fast-verifying
// hash over something a dictionary contains.
func TestHashHighEntropySecret_RefusesShortSecrets(t *testing.T) {
	t.Parallel()

	for _, secret := range []string{"", "demo-secret", strings.Repeat("a", 31)} {
		if _, err := clientauth.HashHighEntropySecret(secret); !errors.Is(err, clientauth.ErrSecretTooShort) {
			t.Fatalf("HashHighEntropySecret(%d chars): got %v, want ErrSecretTooShort", len(secret), err)
		}
	}
	if _, err := clientauth.HashHighEntropySecret(strings.Repeat("a", 32)); err != nil {
		t.Fatalf("HashHighEntropySecret at the floor: %v", err)
	}
}

// TestVerifiers_ReadBothEncodings is the migration guarantee. An OP
// cannot re-hash a stored secret — it holds no plaintext — so whichever
// verifier is installed has to accept records written by the other, or
// enabling the option would lock every existing client out.
func TestVerifiers_ReadBothEncodings(t *testing.T) {
	t.Parallel()

	const legacyPlaintext = "a-statically-provisioned-secret"
	legacy, err := (&clientauth.Argon2id{}).Hash(legacyPlaintext)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	fresh, freshStored, err := clientauth.NewHighEntropySecret()
	if err != nil {
		t.Fatalf("NewHighEntropySecret: %v", err)
	}

	verifiers := map[string]clientauth.SecretVerifier{
		"argon2id":     &clientauth.Argon2id{},
		"high-entropy": clientauth.HighEntropy{},
	}
	for name, verifier := range verifiers {
		if err := verifier.Verify(legacyPlaintext, legacy); err != nil {
			t.Errorf("%s verifier rejected an argon2id record: %v", name, err)
		}
		if err := verifier.Verify(fresh, freshStored); err != nil {
			t.Errorf("%s verifier rejected a high-entropy record: %v", name, err)
		}
	}
}

// TestHighEntropyVerify_RejectsMalformedEncodings checks that a
// corrupted or hostile stored value collapses onto the same sentinel a
// wrong secret produces. The distinctions are integrity faults, and a
// caller able to read them off the wire could fingerprint the parser
// by submitting synthetic records through whatever wrote the store.
func TestHighEntropyVerify_RejectsMalformedEncodings(t *testing.T) {
	t.Parallel()

	_, stored, err := clientauth.NewHighEntropySecret()
	if err != nil {
		t.Fatalf("NewHighEntropySecret: %v", err)
	}
	parts := strings.Split(stored, "$")

	malformed := map[string]string{
		"empty":             "",
		"no segments":       "$hmac-sha256$",
		"extra segment":     stored + "$extra",
		"unknown alg":       "$hmac-sha512$" + parts[2] + "$" + parts[3],
		"salt not base64":   "$hmac-sha256$!!!!$" + parts[3],
		"tag not base64":    "$hmac-sha256$" + parts[2] + "$!!!!",
		"short salt":        "$hmac-sha256$AAAA$" + parts[3],
		"short tag":         "$hmac-sha256$" + parts[2] + "$AAAA",
		"oversized":         "$hmac-sha256$" + parts[2] + "$" + strings.Repeat("A", 512),
		"argon2id envelope": "$argon2id$v=19$m=65536,t=3,p=1$" + parts[2] + "$" + parts[3],
	}
	for name, encoding := range malformed {
		if err := (clientauth.HighEntropy{}).Verify("anything", encoding); !errors.Is(err, clientauth.ErrCredentialsInvalid) {
			t.Errorf("%s: got %v, want ErrCredentialsInvalid", name, err)
		}
	}
}

// TestVerifyDummy_CostsWhatItsOwnVerifyCosts is the assertion the whole
// design turns on.
//
// The shim stands in for a verification that did not happen, so a
// rejection reveals nothing about whether the client_id resolved. It
// only does that while its cost matches the verification's. Those two
// costs live in different methods and nothing but this test ties them
// together — a verifier gaining a faster Verify without a matching
// VerifyDummy would pass every functional test in the tree and hand
// back a client-existence oracle.
//
// The test is deliberately sequential. [allocatedBytes] reads
// process-wide totals, so a parallel sibling deriving its own argon2id
// hash would land 64 MiB inside this measurement and fail the
// high-entropy case for reasons that have nothing to do with it. Go
// runs non-parallel tests while every parallel one is still paused,
// which is the isolation this needs.
//
//nolint:paralleltest // measures process-wide allocation; a parallel sibling would land inside the sample.
func TestVerifyDummy_CostsWhatItsOwnVerifyCosts(t *testing.T) {
	const legacyPlaintext = "a-statically-provisioned-secret"
	legacy, err := (&clientauth.Argon2id{}).Hash(legacyPlaintext)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	fresh, freshStored, err := clientauth.NewHighEntropySecret()
	if err != nil {
		t.Fatalf("NewHighEntropySecret: %v", err)
	}

	cases := []struct {
		name      string
		verifier  clientauth.SecretVerifier
		presented string
		stored    string
		derives   bool
	}{
		{"argon2id", &clientauth.Argon2id{}, legacyPlaintext, legacy, true},
		{"high-entropy", clientauth.HighEntropy{}, fresh, freshStored, false},
	}
	for _, tc := range cases {
		dummy, ok := tc.verifier.(clientauth.DummyVerifier)
		if !ok {
			t.Fatalf("%s: verifier does not state its rejection cost", tc.name)
		}
		verifyAlloc := allocatedBytes(func() { _ = tc.verifier.Verify(tc.presented, tc.stored) })
		dummyAlloc := allocatedBytes(func() { dummy.VerifyDummy(tc.presented) })

		if (verifyAlloc >= argon2Allocation) != tc.derives {
			t.Errorf("%s: Verify allocated %d bytes; derives=%v was expected", tc.name, verifyAlloc, tc.derives)
		}
		if (dummyAlloc >= argon2Allocation) != tc.derives {
			t.Errorf("%s: VerifyDummy allocated %d bytes, but Verify %s the KDF — the shim no longer matches the check it hides",
				tc.name, dummyAlloc, derivationVerb(tc.derives))
		}
	}
}

// derivationVerb renders the expectation in the failure message so a
// reader who trips this test is told which half drifted.
func derivationVerb(derives bool) string {
	if derives {
		return "runs"
	}
	return "does not run"
}
