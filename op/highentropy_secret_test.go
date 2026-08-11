package op_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// staticClientBaseOpts is [validBaseOpts] with a store that can seed
// static clients. The shared fixture store does not implement
// [store.StaticClientReconciler], and op.New refuses WithStaticClients
// without it — a check that fires before anything this file asserts on.
func staticClientBaseOpts(tb testing.TB) []op.Option {
	tb.Helper()
	st := inmem.New()
	return []op.Option{
		op.WithIssuer(validIssuer),
		op.WithStore(st),
		op.WithKeyset(validKeyset(tb)),
		op.WithCookieKeys(newRandomCookieKey(tb)),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		}),
	}
}

// TestWithHighEntropyClientSecrets_RejectsAnArgon2idStaticClient is the
// gate that makes the option's promise enforceable rather than
// advisory.
//
// Under this option a rejected client authentication costs
// microseconds, because that is what verifying a high-entropy secret
// costs. A client still stored under Argon2id verifies in tens of
// milliseconds, and the gap between the two is readable with a
// stopwatch — it says the client_id exists. Refusing at construction
// is the only point where the OP can see the mismatch: once it is
// serving, the difference is silent and looks like nothing but a
// slower endpoint.
func TestWithHighEntropyClientSecrets_RejectsAnArgon2idStaticClient(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(staticClientBaseOpts(t),
		op.WithHighEntropyClientSecrets(),
		op.WithStaticClients(op.ConfidentialClient{
			ID:           "legacy",
			Secret:       "a-statically-provisioned-secret",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}),
	)...)
	if err == nil {
		t.Fatal("expected a configuration error for an Argon2id static client under WithHighEntropyClientSecrets")
	}
	if !strings.Contains(err.Error(), "NewClientSecret") {
		t.Errorf("the error must name the provisioning path that fixes it: %v", err)
	}
}

// TestWithHighEntropyClientSecrets_AcceptsAMintedStaticClient is the
// other half: the option has to leave a correctly provisioned OP
// constructible, or the gate above would simply mean the feature
// cannot be used.
func TestWithHighEntropyClientSecrets_AcceptsAMintedStaticClient(t *testing.T) {
	t.Parallel()

	_, hash, err := op.NewClientSecret()
	if err != nil {
		t.Fatalf("NewClientSecret: %v", err)
	}
	if _, err := op.New(append(staticClientBaseOpts(t),
		op.WithHighEntropyClientSecrets(),
		op.WithStaticClients(op.ConfidentialClient{
			ID:           "minted",
			SecretHash:   hash,
			RedirectURIs: []string{"https://app.example.com/callback"},
		}),
	)...); err != nil {
		t.Fatalf("a minted static client must construct: %v", err)
	}
}

// TestConfidentialClient_RejectsBothSecretForms covers the seed-level
// conflict. Honouring one field and dropping the other would leave the
// operator holding a plaintext they believe works against a client
// that cannot authenticate with it — a failure that surfaces as an
// unexplained invalid_client in production rather than at startup.
func TestConfidentialClient_RejectsBothSecretForms(t *testing.T) {
	t.Parallel()

	_, hash, err := op.NewClientSecret()
	if err != nil {
		t.Fatalf("NewClientSecret: %v", err)
	}
	_, err = op.New(append(staticClientBaseOpts(t),
		op.WithStaticClients(op.ConfidentialClient{
			ID:           "ambiguous",
			Secret:       "a-statically-provisioned-secret",
			SecretHash:   hash,
			RedirectURIs: []string{"https://app.example.com/callback"},
		}),
	)...)
	if err == nil {
		t.Fatal("expected a configuration error when both Secret and SecretHash are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v, want it to name the conflict", err)
	}
}

// TestStaticClientsWithoutTheOption_StillAcceptPlaintextSecrets pins
// that none of the above changed the default. The option is opt-in
// precisely because turning it on for an existing store would make
// every un-migrated client distinguishable; a default that started
// rejecting the documented ConfidentialClient.Secret form would be the
// same breakage arriving by a different route.
func TestStaticClientsWithoutTheOption_StillAcceptPlaintextSecrets(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(staticClientBaseOpts(t),
		op.WithStaticClients(op.ConfidentialClient{
			ID:           "legacy",
			Secret:       "a-statically-provisioned-secret",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}),
	)...); err != nil {
		t.Fatalf("the default configuration must keep accepting a plaintext Secret: %v", err)
	}
}

// TestHashHighEntropyClientSecret_RefusesATypedSecret keeps the public
// helper's floor visible at the API boundary. The fast verifier is
// sound only because the plaintext is beyond guessing, and this
// function is the one place an embedder can supply a plaintext the
// library did not mint.
func TestHashHighEntropyClientSecret_RefusesATypedSecret(t *testing.T) {
	t.Parallel()

	if _, err := op.HashHighEntropyClientSecret("demo-secret"); err == nil {
		t.Fatal("expected a configuration error for a hand-written secret")
	}
	secret, _, err := op.NewClientSecret()
	if err != nil {
		t.Fatalf("NewClientSecret: %v", err)
	}
	if _, err := op.HashHighEntropyClientSecret(secret); err != nil {
		t.Fatalf("a minted secret must hash: %v", err)
	}
}
