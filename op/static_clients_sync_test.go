package op_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const syncRedirect = "https://app.example.com/cb" //nolint:gosec // a redirect URI, not a credential.

// syncSeed builds the seed for one matrix cell. meta varies the scopes and
// secret varies the credential, so a cell can differ from a stored record
// in exactly one dimension.
func syncSeed(tb testing.TB, id, kind string, meta, secret int) op.ClientSeed { //nolint:ireturn // the seed builders share the ClientSeed interface.
	tb.Helper()
	scopes := []string{"openid"}
	if meta == 2 {
		scopes = []string{"openid", "profile"}
	}
	switch kind {
	case "public":
		return op.PublicClient{ID: id, RedirectURIs: []string{syncRedirect}, Scopes: scopes}
	case "plaintext":
		return op.ConfidentialClient{
			ID: id, Secret: syncPlain(secret),
			RedirectURIs: []string{syncRedirect}, Scopes: scopes,
		}
	case "hash":
		return op.ConfidentialClient{
			ID: id, SecretHash: syncHash(tb, secret),
			RedirectURIs: []string{syncRedirect}, Scopes: scopes,
		}
	}
	tb.Fatalf("unknown seed kind %q", kind)
	return nil
}

func syncPlain(secret int) string {
	if secret == 2 {
		return "plain-secret-two"
	}
	return "plain-secret-one"
}

// syncHashes are minted once so a cell that re-derives its seed gets the
// same stored encoding.
var (
	syncHashesMu sync.Mutex
	syncHashes   = map[int]string{}
)

func syncHash(tb testing.TB, secret int) string {
	tb.Helper()
	syncHashesMu.Lock()
	defer syncHashesMu.Unlock()
	if h, ok := syncHashes[secret]; ok {
		return h
	}
	_, h, err := op.NewClientSecret()
	if err != nil {
		tb.Fatalf("NewClientSecret: %v", err)
	}
	syncHashes[secret] = h
	return h
}

func syncProviderOpts(tb testing.TB, st store.Store, seeds ...op.ClientSeed) []op.Option {
	tb.Helper()
	return []op.Option{
		op.WithIssuer(validIssuer),
		op.WithStore(st),
		withUsersOf(st),
		op.WithKeyset(validKeyset(tb)),
		op.WithCookieKeys(newRandomCookieKey(tb)),
		fixtureAuthenticator(),
		op.WithStaticClients(seeds...),
	}
}

func TestSyncStaticClients_Matrix(t *testing.T) {
	t.Parallel()
	// syncHashes is shared mutable test state; pre-mint before any
	// parallel subtest could race on it.
	syncHash(t, 1)
	syncHash(t, 2)

	rows := []struct {
		existing string // absent, static_equal, static_meta_diff, static_secret_diff, dynamic
		secret   string // public, plaintext, hash
		position string // only, second_of_two
	}{
		{"absent", "public", "only"},
		{"absent", "plaintext", "second_of_two"},
		{"absent", "hash", "only"},
		{"static_equal", "public", "second_of_two"},
		{"static_equal", "plaintext", "only"},
		{"static_equal", "hash", "second_of_two"},
		{"static_meta_diff", "public", "only"},
		{"static_meta_diff", "plaintext", "second_of_two"},
		{"static_meta_diff", "hash", "only"},
		{"static_secret_diff", "plaintext", "only"},
		{"static_secret_diff", "hash", "second_of_two"},
		{"dynamic", "public", "second_of_two"},
		{"dynamic", "plaintext", "only"},
		{"dynamic", "hash", "second_of_two"},
	}
	for _, row := range rows {
		t.Run(row.existing+"/"+row.secret+"/"+row.position, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			st := inmem.New()
			const target, first = "target-client", "first-client"

			// Stored state, and the desired meta/secret generation.
			wantMeta, wantSecret := 1, 1
			switch row.existing {
			case "static_equal":
				if _, err := op.SyncStaticClients(ctx, st, syncSeed(t, target, row.secret, 1, 1)); err != nil {
					t.Fatalf("prime: %v", err)
				}
			case "static_meta_diff":
				if _, err := op.SyncStaticClients(ctx, st, syncSeed(t, target, row.secret, 1, 1)); err != nil {
					t.Fatalf("prime: %v", err)
				}
				wantMeta = 2
			case "static_secret_diff":
				if _, err := op.SyncStaticClients(ctx, st, syncSeed(t, target, row.secret, 1, 1)); err != nil {
					t.Fatalf("prime: %v", err)
				}
				wantSecret = 2
			case "dynamic":
				if err := st.RegisterClient(ctx, &store.Client{
					ID:                      target,
					RedirectURIs:            []string{syncRedirect},
					Scopes:                  []string{"openid"},
					GrantTypes:              []string{"authorization_code", "refresh_token"},
					ResponseTypes:           []string{"code"},
					TokenEndpointAuthMethod: "none",
					PublicClient:            true,
					Source:                  store.ClientSourceDynamic,
				}); err != nil {
					t.Fatalf("register dynamic: %v", err)
				}
			}
			var before *store.Client
			if row.existing != "absent" {
				c, err := st.GetClient(ctx, target)
				if err != nil {
					t.Fatalf("GetClient before: %v", err)
				}
				before = c
			}

			seeds := []op.ClientSeed{syncSeed(t, target, row.secret, wantMeta, wantSecret)}
			if row.position == "second_of_two" {
				seeds = []op.ClientSeed{op.PublicClient{
					ID: first, RedirectURIs: []string{syncRedirect}, Scopes: []string{"openid"},
				}, seeds[0]}
			}
			results, err := op.SyncStaticClients(ctx, st, seeds...)

			if row.existing == "dynamic" {
				if !errors.Is(err, store.ErrConflict) {
					t.Fatalf("err=%v want ErrConflict", err)
				}
				if len(results) != 0 {
					t.Errorf("results=%v want none on conflict", results)
				}
				got, getErr := st.GetClient(ctx, target)
				if getErr != nil {
					t.Fatalf("GetClient after: %v", getErr)
				}
				if got.Source != store.ClientSourceDynamic || len(got.Scopes) != 1 || got.SecretHash != before.SecretHash {
					t.Errorf("dynamic record modified: %+v", got)
				}
				if row.position == "second_of_two" {
					if _, getErr := st.GetClient(ctx, first); !errors.Is(getErr, store.ErrNotFound) {
						t.Errorf("first seed written despite a later conflict: err=%v", getErr)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("SyncStaticClients: %v", err)
			}

			want := map[string]op.StaticClientSyncAction{
				"absent":             op.StaticClientInserted,
				"static_equal":       op.StaticClientUnchanged,
				"static_meta_diff":   op.StaticClientUpdated,
				"static_secret_diff": op.StaticClientUpdated,
			}[row.existing]
			var wantResults []op.StaticClientSyncResult
			if row.position == "second_of_two" {
				wantResults = append(wantResults, op.StaticClientSyncResult{ID: first, Action: op.StaticClientInserted})
			}
			wantResults = append(wantResults, op.StaticClientSyncResult{ID: target, Action: want})
			if len(results) != len(wantResults) {
				t.Fatalf("results=%v want %v", results, wantResults)
			}
			for i := range wantResults {
				if results[i] != wantResults[i] {
					t.Errorf("results[%d]=%v want %v", i, results[i], wantResults[i])
				}
			}

			got, getErr := st.GetClient(ctx, target)
			if getErr != nil {
				t.Fatalf("GetClient after: %v", getErr)
			}
			if got.Source != store.ClientSourceStatic {
				t.Errorf("source=%q want static", got.Source)
			}
			if wantMeta == 2 && len(got.Scopes) != 2 {
				t.Errorf("scopes=%v want updated metadata", got.Scopes)
			}
			if want == op.StaticClientUnchanged && got.SecretHash != before.SecretHash {
				t.Error("unchanged client had its secret hash rewritten")
			}
			if row.existing == "static_secret_diff" {
				switch row.secret {
				case "plaintext":
					if !op.VerifyPassword([]byte(got.SecretHash), syncPlain(2)) {
						t.Error("stored hash does not verify the new plaintext")
					}
					if op.VerifyPassword([]byte(got.SecretHash), syncPlain(1)) {
						t.Error("stored hash still verifies the old plaintext")
					}
				case "hash":
					if got.SecretHash != syncHash(t, 2) {
						t.Error("stored hash is not the new SecretHash")
					}
				}
			}
		})
	}
}

func TestSyncStaticClients_ThenNewBoots(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := inmem.New()
	seeds := []op.ClientSeed{
		op.PublicClient{ID: "spa", RedirectURIs: []string{syncRedirect}, Scopes: []string{"openid"}},
		op.ConfidentialClient{
			ID: "svc", Secret: "plain-secret-one",
			RedirectURIs: []string{syncRedirect}, Scopes: []string{"openid"},
		},
	}
	if _, err := op.SyncStaticClients(ctx, st, seeds...); err != nil {
		t.Fatalf("SyncStaticClients: %v", err)
	}
	if _, err := op.New(syncProviderOpts(t, st, seeds...)...); err != nil {
		t.Fatalf("op.New after sync: %v", err)
	}
}

func TestSyncStaticClients_PlaintextThenHighEntropyNewRefuses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := inmem.New()
	seeds := []op.ClientSeed{op.ConfidentialClient{
		ID: "svc", Secret: "plain-secret-one",
		RedirectURIs: []string{syncRedirect}, Scopes: []string{"openid"},
	}}
	if _, err := op.SyncStaticClients(ctx, st, seeds...); err != nil {
		t.Fatalf("SyncStaticClients: %v", err)
	}
	_, err := op.New(append(syncProviderOpts(t, st, seeds...), op.WithHighEntropyClientSecrets())...)
	if err == nil {
		t.Fatal("op.New accepted an argon2id static client under WithHighEntropyClientSecrets")
	}
	if !strings.Contains(err.Error(), "NewClientSecret") {
		t.Errorf("error should name the provisioning path: %v", err)
	}
}

var syncRotationExpiry = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

func syncRotationSeed(secret, previous string) op.ConfidentialClient {
	c := op.ConfidentialClient{
		ID: "svc", Secret: secret,
		RedirectURIs: []string{syncRedirect}, Scopes: []string{"openid"},
	}
	if previous != "" {
		c.PreviousSecret, c.PreviousSecretExpiresAt = previous, syncRotationExpiry
	}
	return c
}

func TestSyncStaticClients_RotationCarriesPreviousHash(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := inmem.New()
	if _, err := op.SyncStaticClients(ctx, st, syncRotationSeed("secret-before", "")); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	before, err := st.GetClient(ctx, "svc")
	if err != nil {
		t.Fatalf("GetClient before: %v", err)
	}

	results, err := op.SyncStaticClients(ctx, st, syncRotationSeed("secret-after", "secret-before"))
	if err != nil {
		t.Fatalf("rotation sync: %v", err)
	}
	if len(results) != 1 || results[0].Action != op.StaticClientUpdated {
		t.Fatalf("results=%v want one updated", results)
	}
	after, err := st.GetClient(ctx, "svc")
	if err != nil {
		t.Fatalf("GetClient after: %v", err)
	}
	if after.PreviousSecretHash != before.SecretHash {
		t.Error("previous hash is not the hash the client had before the rotation")
	}
	if !after.PreviousSecretExpiresAt.Equal(syncRotationExpiry) {
		t.Errorf("PreviousSecretExpiresAt=%v want %v", after.PreviousSecretExpiresAt, syncRotationExpiry)
	}
	if !op.VerifyPassword([]byte(after.SecretHash), "secret-after") ||
		op.VerifyPassword([]byte(after.SecretHash), "secret-before") {
		t.Error("current hash does not verify exactly the new secret")
	}
}

func TestSyncStaticClients_RotationRerunIsUnchanged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := inmem.New()
	for _, seed := range []op.ConfidentialClient{
		syncRotationSeed("secret-before", ""),
		syncRotationSeed("secret-after", "secret-before"),
	} {
		if _, err := op.SyncStaticClients(ctx, st, seed); err != nil {
			t.Fatalf("sync: %v", err)
		}
	}
	rotated, err := st.GetClient(ctx, "svc")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}

	results, err := op.SyncStaticClients(ctx, st, syncRotationSeed("secret-after", "secret-before"))
	if err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if len(results) != 1 || results[0].Action != op.StaticClientUnchanged {
		t.Fatalf("results=%v want one unchanged", results)
	}
	again, err := st.GetClient(ctx, "svc")
	if err != nil {
		t.Fatalf("GetClient again: %v", err)
	}
	if again.SecretHash != rotated.SecretHash || again.PreviousSecretHash != rotated.PreviousSecretHash {
		t.Error("rerun rewrote the stored hashes")
	}
}

func TestSyncStaticClients_HighEntropyUnverifiedPreviousRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := inmem.New()
	_, current, err := op.NewClientSecret()
	if err != nil {
		t.Fatalf("NewClientSecret: %v", err)
	}
	if _, err := op.SyncStaticClients(ctx, st, op.ConfidentialClient{
		ID: "svc", SecretHash: current,
		RedirectURIs: []string{syncRedirect}, Scopes: []string{"openid"},
	}); err != nil {
		t.Fatalf("initial sync: %v", err)
	}

	// The rotating client comes second, so the refusal also has to
	// leave the earlier, writable seed unwritten.
	_, err = op.SyncStaticClients(ctx, st,
		op.PublicClient{ID: "spa", RedirectURIs: []string{syncRedirect}, Scopes: []string{"openid"}},
		syncRotationSeed("secret-after", "unverifiable-previous"),
	)
	if err == nil {
		t.Fatal("Sync accepted a previous plaintext it cannot match to a high-entropy hash")
	}
	if !strings.Contains(err.Error(), "PreviousSecretHash") {
		t.Errorf("error should point at PreviousSecretHash: %v", err)
	}
	if _, getErr := st.GetClient(ctx, "spa"); !errors.Is(getErr, store.ErrNotFound) {
		t.Errorf("an earlier seed was written despite the refusal: err=%v", getErr)
	}
	got, getErr := st.GetClient(ctx, "svc")
	if getErr != nil {
		t.Fatalf("GetClient: %v", getErr)
	}
	if got.SecretHash != current || got.PreviousSecretHash != "" {
		t.Error("the refused client was modified")
	}
}

// noRegistryStore hides every method but store.Store's own, so the
// inmem client registry is not reachable through it.
type noRegistryStore struct{ store.Store }

func TestSyncStaticClients_NoRegistry(t *testing.T) {
	t.Parallel()
	_, err := op.SyncStaticClients(context.Background(), noRegistryStore{inmem.New()},
		op.PublicClient{ID: "spa", RedirectURIs: []string{syncRedirect}})
	var opErr *op.Error
	if !errors.As(err, &opErr) {
		t.Fatalf("err=%v want *op.Error", err)
	}
	if !strings.Contains(err.Error(), "no writable client registry") {
		t.Errorf("err=%v", err)
	}
}

func TestSyncStaticClients_EmptySeeds(t *testing.T) {
	t.Parallel()
	results, err := op.SyncStaticClients(context.Background(), inmem.New())
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if len(results) != 0 {
		t.Errorf("results=%v want empty", results)
	}
}

func TestSyncStaticClients_RejectsInvalidSeeds(t *testing.T) {
	t.Parallel()
	pub := func(id string) op.ClientSeed {
		return op.PublicClient{ID: id, RedirectURIs: []string{syncRedirect}}
	}
	var nilSeed op.ClientSeed
	cases := map[string][]op.ClientSeed{
		"nil seed":     {pub("a"), nilSeed},
		"empty secret": {pub("a"), op.ConfidentialClient{ID: "b", RedirectURIs: []string{syncRedirect}}},
		"duplicate id": {pub("a"), pub("a")},
	}
	for name, seeds := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st := inmem.New()
			if _, err := op.SyncStaticClients(context.Background(), st, seeds...); err == nil {
				t.Fatal("expected an error")
			}
			if _, err := st.GetClient(context.Background(), "a"); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("a seed was written despite an invalid set: err=%v", err)
			}
		})
	}
}
