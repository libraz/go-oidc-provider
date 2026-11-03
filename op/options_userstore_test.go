package op_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// memberStore stands in for the table an application already owns: it
// answers the one question [store.UserStore] asks and knows nothing
// about the OP's own schema. A pointer type so two instances are
// distinguishable by identity, which is what the mismatch warning
// compares.
type memberStore struct {
	subject string
	claims  map[string]any
}

func (m *memberStore) FindBySubject(_ context.Context, sub string) (*store.User, error) {
	if sub != m.subject {
		return nil, store.ErrNotFound
	}
	return &store.User{Subject: m.subject, Claims: m.claims, UpdatedAt: time.Unix(0, 0)}, nil
}

// userInfoTokenClient registers the client the self-signed access tokens
// in this file name. /userinfo requires the token's client to still be
// registered, which is how a deleted client stops its already-issued JWT
// access tokens; a token naming an unregistered client describes a state
// the token endpoint could not have produced.
func userInfoTokenClient() op.Option {
	return op.WithStaticClients(op.PublicClient{
		ID:           userInfoTokenClientID,
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid"},
	})
}

const userInfoTokenClientID = "client-1"

// userInfoEmail drives /userinfo with a self-signed access token for
// subject and returns the "email" claim the OP released.
func userInfoEmail(tb testing.TB, provider *op.Provider, key op.SigningKey, subject string) any {
	tb.Helper()
	return userInfoClaim(tb, provider, key, subject, "email")
}

// userInfoClaim drives /userinfo with a self-signed access token for
// subject and returns the named claim the OP released.
func userInfoClaim(tb testing.TB, provider *op.Provider, key op.SigningKey, subject, claim string) any {
	tb.Helper()

	jws, err := tokens.SignAccessToken(tokens.SigningKey{
		KeyID:  key.KeyID,
		Signer: key.Signer,
	}, tokens.AccessTokenClaims{
		Issuer:    validIssuer,
		Subject:   subject,
		Audience:  []string{validIssuer},
		ClientID:  userInfoTokenClientID,
		GrantID:   "grant-userstore-" + subject,
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		JTI:       "at-userstore-" + subject,
		Scope:     []string{"openid", "email", "profile"},
	})
	if err != nil {
		tb.Fatalf("SignAccessToken: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, validIssuer+"/oidc/userinfo", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+jws)
	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		tb.Fatalf("userinfo status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		tb.Fatalf("decode userinfo: %v", err)
	}
	return body[claim]
}

// TestWithUserStore_ServesClaimsFromTheSuppliedStore is the whole point
// of the option: the backend store keeps every OIDC record, and the
// claims come from the embedder's own table instead of the backend's
// users substore. Both stores hold the same subject with a different
// e-mail so a result that ignored the option would still be well-formed
// — only the value tells the two apart.
func TestWithUserStore_ServesClaimsFromTheSuppliedStore(t *testing.T) {
	t.Parallel()

	signKey := newTestKey(t, "userstore-override")
	backend := inmem.New()
	backend.PutUser(context.Background(), &store.User{
		Subject: "user-1",
		Claims:  map[string]any{"email": "from-backend@example.com"},
	})
	members := &memberStore{
		subject: "user-1",
		claims:  map[string]any{"email": "from-members@example.com"},
	}

	provider, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(backend),
		op.WithUserStore(members),
		op.WithKeyset(op.Keyset{signKey}),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
		userInfoTokenClient(),
	)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}

	if got := userInfoEmail(t, provider, signKey, "user-1"); got != "from-members@example.com" {
		t.Fatalf("email=%v want the WithUserStore value; the option did not reach /userinfo", got)
	}
}

// noUserStoreOpts is a configuration with no user store source: the
// backend is passed to WithStore only, and the login flow carries no
// PrimaryPassword store.
func noUserStoreOpts(tb testing.TB, extra ...op.Option) []op.Option {
	tb.Helper()
	return append([]op.Option{
		op.WithIssuer(validIssuer),
		op.WithStore(inmem.New()),
		op.WithKeyset(validKeyset(tb)),
		op.WithCookieKeys(newRandomCookieKey(tb)),
		// A default, so a grant set without authorization_code does not
		// trip the unused-browser-option check before the user-store one.
		op.WithDefaults(fixtureAuthenticator()),
	}, extra...)
}

// TestNew_RejectsMissingUserStore pins that the aggregate store is not a
// claim source: a grant that resolves end-user subjects with neither
// WithUserStore nor PrimaryPassword.Store is refused, and the message
// names both ways out.
func TestNew_RejectsMissingUserStore(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		extra []op.Option
	}{
		{"default grants", nil},
		{"authorization_code only", []op.Option{op.WithGrants(grant.AuthorizationCode)}},
		{"client_credentials and refresh_token", []op.Option{op.WithGrants(grant.ClientCredentials, grant.RefreshToken)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(noUserStoreOpts(t, tc.extra...)...)
			if err == nil {
				t.Fatal("op.New accepted a subject-resolving grant with no user store")
			}
			if !op.IsServerError(err) {
				t.Errorf("err = %v, want a server configuration error", err)
			}
			for _, want := range []string{"PrimaryPassword.Store", "op.WithUserStore", "st.Users()"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %v, want it to mention %q", err, want)
				}
			}
		})
	}
}

// TestNew_ClientCredentialsOnlyNeedsNoUserStore pins that a deployment
// that never redeems for an end-user builds without a user store.
func TestNew_ClientCredentialsOnlyNeedsNoUserStore(t *testing.T) {
	t.Parallel()

	opts := []op.Option{
		op.WithIssuer(validIssuer),
		op.WithStore(inmem.New()),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		op.WithGrants(grant.ClientCredentials),
	}
	if _, err := op.New(opts...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
}

func TestWithUserStore_RejectsNil(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithUserStore(nil))...)
	if !errors.Is(err, op.ErrUserStoreRequired) {
		t.Fatalf("err=%v want ErrUserStoreRequired", err)
	}
}

// warnings runs op.New with a capturing logger and returns everything it
// logged, so a test can assert on a warning that is deliberately not an
// error.
func warnings(tb testing.TB, opts ...op.Option) string {
	tb.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if _, err := op.New(append(opts, op.WithLogger(logger))...); err != nil {
		tb.Fatalf("op.New: %v", err)
	}
	return buf.String()
}

// TestNew_WarnsWhenTheLoginFlowAuthenticatesAgainstOtherRecords covers
// the misconfiguration the two-sided wiring makes possible: the login
// resolves a subject out of one set of records and the ID Token is then
// assembled from another. Nothing fails, which is exactly why it needs
// to be said out loud. Only an explicit WithUserStore can create it: left
// to inference, the claim source is the primary step's own store.
func TestNew_WarnsWhenTheLoginFlowAuthenticatesAgainstOtherRecords(t *testing.T) {
	t.Parallel()

	signKey := newTestKey(t, "userstore-mismatch")
	backend := inmem.New()
	members := &memberStore{subject: "user-1", claims: map[string]any{}}

	logged := warnings(t,
		op.WithIssuer(validIssuer),
		op.WithStore(backend),
		op.WithUserStore(members),
		op.WithKeyset(op.Keyset{signKey}),
		op.WithCookieKeys(newRandomCookieKey(t)),
		// Authenticates against the backend's users while claims now
		// come from the members table.
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: backend.UserPasswords()},
		}),
	)

	if !strings.Contains(logged, "different user store") {
		t.Fatalf("no mismatch warning logged; got:\n%s", logged)
	}
	if !strings.Contains(logged, "WithUserStore") {
		t.Fatalf("warning does not name the claim source; got:\n%s", logged)
	}
}

// TestNew_DoesNotWarnWhenBothSidesShareTheStore is the regression that
// matters more than the warning itself: the bundled adapters hand out
// one value for both Users() and UserPasswords(), so the ordinary
// single-store setup must stay silent. A warning every embedder sees on
// a correct configuration is a warning nobody reads.
func TestNew_DoesNotWarnWhenBothSidesShareTheStore(t *testing.T) {
	t.Parallel()

	signKey := newTestKey(t, "userstore-shared")
	backend := inmem.New()

	logged := warnings(t,
		op.WithIssuer(validIssuer),
		op.WithStore(backend),
		op.WithKeyset(op.Keyset{signKey}),
		op.WithCookieKeys(newRandomCookieKey(t)),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: backend.UserPasswords()},
		}),
	)

	if strings.Contains(logged, "different user store") {
		t.Fatalf("warned on a single-store configuration; got:\n%s", logged)
	}
}

// TestNew_DoesNotWarnWhenTheOverrideMatchesTheFlow pins the shape the
// option is meant to be used in: one embedder-owned store passed to
// both sides.
func TestNew_DoesNotWarnWhenTheOverrideMatchesTheFlow(t *testing.T) {
	t.Parallel()

	signKey := newTestKey(t, "userstore-aligned")
	backend := inmem.New()
	members := &passwordMemberStore{memberStore: memberStore{subject: "user-1", claims: map[string]any{}}}

	logged := warnings(t,
		op.WithIssuer(validIssuer),
		op.WithStore(backend),
		op.WithUserStore(members),
		op.WithKeyset(op.Keyset{signKey}),
		op.WithCookieKeys(newRandomCookieKey(t)),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: members},
		}),
	)

	if strings.Contains(logged, "different user store") {
		t.Fatalf("warned when both sides share the embedder store; got:\n%s", logged)
	}
}

// passwordMemberStore is memberStore with the two lookups the password
// step needs, so one embedder-owned value can serve both wirings.
type passwordMemberStore struct {
	memberStore
}

func (p *passwordMemberStore) FindByUsername(ctx context.Context, _ string) (*store.User, error) {
	return p.FindBySubject(ctx, p.subject)
}

func (p *passwordMemberStore) ReadPasswordHash(_ context.Context, _ string) ([]byte, error) {
	return nil, store.ErrNotFound
}
