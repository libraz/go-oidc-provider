package authcode_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/grants/authcode"
	"github.com/libraz/go-oidc-provider/internal/pkce"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// fixture bundles a freshly-built Issuer + Exchanger sharing the same
// clock and store. The shared clock is deliberately by-pointer so tests can
// advance it after Issue and observe the new "now" at Exchange.
type fixture struct {
	issuer    *authcode.Issuer
	exchanger *authcode.Exchanger
	cur       *time.Time
}

// movingClock satisfies inmem.Clock and reads the current value of the
// pointer it wraps so the test fixture's clock advances are observed by the
// store's own ConsumedAt stamping.
type movingClock struct{ cur *time.Time }

func (c movingClock) Now() time.Time { return *c.cur }

func newFixture(tb testing.TB, t0 time.Time) fixture {
	tb.Helper()
	cur := t0
	clk := func() time.Time { return cur }
	st := inmem.New(inmem.WithClock(movingClock{cur: &cur})).AuthorizationCodes()
	iss, err := authcode.NewIssuer(authcode.IssuerConfig{Store: st, Clock: clk})
	if err != nil {
		tb.Fatalf("NewIssuer: %v", err)
	}
	exc, err := authcode.NewExchanger(authcode.ExchangerConfig{Store: st, Clock: clk})
	if err != nil {
		tb.Fatalf("NewExchanger: %v", err)
	}
	return fixture{issuer: iss, exchanger: exc, cur: &cur}
}

func goodInput(verifier string) authcode.IssueInput {
	return authcode.IssueInput{
		ClientID:            "client-1",
		Subject:             "user-1",
		GrantID:             "grant-1",
		RedirectURI:         "https://rp.example.com/cb",
		Scope:               []string{"openid", "profile"},
		CodeChallenge:       challengeFor(verifier),
		CodeChallengeMethod: pkce.Method,
		Nonce:               "n-0S6_WzA2Mj",
		State:               "state-abc",
	}
}

func TestNewIssuer_RejectsMissingStore(t *testing.T) {
	t.Parallel()

	if _, err := authcode.NewIssuer(authcode.IssuerConfig{}); err == nil {
		t.Error("NewIssuer accepted empty config")
	}
}

func TestNewExchanger_RejectsMissingStore(t *testing.T) {
	t.Parallel()

	if _, err := authcode.NewExchanger(authcode.ExchangerConfig{}); err == nil {
		t.Error("NewExchanger accepted empty config")
	}
}

func TestIssue_AndExchange_RoundTrip(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	verifier := strings.Repeat("a", 64)
	f := newFixture(t, t0)

	code, err := f.issuer.Issue(context.Background(), goodInput(verifier))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if code == "" {
		t.Fatal("Issue returned empty code")
	}

	out, err := f.exchanger.Exchange(context.Background(), authcode.ExchangeInput{
		Code:         code,
		ClientID:     "client-1",
		RedirectURI:  "https://rp.example.com/cb",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if out.Subject != "user-1" {
		t.Errorf("Subject=%q want user-1", out.Subject)
	}
	if out.GrantID != "grant-1" {
		t.Errorf("GrantID=%q want grant-1", out.GrantID)
	}
	if out.Nonce != "n-0S6_WzA2Mj" {
		t.Errorf("Nonce=%q", out.Nonce)
	}
	if got := out.Scope; len(got) != 2 || got[0] != "openid" || got[1] != "profile" {
		t.Errorf("Scope=%v", got)
	}
	if !out.ConsumedAt.Equal(t0) {
		t.Errorf("ConsumedAt=%v want %v", out.ConsumedAt, t0)
	}
}

// TestIssue_AndExchange_NoPKCE_RoundTrip covers the profile-conditional
// PKCE path: when the authorize layer accepted a request without
// code_challenge (because no profile mandated PKCE), Issue MUST persist
// an empty challenge and Exchange MUST accept the matching code without
// a code_verifier. The exchange with a non-empty verifier is rejected
// to block a downgrade where a client smuggles a verifier onto a code
// that was never bound to PKCE.
func TestIssue_AndExchange_NoPKCE_RoundTrip(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	in := goodInput("ignored")
	in.CodeChallenge = ""
	in.CodeChallengeMethod = ""

	code, err := f.issuer.Issue(context.Background(), in)
	if err != nil {
		t.Fatalf("Issue without PKCE: %v", err)
	}

	out, err := f.exchanger.Exchange(context.Background(), authcode.ExchangeInput{
		Code:        code,
		ClientID:    "client-1",
		RedirectURI: "https://rp.example.com/cb",
	})
	if err != nil {
		t.Fatalf("Exchange without verifier: %v", err)
	}
	if out.Subject != "user-1" {
		t.Errorf("Subject=%q want user-1", out.Subject)
	}
}

// TestExchange_NoPKCE_RejectsSmuggledVerifier covers the PKCE
// downgrade guard: a record issued WITHOUT a code_challenge MUST
// refuse a code_verifier on exchange. Without this branch a client
// (or attacker who captured a verifier-less code via a leakage
// channel) could fabricate a verifier for a code that was never
// bound to PKCE, bypassing every defence the PKCE flow is meant to
// provide.
//
// Tracks:
//   - CVE-2024-23647 (authentik ≤2023.10.6, CVSS 6.1) — token
//     endpoint accepted code_verifier on codes issued without a
//     challenge, enabling code-injection attacks.
//   - CVE-2025-4144 (Cloudflare workers-oauth-provider <0.0.5,
//     CVSS 8.1) — same downgrade variant, different ecosystem.
//   - RFC 9700 §4.8 (OAuth 2.0 Security BCP) which mandates this
//     posture: "the authorization server MUST [...] reject [a
//     verifier] if no code_challenge was registered with the code".
//   - RFC 7636 §4.6 PKCE definition.
//
// The defence lives at internal/grants/authcode/authcode.go:309-316:
// when the issued record's CodeChallenge is empty, any non-empty
// CodeVerifier on the exchange MUST yield [pkce.ErrVerifierMismatch].
// This test pins the contract; a regression that changed the empty-
// challenge branch to "ignore verifier" (which would seem ergonomic
// but is exactly the bypass) would surface here.
func TestExchange_NoPKCE_RejectsSmuggledVerifier(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	in := goodInput("ignored")
	in.CodeChallenge = ""
	in.CodeChallengeMethod = ""

	code, err := f.issuer.Issue(context.Background(), in)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, err = f.exchanger.Exchange(context.Background(), authcode.ExchangeInput{
		Code:         code,
		ClientID:     "client-1",
		RedirectURI:  "https://rp.example.com/cb",
		CodeVerifier: "smuggled-verifier-smuggled-verifier-smuggled-1234",
	})
	if !errors.Is(err, pkce.ErrVerifierMismatch) {
		t.Errorf("err=%v want ErrVerifierMismatch", err)
	}
}

func TestIssue_RejectsMissingFields(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	verifier := strings.Repeat("a", 64)

	cases := map[string]func(*authcode.IssueInput){
		"missing_client":   func(in *authcode.IssueInput) { in.ClientID = "" },
		"missing_subject":  func(in *authcode.IssueInput) { in.Subject = "" },
		"missing_redirect": func(in *authcode.IssueInput) { in.RedirectURI = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in := goodInput(verifier)
			mutate(&in)
			if _, err := f.issuer.Issue(context.Background(), in); err == nil {
				t.Error("Issue accepted incomplete input")
			}
		})
	}
}

func TestIssue_RejectsBadPKCE(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)

	in := goodInput(strings.Repeat("a", 64))
	in.CodeChallengeMethod = "plain"
	_, err := f.issuer.Issue(context.Background(), in)
	if !errors.Is(err, pkce.ErrChallengeMethodUnsupported) {
		t.Errorf("err=%v want ErrChallengeMethodUnsupported", err)
	}
}

func TestExchange_ReplayReturnsSentinel(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	verifier := strings.Repeat("a", 64)
	f := newFixture(t, t0)
	ctx := context.Background()

	code, err := f.issuer.Issue(ctx, goodInput(verifier))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	in := authcode.ExchangeInput{
		Code:         code,
		ClientID:     "client-1",
		RedirectURI:  "https://rp.example.com/cb",
		CodeVerifier: verifier,
	}
	if _, err := f.exchanger.Exchange(ctx, in); err != nil {
		t.Fatalf("first Exchange: %v", err)
	}
	if _, err := f.exchanger.Exchange(ctx, in); !errors.Is(err, authcode.ErrCodeReplayed) {
		t.Errorf("second Exchange err=%v want ErrCodeReplayed", err)
	}
}

func TestExchange_ReplayCarriesGrantIDWhenStoreReturnsConsumedRecord(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	verifier := strings.Repeat("a", 64)
	backing := newReplayMetadataCodeStore()
	issuer, err := authcode.NewIssuer(authcode.IssuerConfig{
		Store: backing,
		Clock: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	exchanger, err := authcode.NewExchanger(authcode.ExchangerConfig{
		Store: backing,
		Clock: func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}
	ctx := context.Background()
	code, err := issuer.Issue(ctx, goodInput(verifier))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	in := authcode.ExchangeInput{
		Code:         code,
		ClientID:     "client-1",
		RedirectURI:  "https://rp.example.com/cb",
		CodeVerifier: verifier,
	}
	if _, err := exchanger.Exchange(ctx, in); err != nil {
		t.Fatalf("first Exchange: %v", err)
	}
	_, err = exchanger.Exchange(ctx, in)
	if !errors.Is(err, authcode.ErrCodeReplayed) {
		t.Fatalf("second Exchange err=%v want ErrCodeReplayed", err)
	}
	if got := authcode.ReplayGrantID(err); got != "grant-1" {
		t.Fatalf("ReplayGrantID=%q want grant-1", got)
	}
	if _, err := backing.Find(ctx, code); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find after replay err=%v want ErrNotFound", err)
	}
}

// TestExchange_RejectsClientMismatch pins the (code, client_id) half
// of RFC 6749 §4.1.3's tuple-binding contract: a code issued to one
// client MUST NOT be exchangeable by another client, regardless of
// who else holds the value.
//
// Tracks: GHSA-vh7g-p26c-j2cw (dexidp/dex, 2024) — the back-channel
// ID-token retrieval path did not re-check the authorization-code's
// bound client_id, so an attacker who intercepted a code at the front
// channel could redeem it under a different client_id and obtain
// tokens minted for the victim. The structural mitigation is the
// (code, client_id, redirect_uri[, code_verifier]) tuple match — this
// test pins the client_id half; sibling tests pin redirect_uri and
// code_verifier.
func TestExchange_RejectsClientMismatch(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	verifier := strings.Repeat("a", 64)
	f := newFixture(t, t0)
	ctx := context.Background()

	code, err := f.issuer.Issue(ctx, goodInput(verifier))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, err = f.exchanger.Exchange(ctx, authcode.ExchangeInput{
		Code:         code,
		ClientID:     "other-client",
		RedirectURI:  "https://rp.example.com/cb",
		CodeVerifier: verifier,
	})
	if !errors.Is(err, authcode.ErrClientMismatch) {
		t.Errorf("err=%v want ErrClientMismatch", err)
	}
}

func TestExchange_RejectsRedirectMismatch(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	verifier := strings.Repeat("a", 64)
	f := newFixture(t, t0)
	ctx := context.Background()

	code, err := f.issuer.Issue(ctx, goodInput(verifier))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, err = f.exchanger.Exchange(ctx, authcode.ExchangeInput{
		Code:         code,
		ClientID:     "client-1",
		RedirectURI:  "https://rp.example.com/elsewhere",
		CodeVerifier: verifier,
	})
	if !errors.Is(err, authcode.ErrRedirectURIMismatch) {
		t.Errorf("err=%v want ErrRedirectURIMismatch", err)
	}
}

func TestExchange_RejectsBadVerifier(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	verifier := strings.Repeat("a", 64)
	f := newFixture(t, t0)
	ctx := context.Background()

	code, err := f.issuer.Issue(ctx, goodInput(verifier))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, err = f.exchanger.Exchange(ctx, authcode.ExchangeInput{
		Code:         code,
		ClientID:     "client-1",
		RedirectURI:  "https://rp.example.com/cb",
		CodeVerifier: strings.Repeat("b", 64),
	})
	if !errors.Is(err, pkce.ErrVerifierMismatch) {
		t.Errorf("err=%v want ErrVerifierMismatch", err)
	}
}

func TestExchange_RejectsMissingCode(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	_, err := f.exchanger.Exchange(context.Background(), authcode.ExchangeInput{
		Code:        "",
		ClientID:    "client-1",
		RedirectURI: "https://rp.example.com/cb",
	})
	if !errors.Is(err, authcode.ErrCodeMissing) {
		t.Errorf("empty code: err=%v want ErrCodeMissing", err)
	}
	_, err = f.exchanger.Exchange(context.Background(), authcode.ExchangeInput{
		Code:        "no-such-code",
		ClientID:    "client-1",
		RedirectURI: "https://rp.example.com/cb",
	})
	if !errors.Is(err, authcode.ErrCodeMissing) {
		t.Errorf("unknown code: err=%v want ErrCodeMissing", err)
	}
}

func TestExchange_DetectsExpiredCode(t *testing.T) {
	t.Parallel()

	// Use a custom store that does NOT expire on read so the exchanger's
	// own clock-based check is exercised. The default inmem store treats
	// expired records as ErrNotFound at Consume; we want to observe the
	// authcode-layer's expiry sentinel instead.
	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	verifier := strings.Repeat("a", 64)
	st := newAlwaysAliveCodeStore()
	cur := t0
	iss, err := authcode.NewIssuer(authcode.IssuerConfig{
		Store: st,
		Clock: func() time.Time { return cur },
		TTL:   60 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	exc, err := authcode.NewExchanger(authcode.ExchangerConfig{
		Store: st,
		Clock: func() time.Time { return cur },
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}
	code, err := iss.Issue(context.Background(), goodInput(verifier))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cur = t0.Add(2 * time.Minute) // 2 min > 60s default TTL
	_, err = exc.Exchange(context.Background(), authcode.ExchangeInput{
		Code:         code,
		ClientID:     "client-1",
		RedirectURI:  "https://rp.example.com/cb",
		CodeVerifier: verifier,
	})
	if !errors.Is(err, authcode.ErrCodeExpired) {
		t.Errorf("err=%v want ErrCodeExpired", err)
	}
}

// alwaysAliveCodeStore is a test-local AuthorizationCodeStore that does no
// expiry filtering at any layer. It exists so the authcode package's own
// clock-based ErrCodeExpired check is exercised end-to-end; a real backing
// store would surface ErrNotFound for an expired record before the
// exchanger ran its own check.
type alwaysAliveCodeStore struct {
	mu sync.Mutex
	m  map[string]*store.AuthorizationCode
}

func newAlwaysAliveCodeStore() *alwaysAliveCodeStore {
	return &alwaysAliveCodeStore{m: make(map[string]*store.AuthorizationCode)}
}

func (s *alwaysAliveCodeStore) Save(_ context.Context, code *store.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[code.ID]; exists {
		return store.ErrAlreadyExists
	}
	clone := *code
	s.m[code.ID] = &clone
	return nil
}

func (s *alwaysAliveCodeStore) Find(_ context.Context, id string) (*store.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	clone := *rec
	return &clone, nil
}

func (s *alwaysAliveCodeStore) Consume(ctx context.Context, id string) (*store.AuthorizationCode, error) {
	rec, err := s.Find(ctx, id)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	rec.ConsumedAt = &now
	return rec, nil
}

// replayMetadataCodeStore simulates backends that hide consumed rows from Find
// while still returning the consumed record from the atomic Consume replay path.
type replayMetadataCodeStore struct {
	mu sync.Mutex
	m  map[string]*store.AuthorizationCode
}

func newReplayMetadataCodeStore() *replayMetadataCodeStore {
	return &replayMetadataCodeStore{m: make(map[string]*store.AuthorizationCode)}
}

func (s *replayMetadataCodeStore) Save(_ context.Context, code *store.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[code.ID]; exists {
		return store.ErrAlreadyExists
	}
	clone := *code
	clone.Scope = append([]string(nil), code.Scope...)
	s.m[code.ID] = &clone
	return nil
}

func (s *replayMetadataCodeStore) Find(_ context.Context, id string) (*store.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok || rec.ConsumedAt != nil {
		return nil, store.ErrNotFound
	}
	clone := *rec
	clone.Scope = append([]string(nil), rec.Scope...)
	return &clone, nil
}

func (s *replayMetadataCodeStore) Consume(_ context.Context, id string) (*store.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	clone := *rec
	clone.Scope = append([]string(nil), rec.Scope...)
	if rec.ConsumedAt != nil {
		return &clone, store.ErrAlreadyConsumed
	}
	now := time.Now().UTC()
	rec.ConsumedAt = &now
	clone.ConsumedAt = &now
	return &clone, nil
}
