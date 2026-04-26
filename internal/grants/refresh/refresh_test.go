package refresh_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// movingClock satisfies inmem.Clock and reads the current value of the
// pointer it wraps so the test fixture's clock advances are observed by
// the store's own ConsumedAt stamping.
type movingClock struct{ cur *time.Time }

func (c movingClock) Now() time.Time { return *c.cur }

type fixture struct {
	issuer    *refresh.Issuer
	exchanger *refresh.Exchanger
	store     store.RefreshTokenStore
	cur       *time.Time
}

func newFixture(tb testing.TB, t0 time.Time) fixture {
	tb.Helper()
	cur := t0
	clk := func() time.Time { return cur }
	st := inmem.New(inmem.WithClock(movingClock{cur: &cur})).RefreshTokens()
	iss, err := refresh.NewIssuer(refresh.IssuerConfig{Store: st, Clock: clk, TTL: 24 * time.Hour})
	if err != nil {
		tb.Fatalf("NewIssuer: %v", err)
	}
	exc, err := refresh.NewExchanger(refresh.ExchangerConfig{Store: st, Clock: clk})
	if err != nil {
		tb.Fatalf("NewExchanger: %v", err)
	}
	return fixture{issuer: iss, exchanger: exc, store: st, cur: &cur}
}

func goodIssue() refresh.IssueInput {
	return refresh.IssueInput{
		ClientID: "client-1",
		Subject:  "user-1",
		GrantID:  "grant-1",
		Scope:    []string{"openid", "profile", "email"},
	}
}

func TestNewIssuer_RejectsMissingStore(t *testing.T) {
	t.Parallel()
	if _, err := refresh.NewIssuer(refresh.IssuerConfig{}); err == nil {
		t.Error("NewIssuer accepted empty config")
	}
}

func TestNewExchanger_RejectsMissingStore(t *testing.T) {
	t.Parallel()
	if _, err := refresh.NewExchanger(refresh.ExchangerConfig{}); err == nil {
		t.Error("NewExchanger accepted empty config")
	}
}

func TestIssue_AndExchange_RoundTrip(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	tok, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok == "" {
		t.Fatal("Issue returned empty token")
	}

	out, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:    tok,
		ClientID: "client-1",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if out.ConsumedID != tok {
		t.Errorf("ConsumedID=%q want %q", out.ConsumedID, tok)
	}
	if out.Subject != "user-1" || out.GrantID != "grant-1" {
		t.Errorf("Subject/GrantID mismatch: %+v", out)
	}
	if got := out.Scope; len(got) != 3 || got[0] != "openid" {
		t.Errorf("Scope=%v want [openid profile email]", got)
	}
	if !out.ConsumedAt.Equal(t0) {
		t.Errorf("ConsumedAt=%v want %v", out.ConsumedAt, t0)
	}
}

func TestIssue_RejectsMissingFields(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)

	cases := map[string]func(*refresh.IssueInput){
		"missing_client":  func(in *refresh.IssueInput) { in.ClientID = "" },
		"missing_subject": func(in *refresh.IssueInput) { in.Subject = "" },
		"missing_scope":   func(in *refresh.IssueInput) { in.Scope = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in := goodIssue()
			mutate(&in)
			if _, err := f.issuer.Issue(context.Background(), in); err == nil {
				t.Error("Issue accepted incomplete input")
			}
		})
	}
}

func TestExchange_MissingToken(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	_, err := f.exchanger.Exchange(context.Background(), refresh.ExchangeInput{
		Token:    "",
		ClientID: "client-1",
	})
	if !errors.Is(err, refresh.ErrTokenMissing) {
		t.Errorf("empty token: err=%v want ErrTokenMissing", err)
	}
	_, err = f.exchanger.Exchange(context.Background(), refresh.ExchangeInput{
		Token:    "no-such-token",
		ClientID: "client-1",
	})
	if !errors.Is(err, refresh.ErrTokenMissing) {
		t.Errorf("unknown token: err=%v want ErrTokenMissing", err)
	}
}

func TestExchange_RejectsClientMismatch(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	tok, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, err = f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:    tok,
		ClientID: "other-client",
	})
	if !errors.Is(err, refresh.ErrClientMismatch) {
		t.Errorf("err=%v want ErrClientMismatch", err)
	}
}

func TestExchange_RotatesViaParentID(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	tok1, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue#1: %v", err)
	}
	out, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: tok1, ClientID: "client-1"})
	if err != nil {
		t.Fatalf("Exchange#1: %v", err)
	}
	parent := out.ConsumedID
	tok2, err := f.issuer.Issue(ctx, refresh.IssueInput{
		ClientID: out.ClientID,
		Subject:  out.Subject,
		GrantID:  out.GrantID,
		Scope:    out.Scope,
		ParentID: &parent,
	})
	if err != nil {
		t.Fatalf("Issue#2: %v", err)
	}
	rec, err := f.store.Find(ctx, tok2)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if rec.ParentID == nil || *rec.ParentID != parent {
		t.Fatalf("ParentID=%v want %q", rec.ParentID, parent)
	}
}

func TestExchange_ReplayRevokesEntireChain(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	root, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue#1: %v", err)
	}
	out, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"})
	if err != nil {
		t.Fatalf("Exchange#1: %v", err)
	}
	parent := out.ConsumedID
	child, err := f.issuer.Issue(ctx, refresh.IssueInput{
		ClientID: out.ClientID,
		Subject:  out.Subject,
		GrantID:  out.GrantID,
		Scope:    out.Scope,
		ParentID: &parent,
	})
	if err != nil {
		t.Fatalf("Issue#2: %v", err)
	}

	// Replay the root: the exchanger must walk to the chain root and
	// revoke every descendant — including the live child token.
	_, err = f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"})
	if !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay err=%v want ErrTokenReplayed", err)
	}
	// The child must now be observed as consumed: a fresh exchange of it
	// yields ErrTokenReplayed too because RevokeChain stamped ConsumedAt.
	_, err = f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: child, ClientID: "client-1"})
	if !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Errorf("child after revoke: err=%v want ErrTokenReplayed", err)
	}
}

func TestExchange_ScopeNarrowingAccepted(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	tok, err := f.issuer.Issue(ctx, goodIssue()) // scope: openid profile email
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	out, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:          tok,
		ClientID:       "client-1",
		RequestedScope: []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got := out.Scope; len(got) != 2 || got[0] != "openid" || got[1] != "profile" {
		t.Errorf("narrowed scope=%v", got)
	}
}

func TestExchange_RejectsScopeWidening(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	tok, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, err = f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:          tok,
		ClientID:       "client-1",
		RequestedScope: []string{"openid", "phone"}, // phone not bound
	})
	if !errors.Is(err, refresh.ErrScopeWidening) {
		t.Errorf("err=%v want ErrScopeWidening", err)
	}
}

func TestExchange_DetectsExpiredToken(t *testing.T) {
	t.Parallel()

	// Use a custom store that does NOT expire on read so the exchanger's
	// own clock-based check is exercised. Mirrors the authcode test.
	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	st := newAlwaysAliveRefreshStore()
	cur := t0
	iss, err := refresh.NewIssuer(refresh.IssuerConfig{
		Store: st,
		Clock: func() time.Time { return cur },
		TTL:   60 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	exc, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store: st,
		Clock: func() time.Time { return cur },
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}
	tok, err := iss.Issue(context.Background(), goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cur = t0.Add(2 * time.Minute)
	_, err = exc.Exchange(context.Background(), refresh.ExchangeInput{
		Token:    tok,
		ClientID: "client-1",
	})
	if !errors.Is(err, refresh.ErrTokenExpired) {
		t.Errorf("err=%v want ErrTokenExpired", err)
	}
}

// alwaysAliveRefreshStore is a test-local RefreshTokenStore that does no
// expiry filtering at any layer. It exists so the refresh package's own
// clock-based ErrTokenExpired check is exercised end-to-end; a real
// backing store would surface ErrNotFound for an expired record before
// the exchanger ran its own check.
type alwaysAliveRefreshStore struct {
	mu sync.Mutex
	m  map[string]*store.RefreshToken
}

func newAlwaysAliveRefreshStore() *alwaysAliveRefreshStore {
	return &alwaysAliveRefreshStore{m: make(map[string]*store.RefreshToken)}
}

func (s *alwaysAliveRefreshStore) Save(_ context.Context, tok *store.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[tok.ID]; exists {
		return store.ErrAlreadyExists
	}
	clone := *tok
	s.m[tok.ID] = &clone
	return nil
}

func (s *alwaysAliveRefreshStore) Find(_ context.Context, id string) (*store.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	clone := *rec
	return &clone, nil
}

func (s *alwaysAliveRefreshStore) Consume(ctx context.Context, id string) (*store.RefreshToken, error) {
	rec, err := s.Find(ctx, id)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	rec.ConsumedAt = &now
	return rec, nil
}

func (s *alwaysAliveRefreshStore) RevokeChain(_ context.Context, rootID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if rec, ok := s.m[rootID]; ok {
		rec.ConsumedAt = &now
	}
	for _, rec := range s.m {
		if rec.ParentID != nil && *rec.ParentID == rootID {
			rec.ConsumedAt = &now
		}
	}
	return nil
}
