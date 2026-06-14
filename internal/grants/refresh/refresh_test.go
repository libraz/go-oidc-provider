package refresh_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
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

	// Step past the RFC 9700 §2.2.2 grace window so the second
	// presentation is treated as a true replay rather than an
	// idempotent retry. One second beyond [refresh.GraceTTLDefault]
	// is enough to observe the strict path.
	*f.cur = f.cur.Add(refresh.GraceTTLDefault + time.Second)

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

func TestExchange_ReplayDoesNotRevokeCrossClientParentLink(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	st := newAlwaysAliveRefreshStoreWithClock(func() time.Time { return t0 })
	exc, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store:    st,
		Clock:    func() time.Time { return t0 },
		GraceTTL: -1,
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}
	parentID := "victim-root"
	consumedAt := t0.Add(-2 * time.Minute)
	if err := st.Save(ctx, &store.RefreshToken{
		ID:        parentID,
		ClientID:  "victim-client",
		Subject:   "victim-user",
		GrantID:   "victim-grant",
		Scope:     []string{"openid"},
		ExpiresAt: t0.Add(time.Hour),
		CreatedAt: t0.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Save parent: %v", err)
	}
	if err := st.Save(ctx, &store.RefreshToken{
		ID:         "attacker-child",
		ClientID:   "client-1",
		Subject:    "user-1",
		GrantID:    "grant-1",
		Scope:      []string{"openid"},
		ParentID:   &parentID,
		ConsumedAt: &consumedAt,
		ExpiresAt:  t0.Add(time.Hour),
		CreatedAt:  t0.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("Save child: %v", err)
	}

	_, err = exc.Exchange(ctx, refresh.ExchangeInput{Token: "attacker-child", ClientID: "client-1"})
	if !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("Exchange err=%v want ErrTokenReplayed", err)
	}
	parent, err := st.Find(ctx, parentID)
	if err != nil {
		t.Fatalf("Find parent: %v", err)
	}
	if parent.ConsumedAt != nil {
		t.Fatalf("cross-client parent was revoked at %v", parent.ConsumedAt)
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

// TestExchange_ScopeUpgradeAttacks_AllRejected hardens the
// scope-widening defence with the attack patterns that have surfaced
// in real-world OAuth implementations. Per RFC 6749 §6 the requested
// scope MUST NOT include any value that was not originally granted.
//
// Tracks: RFC 6749 §6 (scope reduction is the only legal narrowing
// operation), and the broad class of "scope upgrade" defects exemplified
// by GHSA advisories filed against ory/fosite around 2020 (scope upgrade
// / scope grant misinterpretation, fixed in v0.31.x — pre-CVE era for
// fosite, but the same threat shape recurs across implementations).
// The attack pattern is: an attacker who has captured a refresh token
// asks /token to issue a wider access-token scope than the original
// grant.
func TestExchange_ScopeUpgradeAttacks_AllRejected(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	cases := []struct {
		name      string
		requested []string
		why       string
	}{
		{"add_unknown_scope", []string{"openid", "profile", "email", "phone"}, "phone never granted"},
		{"add_admin", []string{"openid", "profile", "email", "admin"}, "privilege-escalation flavor"},
		{"add_wildcard", []string{"openid", "profile", "email", "*"}, "literal wildcard must not be honoured"},
		{"replace_scope", []string{"phone"}, "narrowing-with-substitution must reject"},
		{"add_scope_only", []string{"openid", "profile", "email", "offline_access"}, "offline_access never granted"},
		{"case_variant_uppercase", []string{"OPENID", "profile", "email"}, "scope is case-sensitive per RFC 6749 §3.3"},
		{"case_variant_mixed", []string{"OpenID", "profile", "email"}, "case-sensitivity again"},
		{"unicode_lookalike", []string{"оpenid", "profile", "email"}, "Cyrillic 'о' instead of Latin 'o'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, t0)
			tok, err := f.issuer.Issue(ctx, goodIssue())
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			_, err = f.exchanger.Exchange(ctx, refresh.ExchangeInput{
				Token:          tok,
				ClientID:       "client-1",
				RequestedScope: tc.requested,
			})
			if !errors.Is(err, refresh.ErrScopeWidening) {
				t.Fatalf("requested=%v err=%v want ErrScopeWidening (%s)", tc.requested, err, tc.why)
			}
		})
	}
}

// TestExchange_ScopeReorderAccepted pins the legitimate companion
// behaviour: a request that contains the same scope set in a
// different order is accepted (RFC 6749 §3.3 says scope is a
// space-separated list with order-irrelevant semantics). Without
// this pin a future implementer could "fix" the upgrade-attack tests
// by accidentally enforcing order equality, breaking conformance.
func TestExchange_ScopeReorderAccepted(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	tok, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	out, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:          tok,
		ClientID:       "client-1",
		RequestedScope: []string{"email", "openid", "profile"}, // reordered subset.
	})
	if err != nil {
		t.Fatalf("Exchange reordered subset: %v", err)
	}
	if len(out.Scope) != 3 {
		t.Fatalf("Scope=%v want 3 entries", out.Scope)
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

// TestExchange_GraceWindow_ReturnsInGrace covers the RFC 9700 §2.2.2
// grace path: a refresh token presented again within the configured
// window after a successful rotation must be accepted, the response
// must NOT issue a new refresh token, and the InGrace flag must be set.
func TestExchange_GraceWindow_ReturnsInGrace(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	root, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	first, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"})
	if err != nil {
		t.Fatalf("Exchange#1: %v", err)
	}
	if first.InGrace {
		t.Fatalf("first exchange must not be marked InGrace")
	}
	parent := first.ConsumedID
	if _, err := f.issuer.Issue(ctx, refresh.IssueInput{
		ClientID: first.ClientID,
		Subject:  first.Subject,
		GrantID:  first.GrantID,
		Scope:    first.Scope,
		ParentID: &parent,
	}); err != nil {
		t.Fatalf("Issue child: %v", err)
	}

	// Re-present the original token well inside the grace window.
	*f.cur = f.cur.Add(refresh.GraceTTLDefault / 2)
	again, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"})
	if err != nil {
		t.Fatalf("grace Exchange: %v", err)
	}
	if !again.InGrace {
		t.Errorf("grace Exchange InGrace=false want true")
	}
	if again.ConsumedID != root {
		t.Errorf("grace ConsumedID=%q want %q", again.ConsumedID, root)
	}
	if got, want := again.Subject, first.Subject; got != want {
		t.Errorf("grace Subject=%q want %q", got, want)
	}
}

func TestExchange_GraceWindow_PreservesRefreshContext(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()
	in := goodIssue()
	in.Resource = "https://api.example.com"
	in.Origin = store.RefreshOriginCustomGrant
	in.SubjectPublic = true
	in.AuthTime = t0.Add(-5 * time.Minute)
	in.ACR = "urn:acr:pwd"
	in.AMR = []string{"pwd", "otp"}
	in.AuthorizationDetails = []map[string]any{{"type": "payment"}}
	in.AccessTokenExtra = map[string]any{"act": map[string]any{"sub": "actor"}}

	root, err := f.issuer.Issue(ctx, in)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); err != nil {
		t.Fatalf("Exchange#1: %v", err)
	}
	*f.cur = f.cur.Add(refresh.GraceTTLDefault / 2)
	again, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"})
	if err != nil {
		t.Fatalf("grace Exchange: %v", err)
	}
	if !again.InGrace {
		t.Fatal("grace Exchange InGrace=false want true")
	}
	if again.Resource != in.Resource || again.Origin != in.Origin || !again.SubjectPublic {
		t.Fatalf("context mismatch: resource=%q origin=%q subjectPublic=%v", again.Resource, again.Origin, again.SubjectPublic)
	}
	if !again.AuthTime.Equal(in.AuthTime) || again.ACR != in.ACR {
		t.Fatalf("auth context mismatch: auth_time=%v acr=%q", again.AuthTime, again.ACR)
	}
	if len(again.AuthorizationDetails) != 1 || again.AuthorizationDetails[0]["type"] != "payment" {
		t.Fatalf("authorization_details=%v", again.AuthorizationDetails)
	}
	if len(again.AccessTokenExtra) == 0 {
		t.Fatal("access token extra not preserved")
	}
}

// TestExchange_GraceWindow_ExpiredFallsBackToReplay confirms that
// re-presenting a consumed token after the grace TTL has elapsed
// surfaces the strict replay error and revokes the chain.
func TestExchange_GraceWindow_ExpiredFallsBackToReplay(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	root, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); err != nil {
		t.Fatalf("Exchange#1: %v", err)
	}
	*f.cur = f.cur.Add(refresh.GraceTTLDefault + time.Second)
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Errorf("post-grace err=%v want ErrTokenReplayed", err)
	}
}

// TestExchange_GraceWindow_ClientMismatchRevokes ensures a different
// client presenting the consumed token within the grace window is
// rejected as replay (no idempotent re-emission across clients).
func TestExchange_GraceWindow_ClientMismatchRevokes(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	root, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); err != nil {
		t.Fatalf("Exchange#1: %v", err)
	}
	*f.cur = f.cur.Add(refresh.GraceTTLDefault / 4)
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-2"}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Errorf("cross-client err=%v want ErrTokenReplayed", err)
	}
}

// TestExchange_GraceWindow_MismatchInsideWindowRevokesChain pins the
// RFC 9700 §2.2.2 contract that a credential mismatch inside the
// grace window MUST revoke the rotation chain. The original audit
// concern (H-GRANT-2): if [Exchanger.tryGrace] surfaces ok=false on
// validation failure without revoking, an attacker who learned a
// just-rotated refresh token before its successor reaches the
// legitimate client could keep replaying it (with a different
// client_id) until the grace window expires. The chain root MUST be
// revoked the moment the mismatch is observed; subsequent presentation
// of the live successor MUST also be rejected.
func TestExchange_GraceWindow_MismatchInsideWindowRevokesChain(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	root, err := f.issuer.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	first, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"})
	if err != nil {
		t.Fatalf("Exchange#1: %v", err)
	}
	parent := first.ConsumedID
	child, err := f.issuer.Issue(ctx, refresh.IssueInput{
		ClientID: first.ClientID,
		Subject:  first.Subject,
		GrantID:  first.GrantID,
		Scope:    first.Scope,
		ParentID: &parent,
	})
	if err != nil {
		t.Fatalf("Issue child: %v", err)
	}

	// Within the grace window, an attacker re-presents the original
	// token but claims a different client. tryGrace must NOT emit
	// an InGrace projection AND must revoke the chain so the live
	// successor is invalidated.
	*f.cur = f.cur.Add(refresh.GraceTTLDefault / 4)
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:    root,
		ClientID: "client-2",
	}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("mismatch in grace window err=%v want ErrTokenReplayed", err)
	}

	// The legitimate successor MUST now be rejected: revoking the
	// chain at the mismatch point is the whole point of the cascade.
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:    child,
		ClientID: "client-1",
	}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Errorf("successor after grace-window mismatch err=%v want ErrTokenReplayed (chain not revoked)", err)
	}
}

// TestExchange_GraceWindow_ScopeWideningInsideWindowRevokesChain
// covers the second mismatch shape: an attacker who captured the
// just-consumed refresh token re-presents it with a widened scope
// before the grace window expires. RFC 9700 §2.2.2 / §A.12.5 still
// requires chain revocation — scope widening on a consumed token is
// the same threat shape as client_id mismatch.
func TestExchange_GraceWindow_ScopeWideningInsideWindowRevokesChain(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	f := newFixture(t, t0)
	ctx := context.Background()

	root, err := f.issuer.Issue(ctx, goodIssue()) // scope: openid profile email
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	first, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"})
	if err != nil {
		t.Fatalf("Exchange#1: %v", err)
	}
	parent := first.ConsumedID
	child, err := f.issuer.Issue(ctx, refresh.IssueInput{
		ClientID: first.ClientID,
		Subject:  first.Subject,
		GrantID:  first.GrantID,
		Scope:    first.Scope,
		ParentID: &parent,
	})
	if err != nil {
		t.Fatalf("Issue child: %v", err)
	}

	*f.cur = f.cur.Add(refresh.GraceTTLDefault / 3)
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:          root,
		ClientID:       "client-1",
		RequestedScope: []string{"openid", "profile", "email", "admin"},
	}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("scope-widening in grace window err=%v want ErrTokenReplayed", err)
	}
	if _, err := f.exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:    child,
		ClientID: "client-1",
	}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Errorf("successor after scope-widening mismatch err=%v want ErrTokenReplayed", err)
	}
}

// TestExchange_GraceWindow_BoundaryTable pins the boundary semantics
// of the configured grace window: 0s (strict),
// 30s (default), 31s (one second past default), and 24h (a custom
// override). The check shape is identical across rows; the elapsed
// time relative to GraceTTL is the only varying axis.
func TestExchange_GraceWindow_BoundaryTable(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		grace     time.Duration // ExchangerConfig.GraceTTL
		elapsed   time.Duration // wall-clock advance after the first Exchange
		wantGrace bool          // true = expect InGrace projection, false = expect ErrTokenReplayed
	}{
		// FAPI 2.0 strict mode: any second presentation is a replay.
		{"strict_zero_disabled", -1, 0, false},
		{"strict_zero_disabled_one_sec", -1, time.Second, false},

		// Default 60s window: boundary cases around GraceTTLDefault.
		{"default_at_zero", 0, 0, true},
		{"default_at_29s", 0, 29 * time.Second, true},
		{"default_at_default", 0, refresh.GraceTTLDefault, true},
		{"default_at_default_plus_1s", 0, refresh.GraceTTLDefault + time.Second, false},
		{"default_at_2x_default", 0, 2 * refresh.GraceTTLDefault, false},

		// Custom 24h window (long-lived refresh requirement).
		{"long_at_23h", 24 * time.Hour, 23 * time.Hour, true},
		{"long_at_24h", 24 * time.Hour, 24 * time.Hour, true},
		{"long_at_24h_plus_1s", 24 * time.Hour, 24*time.Hour + time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cur := t0
			clk := func() time.Time { return cur }
			st := inmem.New(inmem.WithClock(movingClock{cur: &cur})).RefreshTokens()
			iss, err := refresh.NewIssuer(refresh.IssuerConfig{Store: st, Clock: clk, TTL: 30 * 24 * time.Hour})
			if err != nil {
				t.Fatalf("NewIssuer: %v", err)
			}
			exc, err := refresh.NewExchanger(refresh.ExchangerConfig{Store: st, Clock: clk, GraceTTL: tc.grace})
			if err != nil {
				t.Fatalf("NewExchanger: %v", err)
			}
			ctx := context.Background()
			root, err := iss.Issue(ctx, goodIssue())
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); err != nil {
				t.Fatalf("first Exchange: %v", err)
			}
			cur = cur.Add(tc.elapsed)
			out, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"})
			if tc.wantGrace {
				if err != nil {
					t.Fatalf("grace=%v elapsed=%v err=%v want InGrace success", tc.grace, tc.elapsed, err)
				}
				if !out.InGrace {
					t.Errorf("grace=%v elapsed=%v InGrace=false want true", tc.grace, tc.elapsed)
				}
			} else if !errors.Is(err, refresh.ErrTokenReplayed) {
				t.Errorf("grace=%v elapsed=%v err=%v want ErrTokenReplayed", tc.grace, tc.elapsed, err)
			}
		})
	}
}

// alwaysAliveRefreshStore is a test-local RefreshTokenStore that does no
// expiry filtering at any layer. It exists so the refresh package's own
// clock-based ErrTokenExpired check is exercised end-to-end; a real
// backing store would surface ErrNotFound for an expired record before
// the exchanger ran its own check.
type alwaysAliveRefreshStore struct {
	mu  sync.Mutex
	m   map[string]*store.RefreshToken
	now func() time.Time
}

func newAlwaysAliveRefreshStore() *alwaysAliveRefreshStore {
	return &alwaysAliveRefreshStore{m: make(map[string]*store.RefreshToken), now: func() time.Time { return time.Now().UTC() }}
}

// withClock returns a fresh store backed by the supplied clock so the
// ConsumedAt timestamp the store stamps is deterministic relative to
// the exchanger's own clock; without this hook a wall-clock stamping
// would race the test's frozen clock and the grace-window arithmetic
// would diverge.
func newAlwaysAliveRefreshStoreWithClock(now func() time.Time) *alwaysAliveRefreshStore {
	return &alwaysAliveRefreshStore{m: make(map[string]*store.RefreshToken), now: now}
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

func (s *alwaysAliveRefreshStore) Consume(_ context.Context, id string) (*store.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
	}
	now := s.now().UTC()
	rec.ConsumedAt = &now
	clone := *rec
	return &clone, nil
}

func (s *alwaysAliveRefreshStore) RevokeChain(_ context.Context, rootID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
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

func (s *alwaysAliveRefreshStore) RevokeByGrant(_ context.Context, grantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	for _, rec := range s.m {
		if rec.GrantID == grantID && rec.ConsumedAt == nil {
			rec.ConsumedAt = &now
		}
	}
	return nil
}

// TestExchange_GraceWindow_ExpiredTokenSurfacesExpired pins H-A1: a
// refresh token whose ExpiresAt has elapsed but whose ConsumedAt is
// inside the grace window MUST surface ErrTokenExpired rather than
// minting a fresh access token via the grace path. The audit concern
// was that the strict (non-grace) path checks ExpiresAt after Consume
// while the grace path runs against a Find-only record; without an
// explicit gate, an expired token would still be honoured inside the
// grace window because the grace check only consults ConsumedAt.
//
// This test uses the alwaysAliveRefreshStore so the expiry filter
// the inmem reference adapter applies on Find does not short-circuit
// the grace path before it reaches the new gate. A real backing
// store typically expires reads (mirroring the inmem posture); the
// test exercises the exchanger's own clock-based check end-to-end.
//
// Timeline:
//
//	t0          : Issue (TTL=90s, ExpiresAt = t0+90s)
//	t0 +  85s   : Exchange#1 succeeds (ConsumedAt = t0+85s)
//	t0 +  95s   : Exchange#2 attempted. elapsed = 10s (well inside the
//	              60s grace window) but the record is expired
//	              (clock > ExpiresAt). The exchanger MUST surface
//	              ErrTokenExpired and MUST NOT cascade the chain
//	              revoke (expiry is the record's contract; the chain
//	              is otherwise intact).
func TestExchange_GraceWindow_ExpiredTokenSurfacesExpired(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	cur := t0
	clk := func() time.Time { return cur }
	st := newAlwaysAliveRefreshStoreWithClock(clk)
	iss, err := refresh.NewIssuer(refresh.IssuerConfig{Store: st, Clock: clk, TTL: 90 * time.Second})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	exc, err := refresh.NewExchanger(refresh.ExchangerConfig{Store: st, Clock: clk})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}
	ctx := context.Background()

	root, err := iss.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Move close to (but before) expiry, then consume.
	cur = cur.Add(85 * time.Second)
	if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); err != nil {
		t.Fatalf("Exchange#1: %v", err)
	}
	// Advance past expiry but well inside the grace window. Without
	// the H-A1 gate, the grace path would mint a fresh access token
	// idempotently; with the gate, it surfaces invalid_grant via
	// ErrTokenExpired.
	cur = cur.Add(10 * time.Second)
	if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); !errors.Is(err, refresh.ErrTokenExpired) {
		t.Errorf("expired-in-grace err=%v want ErrTokenExpired", err)
	}
}

func TestExchange_GraceWindow_FindFaultDoesNotRevokeChain(t *testing.T) {
	t.Parallel()

	st := &graceFindFaultStore{err: errors.New("redis unavailable")}
	exc, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store: st,
		Clock: func() time.Time {
			return time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}

	_, err = exc.Exchange(context.Background(), refresh.ExchangeInput{Token: "rt-1", ClientID: "client-1"})
	if err == nil || errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("Exchange err=%v want non-replay store fault", err)
	}
	if st.revoked {
		t.Fatal("grace lookup transport fault triggered RevokeChain")
	}
}

// recordingEmitter is a test-local audit.Emitter that captures every
// emitted event for inspection.
type recordingEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

// Emit implements audit.Emitter.
func (r *recordingEmitter) Emit(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingEmitter) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.Event, len(r.events))
	copy(out, r.events)
	return out
}

// failingChainStore wraps a [store.RefreshTokenStore] and substitutes
// a synthetic transport fault for [RefreshTokenStore.RevokeChain]
// while passing every other call through. Used to drive the H-A2
// audit signal without breaking the rest of the cascade contract.
type failingChainStore struct {
	store.RefreshTokenStore
	err error
}

func (s *failingChainStore) RevokeChain(_ context.Context, _ string) error {
	return s.err
}

type graceFindFaultStore struct {
	err     error
	revoked bool
}

func (s *graceFindFaultStore) Save(context.Context, *store.RefreshToken) error { return nil }

func (s *graceFindFaultStore) Find(context.Context, string) (*store.RefreshToken, error) {
	return nil, s.err
}

func (s *graceFindFaultStore) Consume(context.Context, string) (*store.RefreshToken, error) {
	return nil, store.ErrAlreadyConsumed
}

func (s *graceFindFaultStore) RevokeChain(context.Context, string) error {
	s.revoked = true
	return nil
}

func (s *graceFindFaultStore) RevokeByGrant(context.Context, string) error { return nil }

type rootLookupFaultStore struct {
	rec     *store.RefreshToken
	revoked bool
}

func (s *rootLookupFaultStore) Save(context.Context, *store.RefreshToken) error { return nil }

func (s *rootLookupFaultStore) Find(_ context.Context, id string) (*store.RefreshToken, error) {
	if id == s.rec.ID {
		return s.rec, nil
	}
	return nil, store.ErrNotFound
}

func (s *rootLookupFaultStore) Consume(context.Context, string) (*store.RefreshToken, error) {
	return s.rec, store.ErrAlreadyConsumed
}

func (s *rootLookupFaultStore) RevokeChain(context.Context, string) error {
	s.revoked = true
	return nil
}

func (s *rootLookupFaultStore) RevokeByGrant(context.Context, string) error { return nil }

// TestExchange_ChainRevokeFailure_EmitsAuditEvent pins H-A2: when the
// post-replay chain revoke encounters a transport fault the
// exchanger MUST emit a warn-level audit event so SOC tooling can
// distinguish a successful cascade from a silent failure. The wire
// response (ErrTokenReplayed) is unchanged.
func TestExchange_ChainRevokeFailure_EmitsAuditEvent(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	cur := t0
	clk := func() time.Time { return cur }
	base := inmem.New(inmem.WithClock(movingClock{cur: &cur})).RefreshTokens()
	wrapped := &failingChainStore{RefreshTokenStore: base, err: errors.New("synthetic chain revoke fault")}
	em := &recordingEmitter{}

	iss, err := refresh.NewIssuer(refresh.IssuerConfig{Store: base, Clock: clk, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	exc, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store: wrapped,
		Clock: clk,
		Audit: em,
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}
	ctx := context.Background()

	root, err := iss.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); err != nil {
		t.Fatalf("first Exchange: %v", err)
	}

	// Step past the grace window so the second presentation is a true
	// replay rather than an idempotent retry.
	cur = cur.Add(refresh.GraceTTLDefault + time.Second)
	if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay err=%v want ErrTokenReplayed", err)
	}

	events := em.snapshot()
	var found bool
	for _, ev := range events {
		if ev.Name == "refresh.chain_revoke_failed" && ev.Level == audit.LevelWarn {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected refresh.chain_revoke_failed warn event, got %+v", events)
	}
}

func TestExchange_ChainRootLookupFailure_EmitsAuditEvent(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	parent := "missing-parent"
	consumedAt := t0.Add(-2 * refresh.GraceTTLDefault)
	st := &rootLookupFaultStore{rec: &store.RefreshToken{
		ID:         "rt-replayed",
		ClientID:   "client-1",
		Subject:    "user-1",
		GrantID:    "grant-1",
		ParentID:   &parent,
		Scope:      []string{"openid"},
		ConsumedAt: &consumedAt,
		ExpiresAt:  t0.Add(time.Hour),
		CreatedAt:  t0.Add(-time.Hour),
	}}
	em := &recordingEmitter{}
	exc, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store: st,
		Clock: func() time.Time { return t0 },
		Audit: em,
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}

	if _, err := exc.Exchange(context.Background(), refresh.ExchangeInput{Token: "rt-replayed", ClientID: "client-1"}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay err=%v want ErrTokenReplayed", err)
	}
	if st.revoked {
		t.Fatal("RevokeChain called even though root lookup failed")
	}
	events := em.snapshot()
	for _, ev := range events {
		if ev.Name == "refresh.chain_revoke_failed" && ev.Level == audit.LevelWarn && ev.Extras["reason"] == "chain_root_lookup_failed" {
			return
		}
	}
	t.Fatalf("expected chain_root_lookup_failed audit event, got %+v", events)
}

func TestExchange_Replay_EmitsReplayDetectedAuditEvent(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	cur := t0
	clk := func() time.Time { return cur }
	st := inmem.New(inmem.WithClock(movingClock{cur: &cur})).RefreshTokens()
	em := &recordingEmitter{}

	iss, err := refresh.NewIssuer(refresh.IssuerConfig{Store: st, Clock: clk, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	exc, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store: st,
		Clock: clk,
		Audit: em,
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}
	ctx := context.Background()
	root, err := iss.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); err != nil {
		t.Fatalf("first Exchange: %v", err)
	}

	cur = cur.Add(refresh.GraceTTLDefault + time.Second)
	if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay err=%v want ErrTokenReplayed", err)
	}

	var found bool
	for _, ev := range em.snapshot() {
		if ev.Name != "refresh.replay_detected" {
			continue
		}
		found = true
		if ev.Level != audit.LevelWarn {
			t.Fatalf("level=%v want %v", ev.Level, audit.LevelWarn)
		}
		if got := ev.Extras["refresh_token_id"]; got != root {
			t.Fatalf("extras.refresh_token_id=%v want %q", got, root)
		}
	}
	if !found {
		t.Fatalf("expected refresh.replay_detected audit event; got %v", em.snapshot())
	}
}

// stubGrantRevocationStore captures RevokeGrant invocations so tests
// can assert the cascade ran the grant tombstone path. Other methods
// are stubs that return safe defaults so the substore satisfies the
// interface without coupling the test to behaviour it does not
// exercise.
type stubGrantRevocationStore struct {
	mu     sync.Mutex
	grants []store.GrantTombstone
	err    error
}

func (s *stubGrantRevocationStore) RevokeGrant(_ context.Context, t store.GrantTombstone) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.grants = append(s.grants, t)
	return nil
}

func (s *stubGrantRevocationStore) RevokeJTI(_ context.Context, _ store.RevokedJTI) error {
	return nil
}

func (s *stubGrantRevocationStore) IsRevoked(_ context.Context, _, _ string, _ time.Time) (bool, error) {
	return false, nil
}

func (s *stubGrantRevocationStore) GC(_ context.Context, _ time.Time) (int, error) {
	return 0, nil
}

func (s *stubGrantRevocationStore) snapshot() []store.GrantTombstone {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.GrantTombstone, len(s.grants))
	copy(out, s.grants)
	return out
}

// TestExchange_ChainRevoke_TombstonesGrant pins H-A6: a refresh
// replay MUST cascade onto the grant-tombstone substore so JWT
// access tokens descended from the chain are blocked at userinfo /
// introspection / mint time. Without the cascade, the chain revoke
// only kills refresh tokens; outstanding JWT access tokens remain
// redeemable until natural expiry.
func TestExchange_ChainRevoke_TombstonesGrant(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	cur := t0
	clk := func() time.Time { return cur }
	st := inmem.New(inmem.WithClock(movingClock{cur: &cur})).RefreshTokens()
	revs := &stubGrantRevocationStore{}

	iss, err := refresh.NewIssuer(refresh.IssuerConfig{Store: st, Clock: clk, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	exc, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store:             st,
		Clock:             clk,
		GrantRevocations:  revs,
		GrantTombstoneTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}
	ctx := context.Background()

	root, err := iss.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); err != nil {
		t.Fatalf("first Exchange: %v", err)
	}
	cur = cur.Add(refresh.GraceTTLDefault + time.Second)
	if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay err=%v want ErrTokenReplayed", err)
	}

	tombs := revs.snapshot()
	if len(tombs) != 1 {
		t.Fatalf("tombstones=%d want 1: %+v", len(tombs), tombs)
	}
	if tombs[0].GrantID != "grant-1" {
		t.Errorf("tombstone.GrantID=%q want %q", tombs[0].GrantID, "grant-1")
	}
	if tombs[0].RevokedAt.IsZero() {
		t.Errorf("tombstone.RevokedAt is zero")
	}
	if tombs[0].ExpiresAt.IsZero() {
		t.Errorf("tombstone.ExpiresAt is zero (configured TTL was 1h)")
	}
	if tombs[0].Reason == "" {
		t.Errorf("tombstone.Reason is empty; want a non-empty cascade trigger")
	}
}

// TestExchange_ChainRevoke_GrantTombstoneFailure_EmitsAudit pins the
// H-A2 audit signal for the grant tombstone branch: when the
// tombstone substore returns an error the exchanger MUST emit a
// warn-level audit event so SOC tooling can spot the half-cascade.
func TestExchange_ChainRevoke_GrantTombstoneFailure_EmitsAudit(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	cur := t0
	clk := func() time.Time { return cur }
	st := inmem.New(inmem.WithClock(movingClock{cur: &cur})).RefreshTokens()
	revs := &stubGrantRevocationStore{err: errors.New("synthetic tombstone fault")}
	em := &recordingEmitter{}

	iss, err := refresh.NewIssuer(refresh.IssuerConfig{Store: st, Clock: clk, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	exc, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store:            st,
		Clock:            clk,
		Audit:            em,
		GrantRevocations: revs,
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}
	ctx := context.Background()

	root, err := iss.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); err != nil {
		t.Fatalf("first Exchange: %v", err)
	}
	cur = cur.Add(refresh.GraceTTLDefault + time.Second)
	if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay err=%v want ErrTokenReplayed", err)
	}

	events := em.snapshot()
	var found bool
	for _, ev := range events {
		if ev.Name == "refresh.grant_revoke_failed" && ev.Level == audit.LevelWarn {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected refresh.grant_revoke_failed warn event, got %+v", events)
	}
}
