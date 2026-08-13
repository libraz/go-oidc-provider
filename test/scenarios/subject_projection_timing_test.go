package scenarios_test

// Spec:
//   - OIDC Core 1.0 §5.3 (UserInfo sub matches the ID Token sub)
//   - OIDC Core 1.0 §8 (subject types)

import (
	"context"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/subject"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// countingGenerator is a passthrough [op.SubjectGenerator] that records
// how many times the library asked it to project a subject.
type countingGenerator struct {
	calls atomic.Int64
}

func (g *countingGenerator) Generate(_ context.Context, in subject.GeneratorInput) (subject.Subject, error) {
	g.calls.Add(1)
	if in.InternalUserID == "" {
		return "", subject.ErrInputEmpty
	}
	return subject.Subject(in.InternalUserID), nil
}

// TestSubjectGeneratorRunsOnEveryRelease pins when the library invokes a
// SubjectGenerator, because its godoc is the only thing an embedder has
// to price the call by.
//
// A grant records the OP-internal subject and nothing else: the value a
// client is served is projected again on each surface that releases a
// "sub". So the generator runs once per releasing request, not once per
// grant — an implementation written against "once per (user, client)"
// would be free to carry a side effect priced at that rate, and would
// pay it on every token exchange and every UserInfo call instead.
//
// The assertion is on the growth of the count across a second release,
// not on a fixed total: how many projections one exchange needs is an
// implementation detail, whereas "a later release re-projects" is the
// contract. A generator consulted only at grant creation leaves the
// count unchanged and fails here.
func TestSubjectGeneratorRunsOnEveryRelease(t *testing.T) {
	t.Parallel()

	gen := &countingGenerator{}
	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithSubjectGenerator(gen)))

	const redirectURI = "https://rp.projection.test/cb"
	client := tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "projection-client",
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
		PublicClient: true,
	})

	// /userinfo answers from the user record, so the release under test
	// only happens if the subject resolves to a stored user.
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims:  map[string]any{"email": "alice@example.com"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    client.ID,
		RedirectURI: redirectURI,
		Scope:       "openid",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback carried no code: %+v", flow)
	}

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:        flow.Code,
		RedirectURI: redirectURI,
		Verifier:    pkce.Verifier,
		ClientID:    client.ID,
		Extra:       url.Values{"client_id": {client.ID}},
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	if tok.AccessToken == "" {
		t.Fatalf("/token returned no access_token: %v", tok.Raw)
	}

	afterIssuance := gen.calls.Load()
	if afterIssuance == 0 {
		t.Fatal("the generator was never consulted; the projection seam is not reached at all, " +
			"so this test cannot say anything about when it runs")
	}

	status, claims, challenge := getUserInfo(t, tk, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("GET /userinfo status=%d challenge=%q", status, challenge)
	}
	if sub, _ := claims["sub"].(string); sub != scenariokit.DefaultSubject {
		t.Errorf("userinfo sub=%q want %q", sub, scenariokit.DefaultSubject)
	}

	if got := gen.calls.Load(); got <= afterIssuance {
		t.Errorf("generator calls did not grow across the UserInfo release: %d before, %d after. "+
			"A releasing surface answered from a stored projection instead of re-projecting, "+
			"so the generator's documented call rate is wrong and an embedder pricing work "+
			"per call would be misled",
			afterIssuance, got)
	}
}
