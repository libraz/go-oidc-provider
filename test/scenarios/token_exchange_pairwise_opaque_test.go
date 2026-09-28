package scenarios_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/subject"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestTokenExchange_OpaqueSubjectTokenCarriesPairwiseSubject drives an
// opaque subject_token through a Provider built with pairwise subjects.
// The opaque record stores the OP-internal subject; the exchanged
// access token must name the pairwise value the issuing client sees,
// never the internal identifier.
func TestTokenExchange_OpaqueSubjectTokenCarriesPairwiseSubject(t *testing.T) {
	t.Parallel()

	const (
		rawSubject = "user-tx-pairwise-internal"
		opaqueID   = "tx-opaque-pairwise-subject-token"
	)
	salt := []byte("tx-opaque-pairwise-salt-32-bytes")
	p := newTXProviderOpts(t, txAllowAllPolicy{}, op.WithPairwiseSubject(salt))
	subjectClient := p.tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "tx-pairwise-subject-client",
		RedirectURIs: []string{"https://pairwise-rp.example.test/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "read"},
		Resources:    []string{txOriginAud, txTargetAud},
		SubjectType:  "pairwise",
	})
	// A user token descends from a Grant record; that is what marks its
	// recorded subject as OP-internal.
	if err := p.tk.Store.Grants().Save(context.Background(), &store.Grant{
		ID: "grant-tx-pairwise", Subject: rawSubject, ClientID: subjectClient.ID, Scope: []string{"read"},
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	now := txClockNow()
	if err := p.tk.Store.OpaqueAccessTokens().Save(context.Background(), &store.OpaqueAccessToken{
		ID:        opaqueID,
		GrantID:   "grant-tx-pairwise",
		Subject:   rawSubject,
		ClientID:  subjectClient.ID,
		Scope:     []string{"read"},
		Audience:  txOriginAud,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("OpaqueAccessTokens.Save: %v", err)
	}
	want, err := subject.Pairwise(salt).Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: rawSubject,
		Client:         subjectClient,
	})
	if err != nil {
		t.Fatalf("Pairwise.Generate: %v", err)
	}

	status, body := p.postTokenExchange(t, url.Values{
		"subject_token":      []string{opaqueID},
		"subject_token_type": []string{txTokenTypeAT},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	at, _ := body["access_token"].(string)
	got := decodeTXJWTClaims(t, at)["sub"]
	if got == rawSubject {
		t.Fatalf("exchanged sub=%v leaks the OP-internal subject", got)
	}
	if got != string(want) {
		t.Errorf("exchanged sub=%v want pairwise %q", got, want)
	}
}
