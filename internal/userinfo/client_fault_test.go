package userinfo_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/internal/userinfo"
	"github.com/libraz/go-oidc-provider/op/store"
)

// faultingClientStore answers every lookup with a backend fault.
type faultingClientStore struct{}

func (faultingClientStore) GetClient(context.Context, string) (*store.Client, error) {
	return nil, errors.New("client registry unavailable")
}

// TestHandler_ClientLookupFaultFailsClosed pins that a registry fault
// while choosing the response shape fails the request: the handler
// cannot tell whether the client registered userinfo encryption, so it
// must not fall back to a plaintext JSON body. RevocationStrategyNone is
// used because it skips the client probe the revocation check would
// otherwise run first.
func TestHandler_ClientLookupFaultFailsClosed(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{{KeyID: "k1", Signer: priv}})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	const (
		issuer   = "https://op.example"
		clientID = "client-fault"
		subject  = "user-fault"
	)
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	deps := userinfo.HandlerDeps{
		Keys:               keySet,
		Issuer:             issuer,
		Clients:            faultingClientStore{},
		UserStore:          singleUserStore{user: &store.User{Subject: subject, Claims: map[string]any{"email": "alice@example.com"}}},
		Clock:              clock,
		RevocationStrategy: store.RevocationStrategyNone,
	}
	token, err := tokens.SignAccessToken(tokens.SigningKey{KeyID: "k1", Signer: priv}, tokens.AccessTokenClaims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  []string{issuer},
		ClientID:  clientID,
		GrantID:   "grant-fault",
		IssuedAt:  clock.now.Unix(),
		ExpiresAt: clock.now.Add(time.Hour).Unix(),
		JTI:       "at-fault-1",
		Scope:     []string{"openid", "email"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, issuer+"/userinfo", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	userinfo.Handler(deps).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "alice@example.com") {
		t.Errorf("claims leaked in the fault response: %s", rec.Body.String())
	}
}
