//nolint:testpackage // exercises unexported lookup helpers
package tokenexchange

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// staticOpaqueStore returns rec from Find regardless of the presented
// id. The other OpaqueAccessTokenStore methods are not exercised by
// the lookup path so they panic.
type staticOpaqueStore struct {
	rec *store.OpaqueAccessToken
}

func (s staticOpaqueStore) Save(context.Context, *store.OpaqueAccessToken) error {
	panic("staticOpaqueStore.Save should not be reached on the lookup path")
}

func (s staticOpaqueStore) Find(context.Context, string) (*store.OpaqueAccessToken, error) {
	return s.rec, nil
}

func (s staticOpaqueStore) RevokeByID(context.Context, string) error {
	panic("staticOpaqueStore.RevokeByID should not be reached on the lookup path")
}

func (s staticOpaqueStore) RevokeByGrant(context.Context, string) (int, error) {
	panic("staticOpaqueStore.RevokeByGrant should not be reached on the lookup path")
}

func (s staticOpaqueStore) GC(context.Context, time.Time) (int, error) {
	panic("staticOpaqueStore.GC should not be reached on the lookup path")
}

// TestLookupJWT_AudienceNormalised pins that a subject_token whose
// aud claim carries a non-canonical resource indicator (uppercase
// host, trailing slash) surfaces to the policy already normalised
// per RFC 8707 §2, matching the [op.SubjectTokenView.Audience] godoc.
func TestLookupJWT_AudienceNormalised(t *testing.T) {
	t.Parallel()

	entry, err := keys.GenerateES256("tx-aud-kid")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	h := &Handler{
		issuer: "https://op.example",
		keys:   keySet,
		clock:  fixedClock{now: now},
	}
	signer := tokens.FromInternalEntry(entry)
	subjectJWS, err := tokens.SignAccessToken(signer, tokens.AccessTokenClaims{
		Issuer:    "https://op.example",
		Subject:   "user-aud",
		Audience:  []string{"HTTPS://API.EXAMPLE/foo/"},
		ClientID:  "subject-client",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "tx-aud-jti",
		Scope:     []string{"read"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	result, err := h.lookupJWT(context.Background(), subjectJWS, TokenTypeAccessToken)
	if err != nil {
		t.Fatalf("lookupJWT err=%v want nil", err)
	}
	want := []string{"https://api.example/foo"}
	if len(result.view.Audience) != 1 || result.view.Audience[0] != want[0] {
		t.Fatalf("Audience=%v want %v", result.view.Audience, want)
	}
}

// TestLookupIDToken_AudienceNormalised mirrors
// TestLookupJWT_AudienceNormalised for the id_token path.
func TestLookupIDToken_AudienceNormalised(t *testing.T) {
	t.Parallel()

	entry, err := keys.GenerateES256("tx-aud-idtoken-kid")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	h := &Handler{
		issuer: "https://op.example",
		keys:   keySet,
		clock:  fixedClock{now: now},
		grants: staticGrantStore{grant: &store.Grant{
			ID:       "grant-aud-idtoken",
			Subject:  "user-aud",
			ClientID: "https://api.example/foo",
			Scope:    []string{"read"},
		}},
	}
	signer := tokens.FromInternalEntry(entry)
	idJWS, err := tokens.SignIDToken(signer, tokens.IDTokenClaims{
		Issuer:    "https://op.example",
		Subject:   "user-aud",
		Audience:  []string{"HTTPS://API.EXAMPLE/foo/"},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}

	result, err := h.lookupIDToken(context.Background(), idJWS)
	if err != nil {
		t.Fatalf("lookupIDToken err=%v want nil", err)
	}
	want := "https://api.example/foo"
	if len(result.view.Audience) != 1 || result.view.Audience[0] != want {
		t.Fatalf("Audience=%v want [%v]", result.view.Audience, want)
	}
}

// TestLookupOpaqueAccessToken_AudienceNormalised mirrors
// TestLookupJWT_AudienceNormalised for the opaque-store path.
func TestLookupOpaqueAccessToken_AudienceNormalised(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	h := &Handler{
		clock: fixedClock{now: now},
		opaqueAccessTokens: staticOpaqueStore{rec: &store.OpaqueAccessToken{
			ClientID:  "subject-client",
			Subject:   "user-aud",
			Scope:     []string{"read"},
			Audience:  "HTTPS://API.EXAMPLE/foo/",
			ExpiresAt: now.Add(time.Hour),
		}},
	}

	result, err := h.lookupOpaqueAccessToken(context.Background(), "opaque-raw-id")
	if err != nil {
		t.Fatalf("lookupOpaqueAccessToken err=%v want nil", err)
	}
	want := "https://api.example/foo"
	if len(result.view.Audience) != 1 || result.view.Audience[0] != want {
		t.Fatalf("Audience=%v want [%v]", result.view.Audience, want)
	}
}
