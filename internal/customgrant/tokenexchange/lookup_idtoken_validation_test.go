//nolint:testpackage // exercises the unexported ID-token lookup boundary
package tokenexchange

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// staticGrantStore answers FindBySubjectClient with the same record for
// every (subject, client) pair, or [store.ErrNotFound] when grant is
// nil. Only that one method is reachable from the lookup path; the rest
// panic so a future change that quietly reaches for them fails loudly
// instead of reading a zero value.
//
// The stub stands in for consent that the OP recorded elsewhere. Tests
// that must prove the scope really travels from an OP-written grant
// drive the provider end to end instead (see the black-box file in this
// directory) -- a stub can answer with a grant the OP would never
// write, which is exactly the gap that hides a broken lookup.
type staticGrantStore struct {
	grant *store.Grant
}

func (s staticGrantStore) Save(context.Context, *store.Grant) error {
	panic("staticGrantStore.Save should not be reached on the lookup path")
}

func (s staticGrantStore) Find(context.Context, string) (*store.Grant, error) {
	panic("staticGrantStore.Find should not be reached on the lookup path")
}

func (s staticGrantStore) FindBySubjectClient(context.Context, string, string) (*store.Grant, error) {
	if s.grant == nil {
		return nil, store.ErrNotFound
	}
	return s.grant, nil
}

func (s staticGrantStore) ListBySubject(context.Context, string) ([]*store.Grant, error) {
	panic("staticGrantStore.ListBySubject should not be reached on the lookup path")
}

func (s staticGrantStore) Delete(context.Context, string) error {
	panic("staticGrantStore.Delete should not be reached on the lookup path")
}

func (s staticGrantStore) HasAny(context.Context) (bool, error) {
	panic("staticGrantStore.HasAny should not be reached on the lookup path")
}

func TestLookupIDToken_RejectsCrossTokenConfusionAndInvalidLifetime(t *testing.T) {
	t.Parallel()

	entry, err := keys.GenerateES256("tx-id-token-validation-kid")
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
			ID:       "grant-id-token-validation",
			Subject:  "user-123",
			ClientID: "caller-client",
			Scope:    []string{"openid", "profile"},
		}},
	}
	signer := tokens.FromInternalEntry(entry)

	signIDToken := func(t *testing.T, claims tokens.IDTokenClaims) string {
		t.Helper()
		raw, signErr := tokens.SignIDToken(signer, claims)
		if signErr != nil {
			t.Fatalf("SignIDToken: %v", signErr)
		}
		return raw
	}
	validClaims := tokens.IDTokenClaims{
		Issuer:    "https://op.example",
		Subject:   "user-123",
		Audience:  []string{"caller-client"},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	}
	valid := signIDToken(t, validClaims)
	missingExpClaims := validClaims
	missingExpClaims.ExpiresAt = 0
	expiredClaims := validClaims
	expiredClaims.IssuedAt = now.Add(-time.Hour).Unix()
	expiredClaims.ExpiresAt = now.Add(-time.Second).Unix()

	accessToken, err := tokens.SignAccessToken(signer, tokens.AccessTokenClaims{
		Issuer:    validClaims.Issuer,
		Subject:   validClaims.Subject,
		Audience:  validClaims.Audience,
		ClientID:  "caller-client",
		IssuedAt:  validClaims.IssuedAt,
		ExpiresAt: validClaims.ExpiresAt,
		JTI:       "access-token-jti",
		Scope:     []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(
		`{"alg":"none","typ":"JWT","kid":"tx-id-token-validation-kid"}`,
	))
	nonePayload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"https://op.example","sub":"user-123","aud":"caller-client","iat":1700000000,"exp":1700003600}`,
	))

	tests := []struct {
		name       string
		raw        string
		wantReason string
		wantErr    bool
	}{
		{
			name:    "valid ID token",
			raw:     valid,
			wantErr: false,
		},
		{
			name:       "OP access token relabelled as ID token",
			raw:        accessToken,
			wantReason: "typ_mismatch",
			wantErr:    true,
		},
		{
			name:       "alg none",
			raw:        noneHeader + "." + nonePayload + ".",
			wantReason: "malformed",
			wantErr:    true,
		},
		{
			name:       "missing exp",
			raw:        signIDToken(t, missingExpClaims),
			wantReason: "missing_claim",
			wantErr:    true,
		},
		{
			name:       "expired exp",
			raw:        signIDToken(t, expiredClaims),
			wantReason: "expired",
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, lookupErr := h.lookupIDToken(t.Context(), tc.raw)
			if !tc.wantErr {
				if lookupErr != nil {
					t.Fatalf("lookupIDToken: %v", lookupErr)
				}
				if result.view.Subject != validClaims.Subject {
					t.Errorf("Subject=%q want %q", result.view.Subject, validClaims.Subject)
				}
				if result.view.ExpiresAt.Unix() != validClaims.ExpiresAt {
					t.Errorf("ExpiresAt=%v want Unix(%d)", result.view.ExpiresAt, validClaims.ExpiresAt)
				}
				if !equalStrings(result.view.Scope, []string{"openid", "profile"}) {
					t.Errorf("Scope=%v want the grant's scope [openid profile]", result.view.Scope)
				}
				return
			}
			if !errors.Is(lookupErr, errTokenInvalid) {
				t.Fatalf("lookupIDToken err=%v want errTokenInvalid", lookupErr)
			}
			if result.reason != tc.wantReason {
				t.Errorf("reason=%q want %q", result.reason, tc.wantReason)
			}
		})
	}
}

// errInjectedGrantFault is the sentinel the faulty grant store returns
// so the test can distinguish a transport fault from "no such grant".
var errInjectedGrantFault = errors.New("injected: grant store FindBySubjectClient fault")

// faultyGrantStore fails every FindBySubjectClient call. It models the
// transport fault an unreachable consent store produces, which MUST be
// classified apart from a withdrawn consent so operators can tell a
// database outage from a revocation wave.
type faultyGrantStore struct {
	staticGrantStore
}

func (faultyGrantStore) FindBySubjectClient(context.Context, string, string) (*store.Grant, error) {
	return nil, errInjectedGrantFault
}

// TestLookupIDToken_GrantGatesTheExchange pins the three ways the
// consent lookup can refuse an id_token subject_token. All three MUST
// yield errTokenInvalid so the handler collapses them to invalid_grant
// on the wire; only the audit reason distinguishes them.
//
// The withdrawn-consent row is the security-relevant one: an id_token
// stays cryptographically valid until its own exp, so nothing else in
// the exchange path would notice that the user revoked the client.
func TestLookupIDToken_GrantGatesTheExchange(t *testing.T) {
	t.Parallel()

	entry, err := keys.GenerateES256("tx-id-token-grant-kid")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	raw, err := tokens.SignIDToken(tokens.FromInternalEntry(entry), tokens.IDTokenClaims{
		Issuer:    "https://op.example",
		Subject:   "user-123",
		Audience:  []string{"caller-client"},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}

	tests := []struct {
		name       string
		grants     store.GrantStore
		wantReason string
	}{
		{
			name:       "consent withdrawn",
			grants:     staticGrantStore{},
			wantReason: "grant_not_found",
		},
		{
			name:       "consent store unreachable",
			grants:     faultyGrantStore{},
			wantReason: "store_error",
		},
		{
			name:       "no consent store configured",
			grants:     nil,
			wantReason: "no_grant_store",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := &Handler{
				issuer: "https://op.example",
				keys:   keySet,
				clock:  fixedClock{now: now},
				grants: tc.grants,
			}
			result, lookupErr := h.lookupIDToken(t.Context(), raw)
			if !errors.Is(lookupErr, errTokenInvalid) {
				t.Fatalf("lookupIDToken err=%v want errTokenInvalid", lookupErr)
			}
			if result.reason != tc.wantReason {
				t.Errorf("reason=%q want %q", result.reason, tc.wantReason)
			}
			if len(result.view.Scope) != 0 {
				t.Errorf("Scope=%v want empty on the refusal path", result.view.Scope)
			}
		})
	}
}

func TestBuildResponse_RejectsSourceWithoutPositiveRemainingTTL(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	tests := []struct {
		name      string
		expiresAt time.Time
	}{
		{name: "unknown expiry"},
		{name: "expired", expiresAt: now.Add(-time.Second)},
		{name: "expires now", expiresAt: now},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := &Handler{
				clock:        fixedClock{now: now},
				maxAccessTTL: time.Hour,
			}
			_, buildErr := h.buildResponse(
				t.Context(),
				customgrant.Request{Client: &store.Client{ID: "caller-client"}},
				TokenView{
					Subject:   "user-123",
					ExpiresAt: tc.expiresAt,
				},
				nil,
				[]string{"read"},
				[]string{"https://api.example"},
				nil,
			)
			if code := oauthCodeOf(t, buildErr); code != "invalid_grant" {
				t.Errorf("error code=%q want invalid_grant", code)
			}
		})
	}
}

func TestLookupOpaqueAccessToken_RejectsUnknownExpiry(t *testing.T) {
	t.Parallel()

	h := &Handler{
		clock: fixedClock{now: time.Unix(1_700_000_000, 0).UTC()},
		opaqueAccessTokens: staticOpaqueStore{rec: &store.OpaqueAccessToken{
			ClientID: "subject-client",
			Subject:  "user-123",
			Scope:    []string{"read"},
		}},
	}
	result, lookupErr := h.lookupOpaqueAccessToken(t.Context(), "opaque-without-expiry")
	if !errors.Is(lookupErr, errTokenInvalid) {
		t.Fatalf("lookupOpaqueAccessToken err=%v want errTokenInvalid", lookupErr)
	}
	if result.reason != "missing_claim" {
		t.Errorf("reason=%q want missing_claim", result.reason)
	}
}
