//nolint:testpackage // exercises unexported lookup helpers
package tokenexchange

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// pairwiseLikeProjector stands in for the OP's subject projector: the
// public subject differs from the recorded one and depends on the client.
func pairwiseLikeProjector(_ context.Context, raw string, client *store.Client) (string, error) {
	return "pw-" + client.ID + "-" + raw, nil
}

func seedOpaqueSubjectToken(t *testing.T, rec *store.OpaqueAccessToken) *inmem.Store {
	t.Helper()
	st := inmem.New()
	if err := st.RegisterClient(t.Context(), &store.Client{ID: rec.ClientID, SubjectType: "pairwise"}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if err := st.OpaqueAccessTokens().Save(t.Context(), rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return st
}

// A dual-bound opaque subject_token carries both cnf members into the
// exchange, so a request proving only the DPoP key is refused.
func TestLookupOpaqueAccessToken_DualBoundRequiresBothProofs(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	leaf := fixtureLeafCert()
	st := seedOpaqueSubjectToken(t, &store.OpaqueAccessToken{
		ID:                 "dual-bound-subject",
		GrantID:            "grant-1",
		Subject:            "internal-user",
		ClientID:           "subject-client",
		Scope:              []string{"read"},
		ExpiresAt:          now.Add(time.Hour),
		DPoPJKT:            "subject-jkt",
		MTLSCertThumbprint: mtls.Thumbprint(leaf),
	})
	h := &Handler{
		clock:              fixedClock{now: now},
		opaqueAccessTokens: st.OpaqueAccessTokens(),
		clients:            st.Clients(),
	}
	result, err := h.lookupOpaqueAccessToken(t.Context(), "dual-bound-subject")
	if err != nil {
		t.Fatalf("lookupOpaqueAccessToken: %v", err)
	}
	cnf := result.view.Confirmation
	if cnf == nil || cnf.JKT != "subject-jkt" || cnf.X5tS256 != mtls.Thumbprint(leaf) {
		t.Fatalf("Confirmation=%+v want both jkt and x5t#S256", cnf)
	}
	if err := requireMatchingSenderConstraint(customgrant.Request{DPoPJKT: "subject-jkt"}, result.view); err == nil {
		t.Error("DPoP-only request exchanged a token also bound to a client certificate")
	}
	if err := requireMatchingSenderConstraint(customgrant.Request{DPoPJKT: "subject-jkt", MTLSCert: leaf}, result.view); err != nil {
		t.Errorf("request proving both bindings rejected: %v", err)
	}
}

// An opaque subject_token resolves to the same public subject a JWT
// access token for the same grant carries in "sub".
func TestLookupAccessToken_OpaqueAndJWTAgreeOnSubject(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	entry, err := keys.GenerateES256("tx-sub-parity-kid")
	if err != nil {
		t.Fatalf("GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{entry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	st := seedOpaqueSubjectToken(t, &store.OpaqueAccessToken{
		ID:        "opaque-subject",
		GrantID:   "grant-1",
		Subject:   "internal-user",
		ClientID:  "subject-client",
		Scope:     []string{"read"},
		ExpiresAt: now.Add(time.Hour),
	})
	if err := st.Grants().Save(t.Context(), &store.Grant{
		ID: "grant-1", Subject: "internal-user", ClientID: "subject-client", Scope: []string{"read"},
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	client, err := st.Clients().GetClient(t.Context(), "subject-client")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	publicSubject, err := pairwiseLikeProjector(t.Context(), "internal-user", client)
	if err != nil {
		t.Fatalf("projector: %v", err)
	}
	h := &Handler{
		issuer:             "https://op.example",
		keys:               keySet,
		clock:              fixedClock{now: now},
		opaqueAccessTokens: st.OpaqueAccessTokens(),
		clients:            st.Clients(),
		grants:             st.Grants(),
		subjectProjector:   pairwiseLikeProjector,
	}
	// The token endpoint stamps the projected subject on a JWT access
	// token for the same grant.
	jws, err := tokens.SignAccessToken(tokens.FromInternalEntry(entry), tokens.AccessTokenClaims{
		Issuer:    "https://op.example",
		Subject:   publicSubject,
		Audience:  []string{"https://api.example"},
		ClientID:  "subject-client",
		GrantID:   "grant-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       "tx-sub-parity-jti",
		Scope:     []string{"read"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	jwtResult, err := h.lookupAccessToken(t.Context(), jws)
	if err != nil {
		t.Fatalf("JWT lookup: %v", err)
	}
	opaqueResult, err := h.lookupAccessToken(t.Context(), "opaque-subject")
	if err != nil {
		t.Fatalf("opaque lookup: %v", err)
	}
	if opaqueResult.view.Subject != jwtResult.view.Subject {
		t.Errorf("opaque Subject=%q JWT Subject=%q; the two token forms must name the same subject",
			opaqueResult.view.Subject, jwtResult.view.Subject)
	}
	if opaqueResult.view.Subject == "internal-user" {
		t.Error("opaque lookup leaked the OP-internal subject")
	}
}

// Deleting the issuing client through the registry, with no cascade
// run, makes its opaque subject_token unexchangeable.
func TestLookupOpaqueAccessToken_DeletedClientRejected(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	st := seedOpaqueSubjectToken(t, &store.OpaqueAccessToken{
		ID:        "orphaned-subject",
		GrantID:   "grant-1",
		Subject:   "internal-user",
		ClientID:  "subject-client",
		Scope:     []string{"read"},
		ExpiresAt: now.Add(time.Hour),
	})
	if err := st.DeleteClient(t.Context(), "subject-client"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	h := &Handler{
		clock:              fixedClock{now: now},
		opaqueAccessTokens: st.OpaqueAccessTokens(),
		clients:            st.Clients(),
	}
	result, err := h.lookupOpaqueAccessToken(t.Context(), "orphaned-subject")
	if !errors.Is(err, errTokenInvalid) {
		t.Fatalf("err=%v want errTokenInvalid", err)
	}
	if result.reason != "client_deleted" {
		t.Errorf("reason=%q want client_deleted", result.reason)
	}
}
