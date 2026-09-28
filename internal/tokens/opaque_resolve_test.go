package tokens_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// faultingClients answers every GetClient with a backend fault.
type faultingClients struct{ store.ClientStore }

func (faultingClients) GetClient(context.Context, string) (*store.Client, error) {
	return nil, errors.New("backend down")
}

// faultingGrants answers every Find with a backend fault.
type faultingGrants struct{ store.GrantStore }

func (faultingGrants) Find(context.Context, string) (*store.Grant, error) {
	return nil, errors.New("backend down")
}

func seedGrant(t *testing.T, st *inmem.Store, id, subject string) {
	t.Helper()
	if err := st.Grants().Save(t.Context(), &store.Grant{ID: id, Subject: subject, ClientID: "rp", Scope: []string{"openid"}}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
}

func prefixProjector(_ context.Context, raw string, client *store.Client) (string, error) {
	return client.ID + ":" + raw, nil
}

func TestResolveOpaqueAccessToken(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	seed := func(t *testing.T, mutate func(*store.OpaqueAccessToken)) (*inmem.Store, string) {
		t.Helper()
		st := inmem.New()
		if err := st.RegisterClient(t.Context(), &store.Client{ID: "rp"}); err != nil {
			t.Fatalf("RegisterClient: %v", err)
		}
		rec := &store.OpaqueAccessToken{
			ID:        "opaque-token-value",
			GrantID:   "grant-1",
			Subject:   "internal-user",
			ClientID:  "rp",
			IssuedAt:  now.Add(-time.Minute),
			ExpiresAt: now.Add(time.Hour),
		}
		if mutate != nil {
			mutate(rec)
		}
		if err := st.OpaqueAccessTokens().Save(t.Context(), rec); err != nil {
			t.Fatalf("Save: %v", err)
		}
		return st, rec.ID
	}

	cases := []struct {
		name    string
		mutate  func(*store.OpaqueAccessToken)
		prepare func(t *testing.T, st *inmem.Store) tokens.OpaqueAccessTokenLookup
		raw     string
		wantErr error
	}{
		{name: "unknown", raw: "not-issued", wantErr: tokens.ErrOpaqueAccessTokenUnknown},
		{name: "revoked", mutate: func(r *store.OpaqueAccessToken) { r.Revoked = true }, wantErr: tokens.ErrOpaqueAccessTokenRevoked},
		{name: "expired", mutate: func(r *store.OpaqueAccessToken) { r.ExpiresAt = now }, wantErr: tokens.ErrOpaqueAccessTokenExpired},
		{name: "expiry unset", mutate: func(r *store.OpaqueAccessToken) { r.ExpiresAt = time.Time{} }, wantErr: tokens.ErrOpaqueAccessTokenExpired},
		{
			name: "client deleted outside any cascade",
			prepare: func(t *testing.T, st *inmem.Store) tokens.OpaqueAccessTokenLookup {
				t.Helper()
				if err := st.DeleteClient(t.Context(), "rp"); err != nil {
					t.Fatalf("DeleteClient: %v", err)
				}
				return tokens.OpaqueAccessTokenLookup{Store: st.OpaqueAccessTokens(), Clients: st.Clients()}
			},
			wantErr: tokens.ErrOpaqueAccessTokenClientGone,
		},
		{
			name: "client registry fault",
			prepare: func(_ *testing.T, st *inmem.Store) tokens.OpaqueAccessTokenLookup {
				return tokens.OpaqueAccessTokenLookup{Store: st.OpaqueAccessTokens(), Clients: faultingClients{}}
			},
			wantErr: tokens.ErrOpaqueAccessTokenLookup,
		},
		{
			name: "projector without a registry",
			prepare: func(_ *testing.T, st *inmem.Store) tokens.OpaqueAccessTokenLookup {
				return tokens.OpaqueAccessTokenLookup{Store: st.OpaqueAccessTokens(), SubjectProjector: prefixProjector}
			},
			wantErr: tokens.ErrOpaqueAccessTokenSubject,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, raw := seed(t, tc.mutate)
			if tc.raw != "" {
				raw = tc.raw
			}
			opts := tokens.OpaqueAccessTokenLookup{Store: st.OpaqueAccessTokens(), Clients: st.Clients()}
			if tc.prepare != nil {
				opts = tc.prepare(t, st)
			}
			view, err := tokens.ResolveOpaqueAccessToken(t.Context(), opts, raw, now)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v want %v", err, tc.wantErr)
			}
			if view != nil {
				t.Errorf("view=%+v want nil on a rejected token", view)
			}
		})
	}
}

func TestResolveOpaqueAccessToken_ProjectsSubjectAndKeepsBothCnfMembers(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	st := inmem.New()
	if err := st.RegisterClient(t.Context(), &store.Client{ID: "rp"}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	rec := &store.OpaqueAccessToken{
		ID:                 "dual-bound",
		GrantID:            "grant-1",
		Subject:            "internal-user",
		ClientID:           "rp",
		ExpiresAt:          now.Add(time.Hour),
		DPoPJKT:            "jkt-thumbprint",
		MTLSCertThumbprint: "x5t-thumbprint",
	}
	if err := st.OpaqueAccessTokens().Save(t.Context(), rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	seedGrant(t, st, "grant-1", "internal-user")
	view, err := tokens.ResolveOpaqueAccessToken(t.Context(), tokens.OpaqueAccessTokenLookup{
		Store:            st.OpaqueAccessTokens(),
		Clients:          st.Clients(),
		SubjectProjector: prefixProjector,
		Grants:           st.Grants(),
	}, "dual-bound", now)
	if err != nil {
		t.Fatalf("ResolveOpaqueAccessToken: %v", err)
	}
	if view.Subject != "rp:internal-user" {
		t.Errorf("Subject=%q want the projected rp:internal-user", view.Subject)
	}
	if view.Record.Subject != "internal-user" {
		t.Errorf("Record.Subject=%q want the recorded internal-user", view.Record.Subject)
	}
	if view.Client == nil || view.Client.ID != "rp" {
		t.Errorf("Client=%+v want rp", view.Client)
	}
	cnf := view.Confirmation()
	if cnf["jkt"] != "jkt-thumbprint" || cnf["x5t#S256"] != "x5t-thumbprint" {
		t.Errorf("Confirmation()=%v want both jkt and x5t#S256", cnf)
	}
}

// TestResolveOpaqueAccessToken_ProjectsOnlyGrantBackedSubjects pins the
// rule that tells an OP-internal recorded subject from a public one:
// only a token whose GrantID names a Grant record is projected, and a
// grant store that cannot answer fails closed.
func TestResolveOpaqueAccessToken_ProjectsOnlyGrantBackedSubjects(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	cases := []struct {
		name        string
		grantID     string
		seedGrant   bool
		grants      func(st *inmem.Store) store.GrantStore
		projector   bool
		wantSubject string
		wantErr     error
	}{
		{name: "grant-backed token is projected", grantID: "g-1", seedGrant: true, projector: true, wantSubject: "rp:recorded"},
		{name: "no GrantID keeps the recorded wire subject", projector: true, wantSubject: "recorded"},
		{name: "GrantID without a Grant record keeps the recorded wire subject", grantID: "custom-chain", projector: true, wantSubject: "recorded"},
		{
			name: "grant store fault fails closed", grantID: "g-1", seedGrant: true, projector: true,
			grants:  func(*inmem.Store) store.GrantStore { return faultingGrants{} },
			wantErr: tokens.ErrOpaqueAccessTokenLookup,
		},
		{
			name: "no grant store cannot classify a grant-bound subject", grantID: "g-1", projector: true,
			grants:  func(*inmem.Store) store.GrantStore { return nil },
			wantErr: tokens.ErrOpaqueAccessTokenSubject,
		},
		{
			name: "no projector never consults the grant store", grantID: "g-1",
			grants:      func(*inmem.Store) store.GrantStore { return faultingGrants{} },
			wantSubject: "recorded",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := inmem.New()
			if err := st.RegisterClient(t.Context(), &store.Client{ID: "rp"}); err != nil {
				t.Fatalf("RegisterClient: %v", err)
			}
			if err := st.OpaqueAccessTokens().Save(t.Context(), &store.OpaqueAccessToken{
				ID: "tok", GrantID: tc.grantID, Subject: "recorded", ClientID: "rp", ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if tc.seedGrant {
				seedGrant(t, st, tc.grantID, "recorded")
			}
			opts := tokens.OpaqueAccessTokenLookup{Store: st.OpaqueAccessTokens(), Clients: st.Clients(), Grants: st.Grants()}
			if tc.grants != nil {
				opts.Grants = tc.grants(st)
			}
			if tc.projector {
				opts.SubjectProjector = prefixProjector
			}
			view, err := tokens.ResolveOpaqueAccessToken(t.Context(), opts, "tok", now)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err=%v want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveOpaqueAccessToken: %v", err)
			}
			if view.Subject != tc.wantSubject {
				t.Errorf("Subject=%q want %q", view.Subject, tc.wantSubject)
			}
		})
	}
}
