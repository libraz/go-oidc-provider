package authorizeendpoint

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

type corruptGrantStore struct {
	findResult          *store.Grant
	findErr             error
	findBySubjectResult *store.Grant
	findBySubjectErr    error
	saved               *store.Grant
}

func (s *corruptGrantStore) Save(_ context.Context, grant *store.Grant) error {
	s.saved = grant
	return nil
}

func (s *corruptGrantStore) Find(context.Context, string) (*store.Grant, error) {
	return s.findResult, s.findErr
}

func (s *corruptGrantStore) FindBySubjectClient(
	context.Context,
	string,
	string,
) (*store.Grant, error) {
	return s.findBySubjectResult, s.findBySubjectErr
}

func (*corruptGrantStore) ListBySubject(context.Context, string) ([]*store.Grant, error) {
	return nil, nil
}

func (*corruptGrantStore) ListClientIDsBySubject(
	context.Context,
	string,
	string,
	int,
) (store.GrantClientPage, error) {
	return store.GrantClientPage{}, nil
}

func (*corruptGrantStore) Delete(context.Context, string) error { return store.ErrNotFound }
func (*corruptGrantStore) HasAny(context.Context) (bool, error) { return false, nil }

func TestReuseOrCreateGrant_RejectsCorruptLookupResults(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		result *store.Grant
	}{
		{name: "nil record"},
		{
			name: "mismatched owner",
			result: &store.Grant{
				ID:       "grant-1",
				Subject:  "other-subject",
				ClientID: "client-1",
			},
		},
		{
			name: "empty id",
			result: &store.Grant{
				Subject:  "user-1",
				ClientID: "client-1",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			grants := &corruptGrantStore{findBySubjectResult: tc.result}
			_, err := reuseOrCreateGrant(context.Background(), resolved{
				Deps: Deps{Grants: grants},
			}, grantUpsert{
				Subject:  "user-1",
				ClientID: "client-1",
				Scope:    []string{"openid"},
				Now:      time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC),
			})
			if err == nil {
				t.Fatal("corrupt grant lookup was treated as absence")
			}
			if grants.saved != nil {
				t.Fatalf("corrupt lookup created replacement grant: %+v", grants.saved)
			}
		})
	}
}

func TestMutateManagedGrant_BackendFaultAndNilRecordAreServerFaults(t *testing.T) {
	t.Parallel()

	injected := errors.New("injected managed grant lookup failure")
	for _, tc := range []struct {
		name   string
		result *store.Grant
		err    error
	}{
		{name: "backend fault", err: injected},
		{name: "nil record"},
		{
			name: "same owner different id",
			result: &store.Grant{
				ID:       "other-grant",
				Subject:  "user-1",
				ClientID: "client-1",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			grants := &corruptGrantStore{findResult: tc.result, findErr: tc.err}
			_, err := mutateManagedGrant(context.Background(), resolved{
				Deps: Deps{Grants: grants},
			}, grantUpsert{
				Subject:   "user-1",
				ClientID:  "client-1",
				GMAction:  gmActionMerge,
				GMGrantID: "grant-1",
				Now:       time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC),
			})
			if err == nil {
				t.Fatal("managed grant corruption returned nil")
			}
			if errors.Is(err, errGrantNotOwned) {
				t.Fatalf("backend corruption mapped to invalid_grant: %v", err)
			}
		})
	}
}

func TestResolveSilentGrant_RejectsSameOwnerDifferentID(t *testing.T) {
	t.Parallel()

	grants := &corruptGrantStore{
		findResult: &store.Grant{
			ID:       "other-grant",
			Subject:  "user-1",
			ClientID: "client-1",
			Scope:    []string{"openid"},
		},
	}
	_, err := resolveSilentGrant(
		context.Background(),
		resolved{Deps: Deps{Grants: grants}},
		&authorize.Request{ClientID: "client-1", Scope: []string{"openid"}},
		&sessions.Active{Session: &store.Session{Subject: "user-1"}},
		authorizeHint{grant: &store.Grant{ID: "grant-1"}},
	)
	if err == nil {
		t.Fatal("same-owner grant with a different ID was accepted")
	}
}

// TestReuseOrCreateGrant_NewAuthorizationDetailsAmendTheExistingGrant
// pins that a repeat authorization asking for details the record does
// not cover extends that record rather than minting a second one. A
// second row for the same (subject, client) is a grant the consent
// screen never shows and the user cannot revoke, while its refresh
// chain stays redeemable. Grant Management's create action, which does
// mint per authorization, dispatches before this function is reached.
func TestReuseOrCreateGrant_NewAuthorizationDetailsAmendTheExistingGrant(t *testing.T) {
	t.Parallel()

	existingDetail := map[string]any{"type": "account_information"}
	newDetail := map[string]any{"type": "payment_initiation", "amount": "100"}
	grants := &corruptGrantStore{
		findBySubjectResult: &store.Grant{
			ID:                   "grant-old",
			Subject:              "user-1",
			ClientID:             "client-1",
			Scope:                []string{"openid", "profile"},
			AuthorizationDetails: []map[string]any{existingDetail},
		},
	}
	result, err := reuseOrCreateGrant(context.Background(), resolved{
		Deps: Deps{Grants: grants},
	}, grantUpsert{
		Subject:              "user-1",
		ClientID:             "client-1",
		Scope:                []string{"openid", "profile"},
		AuthorizationDetails: []map[string]any{newDetail},
		Now:                  time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("reuseOrCreateGrant: %v", err)
	}
	if result.ID != "grant-old" {
		t.Fatalf("result.ID=%q; new authorization_details minted a second grant for the same "+
			"(subject, client) instead of extending the one the user can see", result.ID)
	}
	if len(result.AuthorizationDetails) != 2 {
		t.Fatalf("AuthorizationDetails=%v want existing + new", result.AuthorizationDetails)
	}
	if !authorizationDetailsCovered([]map[string]any{existingDetail, newDetail}, result) {
		t.Fatalf("result does not cover both details: %v", result.AuthorizationDetails)
	}
}
