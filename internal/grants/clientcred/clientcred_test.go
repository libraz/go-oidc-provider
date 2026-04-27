package clientcred_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/grants/clientcred"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestAuthorize_GrantTypeWireString anchors the package-private wire
// constant to the public [grant.ClientCredentials] enum so a future
// rename of either side cannot drift.
func TestAuthorize_GrantTypeWireString(t *testing.T) {
	t.Parallel()
	if got := grant.ClientCredentials.String(); got != "client_credentials" {
		t.Fatalf("grant.ClientCredentials.String()=%q want client_credentials", got)
	}
}

// TestAuthorize_TableDriven walks the canonical posture: confidential
// + grant-permitted + subset scope succeeds; public, missing grant,
// openid, and out-of-set scope each fail with a distinct sentinel.
func TestAuthorize_TableDriven(t *testing.T) {
	t.Parallel()

	confidential := func(grants, scopes []string) *store.Client {
		return &store.Client{
			ID:           "client-conf",
			GrantTypes:   slices.Clone(grants),
			Scopes:       slices.Clone(scopes),
			PublicClient: false,
		}
	}

	cases := []struct {
		name      string
		client    *store.Client
		requested []string
		wantErr   error
		// wantScope is checked only when wantErr is nil.
		wantScope []string
	}{
		{
			name:      "confidential_no_scope_param_returns_full_registered_set",
			client:    confidential([]string{"client_credentials"}, []string{"read", "write"}),
			requested: nil,
			wantScope: []string{"read", "write"},
		},
		{
			name:      "confidential_subset_scope_returns_subset",
			client:    confidential([]string{"client_credentials"}, []string{"read", "write", "delete"}),
			requested: []string{"read", "write"},
			wantScope: []string{"read", "write"},
		},
		{
			name:      "confidential_single_scope_subset",
			client:    confidential([]string{"client_credentials"}, []string{"read", "write"}),
			requested: []string{"read"},
			wantScope: []string{"read"},
		},
		{
			name: "public_client_rejected",
			client: &store.Client{
				ID:           "client-pub",
				GrantTypes:   []string{"client_credentials"},
				Scopes:       []string{"read"},
				PublicClient: true,
			},
			requested: nil,
			wantErr:   clientcred.ErrPublicClient,
		},
		{
			name:      "client_without_grant_rejected",
			client:    confidential([]string{"authorization_code", "refresh_token"}, []string{"read"}),
			requested: nil,
			wantErr:   clientcred.ErrGrantNotPermitted,
		},
		{
			name:      "client_with_empty_grant_types_rejected",
			client:    confidential(nil, []string{"read"}),
			requested: nil,
			wantErr:   clientcred.ErrGrantNotPermitted,
		},
		{
			name:      "openid_scope_rejected",
			client:    confidential([]string{"client_credentials"}, []string{"openid", "read"}),
			requested: []string{"openid"},
			wantErr:   clientcred.ErrOpenIDScope,
		},
		{
			name:      "openid_scope_rejected_when_mixed_with_other",
			client:    confidential([]string{"client_credentials"}, []string{"openid", "read"}),
			requested: []string{"read", "openid"},
			wantErr:   clientcred.ErrOpenIDScope,
		},
		{
			name:      "scope_outside_registered_set_rejected",
			client:    confidential([]string{"client_credentials"}, []string{"read"}),
			requested: []string{"read", "write"},
			wantErr:   clientcred.ErrScopeForbidden,
		},
		{
			name:      "scope_completely_outside_registered_set_rejected",
			client:    confidential([]string{"client_credentials"}, []string{"read"}),
			requested: []string{"admin"},
			wantErr:   clientcred.ErrScopeForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := clientcred.Authorize(clientcred.AuthorizeInput{
				Client:         tc.client,
				RequestedScope: tc.requested,
			})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err=%v want %v", err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("got=%+v want nil on error path", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err=%v", err)
			}
			if got == nil {
				t.Fatal("Authorized=nil on success path")
			}
			if !slices.Equal(got.Scope, tc.wantScope) {
				t.Errorf("Scope=%v want %v", got.Scope, tc.wantScope)
			}
		})
	}
}

// TestAuthorize_NilClient guards against a misuse where the caller
// hands the package a nil client (typically a missing lookup return
// path). The function returns a generic error, not a typed sentinel,
// so the HTTP layer maps it to server_error rather than leaking the
// programmer bug as a wire code.
func TestAuthorize_NilClient(t *testing.T) {
	t.Parallel()
	got, err := clientcred.Authorize(clientcred.AuthorizeInput{Client: nil})
	if err == nil {
		t.Fatal("err=nil want non-nil")
	}
	if got != nil {
		t.Errorf("got=%+v want nil", got)
	}
	for _, sentinel := range []error{
		clientcred.ErrPublicClient,
		clientcred.ErrGrantNotPermitted,
		clientcred.ErrOpenIDScope,
		clientcred.ErrScopeForbidden,
	} {
		if errors.Is(err, sentinel) {
			t.Errorf("err matched typed sentinel %v; nil client must not surface as a wire code", sentinel)
		}
	}
}

// TestAuthorize_ScopeIndependence confirms the returned scope slice is
// independent of both the client's registered set and the input
// RequestedScope: mutating the result must not corrupt either source.
func TestAuthorize_ScopeIndependence(t *testing.T) {
	t.Parallel()

	t.Run("falls_back_to_clients_scopes_returns_clone", func(t *testing.T) {
		t.Parallel()
		client := &store.Client{
			ID:         "client-conf",
			GrantTypes: []string{"client_credentials"},
			Scopes:     []string{"read", "write"},
		}
		got, err := clientcred.Authorize(clientcred.AuthorizeInput{Client: client})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		got.Scope[0] = "tampered"
		if client.Scopes[0] != "read" {
			t.Errorf("client.Scopes mutated; got=%v want first entry to remain %q", client.Scopes, "read")
		}
	})

	t.Run("requested_subset_returns_clone", func(t *testing.T) {
		t.Parallel()
		client := &store.Client{
			ID:         "client-conf",
			GrantTypes: []string{"client_credentials"},
			Scopes:     []string{"read", "write"},
		}
		requested := []string{"read"}
		got, err := clientcred.Authorize(clientcred.AuthorizeInput{
			Client:         client,
			RequestedScope: requested,
		})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		got.Scope[0] = "tampered"
		if requested[0] != "read" {
			t.Errorf("RequestedScope mutated; got=%v want first entry to remain %q", requested, "read")
		}
		if client.Scopes[0] != "read" {
			t.Errorf("client.Scopes mutated; got=%v", client.Scopes)
		}
	})
}
