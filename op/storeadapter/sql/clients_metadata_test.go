package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestSQLite_ClientStore_EncryptionMetadata_RoundTrip pins that every
// outbound-encryption metadata field round-trips faithfully through the
// SQLite-backed client store. The eight fields land in fresh columns
// added in v0.9.1; a missing column or a swapped scan position would
// surface here as a value-mismatch rather than as a silent loss in
// production. Postgres / MySQL share the column manifest via
// clientColumns / clientArgs / scanClient, so a passing SQLite case
// exercises the bind/scan plumbing all three dialects use.
func TestSQLite_ClientStore_EncryptionMetadata_RoundTrip(t *testing.T) {
	t.Parallel()

	db, err := databasesql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	s, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	want := &store.Client{ //nolint:gosec // G101 false positive: JWE alg/enc names look like credentials.
		ID:                                "rp-encryption",
		RedirectURIs:                      []string{"https://rp.example.com/cb"},
		GrantTypes:                        []string{"authorization_code"},
		Scopes:                            []string{"openid"},
		RequestObjectEncryptionAlg:        "RSA-OAEP-256",
		RequestObjectEncryptionEnc:        "A256GCM",
		IDTokenEncryptedResponseAlg:       "ECDH-ES+A128KW",
		IDTokenEncryptedResponseEnc:       "A128GCM",
		UserInfoEncryptedResponseAlg:      "ECDH-ES",
		UserInfoEncryptedResponseEnc:      "A256GCM",
		AuthorizationEncryptedResponseAlg: "ECDH-ES+A256KW",
		AuthorizationEncryptedResponseEnc: "A128GCM",
		IntrospectionEncryptedResponseAlg: "RSA-OAEP-256",
		IntrospectionEncryptedResponseEnc: "A256GCM",
	}
	ctx := context.Background()
	if err := s.RegisterClient(ctx, want); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	got, err := s.Clients().GetClient(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	checks := []struct {
		name      string
		got, want string
	}{
		{"RequestObjectEncryptionAlg", got.RequestObjectEncryptionAlg, want.RequestObjectEncryptionAlg},
		{"RequestObjectEncryptionEnc", got.RequestObjectEncryptionEnc, want.RequestObjectEncryptionEnc},
		{"IDTokenEncryptedResponseAlg", got.IDTokenEncryptedResponseAlg, want.IDTokenEncryptedResponseAlg},
		{"IDTokenEncryptedResponseEnc", got.IDTokenEncryptedResponseEnc, want.IDTokenEncryptedResponseEnc},
		{"UserInfoEncryptedResponseAlg", got.UserInfoEncryptedResponseAlg, want.UserInfoEncryptedResponseAlg},
		{"UserInfoEncryptedResponseEnc", got.UserInfoEncryptedResponseEnc, want.UserInfoEncryptedResponseEnc},
		{"AuthorizationEncryptedResponseAlg", got.AuthorizationEncryptedResponseAlg, want.AuthorizationEncryptedResponseAlg},
		{"AuthorizationEncryptedResponseEnc", got.AuthorizationEncryptedResponseEnc, want.AuthorizationEncryptedResponseEnc},
		{"IntrospectionEncryptedResponseAlg", got.IntrospectionEncryptedResponseAlg, want.IntrospectionEncryptedResponseAlg},
		{"IntrospectionEncryptedResponseEnc", got.IntrospectionEncryptedResponseEnc, want.IntrospectionEncryptedResponseEnc},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}

	// Update path: empty values overwrite the persisted record so a
	// later read sees the cleared columns. Mirrors the RFC 7592 PUT
	// semantics the manage handler relies on.
	cleared := &store.Client{
		ID:           want.ID,
		RedirectURIs: want.RedirectURIs,
		GrantTypes:   want.GrantTypes,
		Scopes:       want.Scopes,
	}
	if err := s.UpdateClient(ctx, cleared); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	got2, err := s.Clients().GetClient(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetClient after Update: %v", err)
	}
	for _, c := range []struct {
		name string
		got  string
	}{
		{"RequestObjectEncryptionAlg", got2.RequestObjectEncryptionAlg},
		{"IDTokenEncryptedResponseAlg", got2.IDTokenEncryptedResponseAlg},
		{"UserInfoEncryptedResponseAlg", got2.UserInfoEncryptedResponseAlg},
		{"AuthorizationEncryptedResponseAlg", got2.AuthorizationEncryptedResponseAlg},
		{"IntrospectionEncryptedResponseAlg", got2.IntrospectionEncryptedResponseAlg},
	} {
		if c.got != "" {
			t.Errorf("after clearing Update: %s = %q, want empty", c.name, c.got)
		}
	}
}
