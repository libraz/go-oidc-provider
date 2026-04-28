package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestInjection_WithNamingRejectsHostileIdentifiers proves the
// adapter refuses to construct itself when an attacker controls the
// physical table name. This is the structural defence: identifiers
// never reach the query builder, so SQL injection through the naming
// override is impossible by construction. The cases below mirror the
// payloads the OFCS hostile-input test uses.
func TestInjection_WithNamingRejectsHostileIdentifiers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		desc string
		val  string
	}{
		{"semicolon drop", "clients; DROP TABLE oidc_clients --"},
		{"comment terminator", "clients/* */ UNION SELECT * FROM oidc_users --"},
		{"backtick wrap", "`clients`"},
		{"double-quote wrap", `"clients"`},
		{"newline statement", "clients\nDELETE FROM oidc_clients"},
		{"control character", "clients\x00"},
		{"unicode bypass", "ｃlients"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			db, err := databasesql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = db.Close() }()
			_, err = oidcsql.New(db, oidcsql.SQLite(),
				oidcsql.WithNaming(map[string]string{"clients": tc.val}))
			if err == nil {
				t.Fatalf("New accepted hostile identifier %q", tc.val)
			}
			if !strings.Contains(err.Error(), "identifier") {
				t.Errorf("error message does not mention identifier: %v", err)
			}
		})
	}
}

// TestInjection_PayloadValuesAreParameterised proves the adapter
// stores attacker-controlled record fields verbatim and never lets
// them split a statement. The payloads below would be catastrophic if
// any code path interpolated them as SQL; the parameterised query
// path stores them as data and round-trips them unchanged.
func TestInjection_PayloadValuesAreParameterised(t *testing.T) {
	t.Parallel()
	db, err := databasesql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	s, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	const hostile = `'; DROP TABLE oidc_clients; --`
	c := &store.Client{
		ID:           "client-x",
		ClientName:   hostile,
		RedirectURIs: []string{hostile, hostile + "&"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", hostile},
	}
	if err := s.RegisterClient(context.Background(), c); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	got, err := s.Clients().GetClient(context.Background(), "client-x")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.ClientName != hostile {
		t.Errorf("ClientName = %q, want %q", got.ClientName, hostile)
	}
	if len(got.RedirectURIs) != 2 || got.RedirectURIs[0] != hostile {
		t.Errorf("RedirectURIs lost or transformed: %#v", got.RedirectURIs)
	}
	// Re-issue a follow-up read to verify the table still exists.
	if _, err := s.Clients().GetClient(context.Background(), "absent"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetClient absent after hostile insert: want ErrNotFound, got %v", err)
	}
}

// TestSchema_RewritesAllTableNames asserts that every default table
// name is replaced by the override when WithNaming is in effect, so
// embedders who supply a partial override do not silently retain the
// default identifier on the un-renamed tables.
func TestSchema_RewritesAllTableNames(t *testing.T) {
	t.Parallel()
	db, err := databasesql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithNaming(map[string]string{
		"clients":                    "tenant_clients",
		"refresh_tokens":             "tenant_rt",
		"access_tokens":              "tenant_at",
		"authorization_codes":        "tenant_codes",
		"grants":                     "tenant_grants",
		"sessions":                   "tenant_sessions",
		"par_records":                "tenant_par",
		"interactions":               "tenant_interactions",
		"consumed_jtis":              "tenant_jtis",
		"users":                      "tenant_users",
		"initial_access_tokens":      "tenant_iats",
		"registration_access_tokens": "tenant_rats",
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	schema := s.Schema()
	for _, want := range []string{
		"tenant_clients", "tenant_rt", "tenant_at", "tenant_codes",
		"tenant_grants", "tenant_sessions", "tenant_par", "tenant_interactions",
		"tenant_jtis", "tenant_users", "tenant_iats", "tenant_rats",
	} {
		if !strings.Contains(schema, want) {
			t.Errorf("schema missing rewritten name %q", want)
		}
	}
	for _, banned := range []string{
		"oidc_clients", "oidc_refresh_tokens", "oidc_access_tokens",
	} {
		if strings.Contains(schema, banned) {
			t.Errorf("schema retained default name %q after rewrite", banned)
		}
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
}

// TestSchema_DefaultsCompile is a smoke test that the embedded SQLite
// schema is well-formed: an empty in-memory database can absorb every
// CREATE TABLE / CREATE INDEX statement and immediately serve a write.
func TestSchema_DefaultsCompile(t *testing.T) {
	t.Parallel()
	db, err := databasesql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	s, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	jti := "jti-1"
	if err := s.ConsumedJTIs().Mark(context.Background(), jti, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	has, err := s.ConsumedJTIs().Has(context.Background(), jti)
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if !has {
		t.Fatal("Has returned false after Mark")
	}
}
