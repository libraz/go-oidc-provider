package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

func allNamingOverrides(t *testing.T) map[string]string {
	t.Helper()
	keys := validNamingKeys(t)
	out := make(map[string]string, len(keys))
	for _, key := range keys {
		out[key] = "tenant_" + key
	}
	return out
}

func validNamingKeys(t *testing.T) []string {
	t.Helper()
	db, err := databasesql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	_, err = oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithNaming(map[string]string{"__invalid__": "valid_name"}))
	if err == nil {
		t.Fatal("New accepted invalid WithNaming key")
	}
	const marker = "valid keys: "
	_, keysText, ok := strings.Cut(err.Error(), marker)
	if !ok {
		t.Fatalf("unknown-key error missing %q: %v", marker, err)
	}
	return strings.Split(strings.TrimSuffix(keysText, ")"), ", ")
}

func defaultTableNames(t *testing.T) []string {
	t.Helper()
	db, err := databasesql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	s, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	re := regexp.MustCompile(`CREATE TABLE IF NOT EXISTS (oidc_[a-z_]+)`)
	matches := re.FindAllStringSubmatch(s.Schema(), -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		out = append(out, match[1])
	}
	return out
}

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
			_, err = oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithNaming(map[string]string{"clients": tc.val}))
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
	overrides := allNamingOverrides(t)
	s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithNaming(overrides))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	schema := s.Schema()
	for _, want := range overrides {
		if !strings.Contains(schema, want) {
			t.Errorf("schema missing rewritten name %q", want)
		}
	}
	for _, banned := range defaultTableNames(t) {
		if strings.Contains(schema, banned) {
			t.Errorf("schema retained default name %q after rewrite", banned)
		}
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
}

// TestNew_RejectsCollidingWithNamingOverrides proves construction
// fails when two overrides resolve to the same physical table name.
// Without this gate, the query layer and the migration DDL would
// silently share one physical table between two logical record kinds
// with no construction-time signal.
func TestNew_RejectsCollidingWithNamingOverrides(t *testing.T) {
	t.Parallel()
	db, err := databasesql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	_, err = oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithNaming(map[string]string{
		"clients": "shared_physical_name",
		"grants":  "shared_physical_name",
	}))
	if err == nil {
		t.Fatal("New accepted two WithNaming overrides that collide on the same physical name")
	}
	if !strings.Contains(err.Error(), "shared_physical_name") {
		t.Errorf("collision error %q does not name the offending physical name", err)
	}
}

// TestNew_RejectsWithNamingCollidingWithUnoverriddenDefault proves
// construction fails when an override's physical name collides with
// a logical table the caller left at its default, not only when two
// overrides collide with each other.
func TestNew_RejectsWithNamingCollidingWithUnoverriddenDefault(t *testing.T) {
	t.Parallel()
	db, err := databasesql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	// "grants" is never mentioned in the override map, so it keeps its
	// default physical name ("oidc_grants"); renaming "clients" onto
	// that exact string must still be rejected.
	_, err = oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithNaming(map[string]string{
		"clients": "oidc_grants",
	}))
	if err == nil {
		t.Fatal("New accepted a WithNaming override colliding with an un-overridden default")
	}
}

// TestSchema_RewriteSurvivesSubstringOverride pins the specific
// corruption mode a sequential strings.ReplaceAll rewrite is prone to:
// an override whose resolved value happens to contain another
// default table name as a substring. If the rewriter reprocessed
// already-substituted text (as a naive multi-pass ReplaceAll chain
// does), the second table's rename pass would match inside the first
// table's already-rewritten name and mangle it. The single-pass,
// token-based rewriter must not exhibit this failure: both renamed
// tables must appear in the schema exactly as configured, and
// Migrate must succeed against the result.
func TestSchema_RewriteSurvivesSubstringOverride(t *testing.T) {
	t.Parallel()
	db, err := databasesql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	// "oidc_authorization_codes_v2" embeds the *default* authorization-codes
	// table name as a literal prefix substring, so a rewrite pass that
	// later targets that default name is the exact scenario that could
	// corrupt it under the old multi-pass ReplaceAll scheme.
	s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithNaming(map[string]string{
		"clients":             "oidc_authorization_codes_v2",
		"authorization_codes": "ac_new",
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	schema := s.Schema()
	if !strings.Contains(schema, "CREATE TABLE IF NOT EXISTS oidc_authorization_codes_v2") {
		t.Errorf("schema lost the clients override; got:\n%s", schema)
	}
	if !strings.Contains(schema, "CREATE TABLE IF NOT EXISTS ac_new") {
		t.Errorf("schema lost the authorization_codes override; got:\n%s", schema)
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
