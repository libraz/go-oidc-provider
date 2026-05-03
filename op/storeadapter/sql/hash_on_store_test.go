package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// rawAuthCodeID is a recognisable bearer-secret string the test
// looks for verbatim in the underlying SQLite tables. It is chosen
// to be nonsense-like-a-real-token so a regression that writes raw
// values back into the schema is easy to spot in failure output.
const (
	rawAuthCodeID = "ac_raw_secret_must_not_be_persisted_0123456789"
	rawRefreshID  = "rt_raw_secret_must_not_be_persisted_0123456789"
	rawParentID   = "rt_parent_raw_secret_0123456789_abcdef"
	rawPARURI     = "urn:ietf:params:oauth:request_uri:raw_secret_0123456789"
)

// openHashOnStoreFixture bootstraps a fresh SQLite-backed adapter
// and returns both the store handle and the underlying *sql.DB.
// Pinning the C-3 invariant requires a direct read of the stored
// rows so the test reaches around the [store.Store] interface; the
// helper centralises that escape hatch and keeps the per-test setup
// flat.
func openHashOnStoreFixture(t *testing.T) (*oidcsql.Store, *databasesql.DB, time.Time) {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	dir := t.TempDir()
	dsn := "file:" + dir + "/oidc.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithClock(fixedClock{now: now}))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s, db, now
}

// TestSQLite_HashOnStore_AuthCode pins the C-3 invariant that the
// SQL adapter MUST NOT persist a raw authorization-code ID. After
// Save the underlying oidc_authorization_codes row stores the
// SHA-256 hex digest of the bearer secret; the raw secret is
// completely absent from the table.
func TestSQLite_HashOnStore_AuthCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db, now := openHashOnStoreFixture(t)

	if err := s.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{
		ID:        rawAuthCodeID,
		ClientID:  "c",
		Subject:   "sub",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	rows := selectAllText(t, db, "SELECT id FROM oidc_authorization_codes")
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d (%v)", len(rows), rows)
	}
	storedID := rows[0]
	if storedID == rawAuthCodeID {
		t.Fatalf("oidc_authorization_codes.id stored the raw secret %q", storedID)
	}
	if got, want := storedID, patterns.Digest(rawAuthCodeID); got != want {
		t.Fatalf("oidc_authorization_codes.id = %q, want digest %q", got, want)
	}
	for _, scan := range scanAllStringColumns(t, db, "oidc_authorization_codes") {
		if strings.Contains(scan, rawAuthCodeID) {
			t.Fatalf("oidc_authorization_codes leaked the raw secret in %q", scan)
		}
	}

	// Find / Consume must still resolve the raw secret end-to-end.
	got, err := s.AuthorizationCodes().Find(ctx, rawAuthCodeID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != rawAuthCodeID {
		t.Fatalf("Find returned ID %q, want %q (caller-presented value)", got.ID, rawAuthCodeID)
	}
	consumed, err := s.AuthorizationCodes().Consume(ctx, rawAuthCodeID)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if consumed.ConsumedAt == nil {
		t.Fatal("Consume returned nil ConsumedAt")
	}
}

// TestSQLite_HashOnStore_RefreshToken pins the C-3 invariant for
// refresh tokens, including the parent_id chain pointer. Both
// columns store SHA-256 hex digests; neither raw secret reaches
// the database.
func TestSQLite_HashOnStore_RefreshToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db, now := openHashOnStoreFixture(t)

	parent := rawParentID
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID:        rawParentID,
		ClientID:  "c",
		Subject:   "sub",
		GrantID:   "g",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save parent: %v", err)
	}
	if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
		ID:        rawRefreshID,
		ClientID:  "c",
		Subject:   "sub",
		GrantID:   "g",
		ParentID:  &parent,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatalf("Save child: %v", err)
	}

	rows := selectAllTextPair(t, db, "SELECT id, parent_id FROM oidc_refresh_tokens ORDER BY created_at")
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d (%v)", len(rows), rows)
	}
	for _, row := range rows {
		if row[0] == rawRefreshID || row[0] == rawParentID {
			t.Fatalf("oidc_refresh_tokens.id stored a raw secret: %q", row[0])
		}
		if row[1] == rawParentID {
			t.Fatalf("oidc_refresh_tokens.parent_id stored a raw secret: %q", row[1])
		}
	}
	wantParentDigest := patterns.Digest(rawParentID)
	foundChild := false
	for _, row := range rows {
		if row[0] == patterns.Digest(rawRefreshID) {
			foundChild = true
			if row[1] != wantParentDigest {
				t.Fatalf("child parent_id = %q, want digest %q", row[1], wantParentDigest)
			}
		}
	}
	if !foundChild {
		t.Fatalf("child row keyed on digest %q not found", patterns.Digest(rawRefreshID))
	}

	for _, scan := range scanAllStringColumns(t, db, "oidc_refresh_tokens") {
		if strings.Contains(scan, rawRefreshID) || strings.Contains(scan, rawParentID) {
			t.Fatalf("oidc_refresh_tokens leaked a raw secret in %q", scan)
		}
	}

	// End-to-end Find resolves the raw secret and surfaces the
	// caller-presented ID back; the digest stays inside the schema.
	got, err := s.RefreshTokens().Find(ctx, rawRefreshID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != rawRefreshID {
		t.Fatalf("Find returned ID %q, want %q (caller-presented value)", got.ID, rawRefreshID)
	}

	// RevokeChain walks the parent_id digest graph; revoking the
	// root must mark the descendant too.
	if err := s.RefreshTokens().RevokeChain(ctx, rawParentID); err != nil {
		t.Fatalf("RevokeChain: %v", err)
	}
	child, err := s.RefreshTokens().Find(ctx, rawRefreshID)
	if err != nil {
		t.Fatalf("Find child after revoke: %v", err)
	}
	if !child.Revoked {
		t.Fatalf("child not revoked after RevokeChain on parent")
	}
}

// TestSQLite_HashOnStore_PAR pins the C-3 invariant for pushed
// authorization request URIs.
func TestSQLite_HashOnStore_PAR(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db, now := openHashOnStoreFixture(t)

	if err := s.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
		URI:       rawPARURI,
		ClientID:  "c",
		RawParams: []byte("{}"),
		ExpiresAt: now.Add(time.Minute),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	rows := selectAllText(t, db, "SELECT uri FROM oidc_par_records")
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0] == rawPARURI {
		t.Fatalf("oidc_par_records.uri stored the raw secret %q", rows[0])
	}
	if got, want := rows[0], patterns.Digest(rawPARURI); got != want {
		t.Fatalf("oidc_par_records.uri = %q, want digest %q", got, want)
	}
	for _, scan := range scanAllStringColumns(t, db, "oidc_par_records") {
		if strings.Contains(scan, rawPARURI) {
			t.Fatalf("oidc_par_records leaked the raw secret in %q", scan)
		}
	}

	got, err := s.PushedAuthRequests().Find(ctx, rawPARURI)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.URI != rawPARURI {
		t.Fatalf("Find returned URI %q, want %q (caller-presented value)", got.URI, rawPARURI)
	}
}

// selectAllText runs query against db and returns every first-column
// TEXT value as a flat slice. The helper is the regression net for
// "raw secret leaked into the schema": the test reads the stored
// column directly and compares it byte-for-byte against the wire
// value the caller passed to Save.
func selectAllText(t *testing.T, db *databasesql.DB, query string) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	return out
}

// selectAllTextPair runs query against db and returns every
// (col1, col2) TEXT pair. col2 may be NULL; NULL is mapped to the
// empty string so the caller can compare without unwrapping.
func selectAllTextPair(t *testing.T, db *databasesql.DB, query string) [][2]string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	var out [][2]string
	for rows.Next() {
		var a string
		var b databasesql.NullString
		if err := rows.Scan(&a, &b); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, [2]string{a, b.String})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	return out
}

// scanAllStringColumns reads every TEXT-like column on every row of
// the supplied table and returns the concatenated values. The helper
// is intentionally over-broad: a future schema change that surfaces
// a raw bearer secret in any column trips the assertion regardless
// of which column the leak lands in.
func scanAllStringColumns(t *testing.T, db *databasesql.DB, table string) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), "SELECT * FROM "+table) //nolint:gosec // table is an adapter-controlled constant in this test file.
	if err != nil {
		t.Fatalf("SELECT *: %v", err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("Columns: %v", err)
	}
	var out []string
	for rows.Next() {
		buf := make([]any, len(cols))
		for i := range buf {
			var v databasesql.NullString
			buf[i] = &v
		}
		if err := rows.Scan(buf...); err != nil {
			t.Fatalf("scan: %v", err)
		}
		for _, p := range buf {
			if v, ok := p.(*databasesql.NullString); ok && v.Valid {
				out = append(out, v.String)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	return out
}
