//go:build testcontainers

package oidcsql_test

import (
	"bytes"
	"context"
	databasesql "database/sql"
	"errors"
	"os"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	mysqlmod "github.com/testcontainers/testcontainers-go/modules/mysql"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestMySQL_UsernameCollation measures, against a real server, the
// property v1.sql's comment on oidc_users.username only documents: that
// MySQL 8.4's own default utf8mb4 collation (utf8mb4_0900_ai_ci) folds
// accented and unaccented Latin letters onto the same key, and that the
// schema's explicit utf8mb4_bin pin keeps them apart end to end.
//
// Both halves run against the same container so a future engine
// version changes both readings together instead of one silently
// drifting out of sync with the other.
func TestMySQL_UsernameCollation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ctr, err := mysqlmod.Run(ctx, mysqlImage,
		mysqlmod.WithUsername("root"),
		mysqlmod.WithPassword("oidcpw"),
		mysqlmod.WithDatabase("oidc_admin"),
	)
	if err != nil {
		if os.Getenv("RELEASE_CONTRACT_REQUIRED") == "1" {
			t.Fatalf("mysql container required for release contract: %v", err)
		}
		t.Skipf("mysql container unavailable (Docker not running?): %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	adminDSN, err := ctr.ConnectionString(ctx, "parseTime=true", "multiStatements=true")
	if err != nil {
		t.Fatalf("ConnectionString: %v", err)
	}
	baseCfg, err := mysqldriver.ParseDSN(adminDSN)
	if err != nil {
		t.Fatalf("ParseDSN: %v", err)
	}
	admin, err := databasesql.Open("mysql", adminDSN)
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	openDB := func(name string) *databasesql.DB {
		t.Helper()
		if _, err := admin.ExecContext(ctx, "CREATE DATABASE `"+name+"`"); err != nil {
			t.Fatalf("CREATE DATABASE %s: %v", name, err)
		}
		cfg := *baseCfg
		cfg.DBName = name
		db, err := databasesql.Open("mysql", cfg.FormatDSN())
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}

	t.Run("DefaultCollationFoldsAccents", func(t *testing.T) {
		// Negative control: a column left at MySQL 8.4's own default
		// utf8mb4 collation, with no reference to the store's schema at
		// all. If this sub-test stopped observing folding, the pin in
		// v1.sql would be defending against a threat that no longer
		// exists on the tested engine version, and the guarantee proven
		// below would say nothing about production risk.
		db := openDB("oidc_collation_control")
		if _, err := db.ExecContext(ctx, `
			CREATE TABLE accent_probe (
				username VARCHAR(255) CHARACTER SET utf8mb4 NOT NULL,
				UNIQUE KEY accent_probe_username (username)
			)`); err != nil {
			t.Fatalf("CREATE TABLE accent_probe: %v", err)
		}
		if _, err := db.ExecContext(ctx,
			"INSERT INTO accent_probe (username) VALUES (?)", "café@example.com"); err != nil {
			t.Fatalf("insert café@example.com: %v", err)
		}

		var folded string
		err := db.QueryRowContext(ctx,
			"SELECT username FROM accent_probe WHERE username = ?", "cafe@example.com",
		).Scan(&folded)
		if err != nil {
			t.Fatalf("default-collation lookup for the unaccented spelling: %v "+
				"(want it to resolve the accented row, proving the default collation folds them)", err)
		}
		if folded != "café@example.com" {
			t.Fatalf("default-collation lookup for cafe@example.com returned %q, want café@example.com", folded)
		}

		_, err = db.ExecContext(ctx,
			"INSERT INTO accent_probe (username) VALUES (?)", "cafe@example.com")
		var mysqlErr *mysqldriver.MySQLError
		if !errors.As(err, &mysqlErr) || mysqlErr.Number != 1062 {
			t.Fatalf("inserting the unaccented spelling alongside the accented one: err = %v, "+
				"want a 1062 duplicate-entry error (the default collation treats the two as the same unique-key value)", err)
		}
	})

	t.Run("PinnedCollationDistinguishesAccents", func(t *testing.T) {
		// The actual guarantee: the schema oidcsql ships, applied
		// through Store.Migrate exactly as an embedder would run it,
		// keeps the two spellings apart end to end — as distinct
		// FindByUsername results with their own password hashes, and as
		// two rows a unique index accepts rather than merges.
		db := openDB("oidc_collation_guarantee")
		s, err := oidcsql.New(db, oidcsql.MySQL())
		if err != nil {
			t.Fatalf("oidcsql.New: %v", err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate: %v", err)
		}

		accentedHash := []byte("$argon2id$v=19$m=65536,t=3,p=4$AAAA$accented")
		asciiHash := []byte("$argon2id$v=19$m=65536,t=3,p=4$AAAA$ascii")
		if err := s.PutUserWithPassword(ctx,
			&store.User{Subject: "user-cafe-accented"}, "café@example.com", accentedHash); err != nil {
			t.Fatalf("PutUserWithPassword(café@example.com): %v", err)
		}
		if err := s.PutUserWithPassword(ctx,
			&store.User{Subject: "user-cafe-ascii"}, "cafe@example.com", asciiHash); err != nil {
			t.Fatalf("PutUserWithPassword(cafe@example.com): %v", err)
		}

		// Under the pinned collation these are two non-conflicting
		// inserts. Under the default collation, MySQL's
		// INSERT ... ON DUPLICATE KEY UPDATE would treat the second
		// write as a hit on the username unique key and silently
		// overwrite the first account's username and password_hash in
		// place — no error, just a corrupted row — which is why the
		// assertions below read the data back rather than trusting the
		// absence of an error from the writes above.
		pw := s.UserPasswords()
		gotAccented, err := pw.FindByUsername(ctx, "café@example.com")
		if err != nil {
			t.Fatalf("FindByUsername(café@example.com): %v", err)
		}
		if gotAccented.Subject != "user-cafe-accented" {
			t.Fatalf("FindByUsername(café@example.com) subject = %q, want %q",
				gotAccented.Subject, "user-cafe-accented")
		}
		gotASCII, err := pw.FindByUsername(ctx, "cafe@example.com")
		if err != nil {
			t.Fatalf("FindByUsername(cafe@example.com): %v", err)
		}
		if gotASCII.Subject != "user-cafe-ascii" {
			t.Fatalf("FindByUsername(cafe@example.com) subject = %q, want %q",
				gotASCII.Subject, "user-cafe-ascii")
		}

		accentedHashGot, err := pw.ReadPasswordHash(ctx, "user-cafe-accented")
		if err != nil {
			t.Fatalf("ReadPasswordHash(user-cafe-accented): %v", err)
		}
		if !bytes.Equal(accentedHashGot, accentedHash) {
			t.Fatalf("ReadPasswordHash(user-cafe-accented) = %q, want its own hash %q — "+
				"a login for the unaccented spelling would otherwise be checked against a different account's password",
				accentedHashGot, accentedHash)
		}
		asciiHashGot, err := pw.ReadPasswordHash(ctx, "user-cafe-ascii")
		if err != nil {
			t.Fatalf("ReadPasswordHash(user-cafe-ascii): %v", err)
		}
		if !bytes.Equal(asciiHashGot, asciiHash) {
			t.Fatalf("ReadPasswordHash(user-cafe-ascii) = %q, want its own hash %q", asciiHashGot, asciiHash)
		}

		var collation string
		err = db.QueryRowContext(ctx, `
			SELECT COLLATION_NAME FROM information_schema.COLUMNS
			WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oidc_users' AND COLUMN_NAME = 'username'`,
		).Scan(&collation)
		if err != nil {
			t.Fatalf("read the username column's collation from information_schema: %v", err)
		}
		if collation != "utf8mb4_bin" {
			t.Errorf("oidc_users.username collation = %q, want utf8mb4_bin", collation)
		}
	})
}

// TestMySQL_IdentifierCollation is [TestMySQL_UsernameCollation] for the
// identifier columns store-adapters-003 pins: every subject and client_id
// column, plus oidc_clients.id. Each is compared for exact equality against
// a value the OP generated or an embedder chose, never freeform text, so
// the same folding defect applies: on MySQL's default collation
// PutUserWithPassword("Alice", ...) overwrites the row "alice" already
// has, FindBySubject("ALICE") resolves "alice", and GetClient("MYAPP")
// resolves "myapp".
func TestMySQL_IdentifierCollation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ctr, err := mysqlmod.Run(ctx, mysqlImage,
		mysqlmod.WithUsername("root"),
		mysqlmod.WithPassword("oidcpw"),
		mysqlmod.WithDatabase("oidc_admin"),
	)
	if err != nil {
		if os.Getenv("RELEASE_CONTRACT_REQUIRED") == "1" {
			t.Fatalf("mysql container required for release contract: %v", err)
		}
		t.Skipf("mysql container unavailable (Docker not running?): %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	adminDSN, err := ctr.ConnectionString(ctx, "parseTime=true", "multiStatements=true")
	if err != nil {
		t.Fatalf("ConnectionString: %v", err)
	}
	baseCfg, err := mysqldriver.ParseDSN(adminDSN)
	if err != nil {
		t.Fatalf("ParseDSN: %v", err)
	}
	admin, err := databasesql.Open("mysql", adminDSN)
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	if _, err := admin.ExecContext(ctx, "CREATE DATABASE `oidc_identifier_collation`"); err != nil {
		t.Fatalf("CREATE DATABASE: %v", err)
	}
	cfg := *baseCfg
	cfg.DBName = "oidc_identifier_collation"
	db, err := databasesql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("open oidc_identifier_collation: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s, err := oidcsql.New(db, oidcsql.MySQL())
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Structural half: every column this schema uses to hold a subject or
	// a client_id, read out of the live database rather than a hand-kept
	// list, so a column added later is covered without anyone updating
	// this test.
	t.Run("EveryIdentifierColumnIsPinned", func(t *testing.T) {
		rows, err := db.QueryContext(ctx, `
			SELECT TABLE_NAME, COLUMN_NAME, COLLATION_NAME FROM information_schema.COLUMNS
			WHERE TABLE_SCHEMA = DATABASE()
			  AND (COLUMN_NAME IN ('subject', 'client_id')
			       OR (TABLE_NAME = 'oidc_clients' AND COLUMN_NAME = 'id'))`)
		if err != nil {
			t.Fatalf("query information_schema: %v", err)
		}
		defer func() { _ = rows.Close() }()
		checked := 0
		for rows.Next() {
			var table, column, collation string
			if err := rows.Scan(&table, &column, &collation); err != nil {
				t.Fatalf("scan: %v", err)
			}
			checked++
			if collation != "utf8mb4_bin" {
				t.Errorf("%s.%s collation = %q, want utf8mb4_bin", table, column, collation)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("rows: %v", err)
		}
		if checked == 0 {
			t.Fatal("no subject/client_id/oidc_clients.id columns matched: the query stopped tracking the schema")
		}
	})

	// Behavioural half: the two lookups the finding names, driven through
	// the public API exactly as an embedder would call it.
	t.Run("SubjectDistinguishesCase", func(t *testing.T) {
		if err := s.PutUser(ctx, &store.User{Subject: "Alice"}); err != nil {
			t.Fatalf("PutUser(Alice): %v", err)
		}
		if err := s.PutUser(ctx, &store.User{Subject: "alice"}); err != nil {
			t.Fatalf("PutUser(alice): %v", err)
		}
		users := s.Users()
		upper, err := users.FindBySubject(ctx, "Alice")
		if err != nil {
			t.Fatalf("FindBySubject(Alice): %v", err)
		}
		lower, err := users.FindBySubject(ctx, "alice")
		if err != nil {
			t.Fatalf("FindBySubject(alice): %v", err)
		}
		if upper.Subject != "Alice" || lower.Subject != "alice" {
			t.Fatalf("FindBySubject folded Alice/alice onto one record: got %q and %q", upper.Subject, lower.Subject)
		}
	})

	t.Run("ClientIDDistinguishesCase", func(t *testing.T) {
		if err := s.RegisterClient(ctx, &store.Client{
			ID:           "MyApp",
			RedirectURIs: []string{"https://rp.example.com/cb"},
			GrantTypes:   []string{"authorization_code"},
			Scopes:       []string{"openid"},
		}); err != nil {
			t.Fatalf("RegisterClient(MyApp): %v", err)
		}
		if err := s.RegisterClient(ctx, &store.Client{
			ID:           "myapp",
			RedirectURIs: []string{"https://rp2.example.com/cb"},
			GrantTypes:   []string{"authorization_code"},
			Scopes:       []string{"openid"},
		}); err != nil {
			t.Fatalf("RegisterClient(myapp): %v", err)
		}
		clients := s.Clients()
		upper, err := clients.GetClient(ctx, "MyApp")
		if err != nil {
			t.Fatalf("GetClient(MyApp): %v", err)
		}
		lower, err := clients.GetClient(ctx, "myapp")
		if err != nil {
			t.Fatalf("GetClient(myapp): %v", err)
		}
		if upper.ID != "MyApp" || lower.ID != "myapp" {
			t.Fatalf("GetClient folded MyApp/myapp onto one record: got %q and %q", upper.ID, lower.ID)
		}
		if len(upper.RedirectURIs) != 1 || upper.RedirectURIs[0] != "https://rp.example.com/cb" {
			t.Fatalf("GetClient(MyApp) redirect_uris = %v, want its own record", upper.RedirectURIs)
		}
	})
}
