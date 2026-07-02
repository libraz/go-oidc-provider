//nolint:testpackage // tests reference unexported validateIdentifier and applyOverrides.
package oidcsql

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateIdentifier_AcceptsRegularIdentifiers(t *testing.T) {
	t.Parallel()
	cases := []string{
		"a",
		"_",
		"clients",
		"oidc_clients",
		"My_Table_42",
		"_underscored",
		strings.Repeat("a", 63),
	}
	for _, name := range cases {
		if err := validateIdentifier(name); err != nil {
			t.Errorf("%q: want accepted, got %v", name, err)
		}
	}
}

func TestValidateIdentifier_RejectsInjectionLookalikes(t *testing.T) {
	t.Parallel()
	// Each value below is something an attacker might try to push
	// through a naming override. The validator MUST reject all of
	// them so the SQL the adapter emits is never assembled from
	// untrusted input.
	cases := []struct {
		name string
		val  string
	}{
		{"empty", ""},
		{"leading digit", "1clients"},
		{"dot separator", "schema.clients"},
		{"semicolon", "clients;DROP TABLE oidc_clients"},
		{"backtick", "`clients`"},
		{"double quote", `"clients"`},
		{"single quote", "client's"},
		{"space", "oidc clients"},
		{"newline", "clients\nDROP TABLE x"},
		{"tab", "clients\tx"},
		{"comment", "clients--evil"},
		{"slash star", "clients/*evil*/"},
		{"unicode letter", "テーブル"},
		{"emoji", "clients😈"},
		{"too long", strings.Repeat("a", 64)},
		{"way too long", strings.Repeat("a", 256)},
		{"null byte", "clients\x00drop"},
		{"control char", "clients\x01"},
		{"sql union", "clients UNION SELECT * FROM users"},
		{"backslash", `clients\evil`},
	}
	for _, c := range cases {
		if err := validateIdentifier(c.val); err == nil {
			t.Errorf("%s: want rejected, got accepted", c.name)
		}
	}
}

func TestApplyOverrides_ValidKeysOnly(t *testing.T) {
	t.Parallel()
	n := defaultNames()
	if err := n.applyOverrides(map[string]string{
		"clients":               "tenant_clients",
		"refresh_tokens":        "tenant_rt",
		"par_records":           "tenant_par",
		"consumed_jtis":         "tenant_jti",
		"initial_access_tokens": "tenant_iat",
	}); err != nil {
		t.Fatalf("applyOverrides: %v", err)
	}
	if n.clients != "tenant_clients" {
		t.Errorf("clients: %q", n.clients)
	}
	if n.refreshes != "tenant_rt" {
		t.Errorf("refreshes: %q", n.refreshes)
	}
	if n.pars != "tenant_par" {
		t.Errorf("pars: %q", n.pars)
	}
	if n.jtis != "tenant_jti" {
		t.Errorf("jtis: %q", n.jtis)
	}
	if n.iats != "tenant_iat" {
		t.Errorf("iats: %q", n.iats)
	}
}

// TestRewriteSchema_RenamesEveryTable guards against a rename pair being
// added to applyOverrides / knownNamingKeys but forgotten in
// rewriteSchema. When that happens the query builder targets the renamed
// table while Migrate creates the table under its default name, so the
// store boots broken at the first query (this regressed op_metadata
// once). The test overrides every known key to a distinct sentinel and
// asserts that no default name survives the rewrite for any dialect.
func TestRewriteSchema_RenamesEveryTable(t *testing.T) {
	t.Parallel()

	overrides := make(map[string]string, len(knownNamingKeys))
	for _, key := range knownNamingKeys {
		overrides[key] = "rn_" + key
	}

	n := defaultNames()
	if err := n.applyOverrides(overrides); err != nil {
		t.Fatalf("applyOverrides: %v", err)
	}

	for _, d := range []struct {
		name    string
		dialect Dialect
	}{
		{"sqlite", SQLite()},
		{"mysql", MySQL()},
		{"postgres", Postgres()},
	} {
		rewritten := rewriteSchema(d.dialect.schema, n)
		for _, def := range defaultNames().all() {
			if strings.Contains(rewritten, def) {
				t.Errorf("%s: default table name %q survived rewriteSchema; "+
					"its rename pair is missing from rewriteSchema", d.name, def)
			}
		}
	}
}

// TestApplyOverrides_CollisionBetweenTwoOverridesRejected proves
// applyOverrides rejects a naming map whose two distinct logical keys
// resolve to the same physical table name. Without this check the
// query layer and the migration DDL would silently target one shared
// table for two record kinds.
func TestApplyOverrides_CollisionBetweenTwoOverridesRejected(t *testing.T) {
	t.Parallel()
	n := defaultNames()
	err := n.applyOverrides(map[string]string{
		"clients": "shared_name",
		"grants":  "shared_name",
	})
	if err == nil {
		t.Fatal("want collision error, got nil")
	}
	if !strings.Contains(err.Error(), "shared_name") {
		t.Errorf("error %q does not name the colliding physical name", err)
	}
}

// TestApplyOverrides_CollisionWithUnoverriddenDefaultRejected proves
// the collision check also fires when only one side of the clash was
// explicitly overridden — the other logical table kept its default
// physical name.
func TestApplyOverrides_CollisionWithUnoverriddenDefaultRejected(t *testing.T) {
	t.Parallel()
	n := defaultNames()
	err := n.applyOverrides(map[string]string{"clients": defaultNames().grants})
	if err == nil {
		t.Fatal("want collision error, got nil")
	}
}

// TestApplyOverrides_DistinctOverridesAccepted is the positive
// counterpart: a naming map whose resolved physical names remain
// pairwise distinct MUST still construct successfully.
func TestApplyOverrides_DistinctOverridesAccepted(t *testing.T) {
	t.Parallel()
	n := defaultNames()
	if err := n.applyOverrides(map[string]string{
		"clients": "tenant_clients",
		"grants":  "tenant_grants",
	}); err != nil {
		t.Fatalf("applyOverrides: %v", err)
	}
}

// TestNameMapFieldOrderMatchesKnownNamingKeys pins the invariant
// [nameMap.checkCollisions] depends on: nameMap.all() and
// knownNamingKeys must stay in the same field order so the collision
// error can name the correct logical key by index. A default nameMap
// has no duplicate values, so pairing each resolved name 1:1 with its
// logical key and round-tripping through applyOverrides with that same
// key set must not report a spurious collision.
func TestNameMapFieldOrderMatchesKnownNamingKeys(t *testing.T) {
	t.Parallel()
	if len(defaultNames().all()) != len(knownNamingKeys) {
		t.Fatalf("nameMap.all() has %d entries, knownNamingKeys has %d",
			len(defaultNames().all()), len(knownNamingKeys))
	}
	overrides := make(map[string]string, len(knownNamingKeys))
	for i, key := range knownNamingKeys {
		overrides[key] = fmt.Sprintf("ord_%d_%s", i, key)
	}
	n := defaultNames()
	if err := n.applyOverrides(overrides); err != nil {
		t.Fatalf("applyOverrides: %v", err)
	}
	got := n.all()
	for i, key := range knownNamingKeys {
		want := overrides[key]
		if got[i] != want {
			t.Errorf("nameMap.all()[%d] = %q, want %q (field order drifted from knownNamingKeys[%d]=%q)",
				i, got[i], want, i, key)
		}
	}
}

func TestApplyOverrides_UnknownKeyRejected(t *testing.T) {
	t.Parallel()
	n := defaultNames()
	err := n.applyOverrides(map[string]string{"clients": "ok", "typo_here": "x"})
	if err == nil {
		t.Fatal("want error for unknown key")
	}
	if !strings.Contains(err.Error(), "typo_here") {
		t.Errorf("error %q does not name the offending key", err)
	}
}

func TestApplyOverrides_InvalidPhysicalRejected(t *testing.T) {
	t.Parallel()
	n := defaultNames()
	err := n.applyOverrides(map[string]string{"clients": "clients;DROP TABLE x"})
	if err == nil {
		t.Fatal("want error for injection lookalike")
	}
}

// FuzzValidateIdentifier is a fuzz harness to surface any input that
// slips past the validator without matching a sensible identifier
// shape. The harness asserts the basic invariant: every accepted
// identifier is composed exclusively of [A-Za-z0-9_], starts with a
// letter or underscore, and is between 1 and 63 bytes long.
func FuzzValidateIdentifier(f *testing.F) {
	for _, seed := range []string{
		"clients", "oidc_clients", "_x", "ABC123", "tableNameThatIsExactlySixtyThreeCharactersLongAndHopefullyOK",
		"", "1bad", "table.name", "evil;drop",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		err := validateIdentifier(name)
		if err != nil {
			return
		}
		// Accepted: enforce shape invariants.
		if name == "" {
			t.Errorf("validator accepted empty string")
			return
		}
		if len(name) > 63 {
			t.Errorf("validator accepted overlong identifier %q (%d bytes)", name, len(name))
			return
		}
		if !isLetterOrUnderscore(rune(name[0])) {
			t.Errorf("validator accepted leading non-letter in %q", name)
			return
		}
		for i := 1; i < len(name); i++ {
			if !isIdentChar(rune(name[i])) {
				t.Errorf("validator accepted forbidden byte %q in %q", name[i], name)
				return
			}
		}
	})
}

func isLetterOrUnderscore(r rune) bool {
	return r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

func isIdentChar(r rune) bool {
	return isLetterOrUnderscore(r) || (r >= '0' && r <= '9')
}
