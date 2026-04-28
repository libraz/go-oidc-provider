//nolint:testpackage // tests reference unexported validateIdentifier and applyOverrides.
package oidcsql

import (
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
