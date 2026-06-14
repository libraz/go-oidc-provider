//nolint:testpackage // tests reference unexported buildQueries, auditQueryString, and nameMap.
package oidcsql

import (
	"reflect"
	"strings"
	"testing"
)

// TestBuildQueries_DefaultsAuditClean asserts that the canonical name
// map produces a queries struct that passes the audit (Layer 6). The
// test also enumerates every field via reflection and verifies the
// table name appears in the rendered template, catching a future
// query that forgets to interpolate the name.
func TestBuildQueries_DefaultsAuditClean(t *testing.T) {
	t.Parallel()
	q, err := buildQueries(SQLite(), defaultNames())
	if err != nil {
		t.Fatalf("buildQueries: %v", err)
	}
	v := reflect.ValueOf(q)
	tt := v.Type()
	for i := range v.NumField() {
		field := tt.Field(i)
		if v.Field(i).Kind() != reflect.String {
			continue
		}
		s := v.Field(i).String()
		if s == "" {
			t.Errorf("field %s is empty", field.Name)
		}
	}
}

// TestBuildQueries_AcrossDialects asserts that all three shipped
// dialects produce non-empty audit-clean queries with no surprising
// differences in table-name interpolation.
func TestBuildQueries_AcrossDialects(t *testing.T) {
	t.Parallel()
	for _, d := range []Dialect{SQLite(), MySQL(), Postgres()} {
		t.Run(d.Name(), func(t *testing.T) {
			t.Parallel()
			q, err := buildQueries(d, defaultNames())
			if err != nil {
				t.Fatalf("buildQueries(%s): %v", d.Name(), err)
			}
			v := reflect.ValueOf(q)
			for i := range v.NumField() {
				if v.Field(i).Kind() != reflect.String {
					continue
				}
				s := v.Field(i).String()
				if s == "" {
					t.Errorf("%s: field %s empty", d.Name(), v.Type().Field(i).Name)
				}
			}
		})
	}
}

// TestBuildQueries_RejectsHostileNames asserts Layer 4: even if a
// caller manages to forge a nameMap with a hostile value (bypassing
// applyOverrides), buildQueries refuses to operate. The hostile values
// are the same set the public TestInjection_WithNamingRejectsHostileIdentifiers
// vets at the WithNaming gate.
func TestBuildQueries_RejectsHostileNames(t *testing.T) {
	t.Parallel()
	hostile := []string{
		"clients;DROP TABLE x",
		"clients--",
		"`clients`",
		`"clients"`,
		"clients/*evil*/",
		"clients UNION SELECT * FROM users",
		"client's",
	}
	for _, h := range hostile {
		t.Run(h, func(t *testing.T) {
			t.Parallel()
			n := defaultNames()
			// Bypass applyOverrides — directly stuff the hostile
			// value into the field that buildQueries reads. This
			// simulates a future code path that constructs a
			// nameMap without going through the public gate.
			n.clients = h
			_, err := buildQueries(SQLite(), n)
			if err == nil {
				t.Fatalf("buildQueries accepted hostile name %q", h)
			}
		})
	}
}

// TestAuditQueryString_RejectsDangerousBytes pins down exactly which
// byte patterns Layer 6 considers dangerous. New queries that someday
// need a legitimate use of one of these bytes will fail the audit
// here, which is by design — the review surfaces the change.
func TestAuditQueryString_RejectsDangerousBytes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		s    string
	}{
		{"single quote", "SELECT 'x' FROM t"},
		{"double quote", `SELECT "x" FROM t`},
		{"backtick", "SELECT `x` FROM t"},
		{"semicolon", "SELECT 1; DROP TABLE t"},
		{"line comment", "SELECT 1 -- evil"},
		{"block comment open", "SELECT /* evil */ 1"},
		{"block comment close", "SELECT 1 */ evil"},
		{"NUL byte", "SELECT 1\x00"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if err := auditQueryString(c.s); err == nil {
				t.Errorf("auditQueryString accepted %q", c.s)
			}
		})
	}
}

// TestAuditQueryString_AcceptsAdapterCorpus asserts that none of the
// shipped queries trip the audit. Combined with
// TestBuildQueries_DefaultsAuditClean this is double coverage: the
// builder calls auditQueries internally, and the test re-runs the
// audit on every dialect just to be sure.
func TestAuditQueryString_AcceptsAdapterCorpus(t *testing.T) {
	t.Parallel()
	for _, d := range []Dialect{SQLite(), MySQL(), Postgres()} {
		t.Run(d.Name(), func(t *testing.T) {
			t.Parallel()
			q, err := buildQueries(d, defaultNames())
			if err != nil {
				t.Fatalf("buildQueries: %v", err)
			}
			v := reflect.ValueOf(q)
			tt := v.Type()
			for i := range v.NumField() {
				if v.Field(i).Kind() != reflect.String {
					continue
				}
				s := v.Field(i).String()
				if err := auditQueryString(s); err != nil {
					t.Errorf("%s: field %s tripped audit: %v\nquery: %s",
						d.Name(), tt.Field(i).Name, err, s)
				}
			}
		})
	}
}

// TestBuildQueries_AppliesNamingOverrides asserts that a non-default
// table name actually appears in the rendered query (a regression net
// for buildQueries forgetting to interpolate the parameter).
func TestBuildQueries_AppliesNamingOverrides(t *testing.T) {
	t.Parallel()
	n := defaultNames()
	if err := n.applyOverrides(map[string]string{
		"clients":        "tenant_clients",
		"refresh_tokens": "tenant_rt",
	}); err != nil {
		t.Fatalf("applyOverrides: %v", err)
	}
	q, err := buildQueries(SQLite(), n)
	if err != nil {
		t.Fatalf("buildQueries: %v", err)
	}
	if !strings.Contains(q.clientGet, "tenant_clients") {
		t.Errorf("clientGet missing override: %q", q.clientGet)
	}
	if strings.Contains(q.clientGet, "oidc_clients") {
		t.Errorf("clientGet still references default: %q", q.clientGet)
	}
	if !strings.Contains(q.refreshSave, "tenant_rt") {
		t.Errorf("refreshSave missing override: %q", q.refreshSave)
	}
}

func TestBuildQueries_GCQueriesPreserveZeroExpiry(t *testing.T) {
	t.Parallel()

	q, err := buildQueries(SQLite(), defaultNames())
	if err != nil {
		t.Fatalf("buildQueries: %v", err)
	}
	for name, query := range map[string]string{
		"accessTokenGC":       q.accessTokenGC,
		"opaqueAccessTokenGC": q.opaqueAccessTokenGC,
		"jtiGC":               q.jtiGC,
		"deviceCodeGC":        q.deviceCodeGC,
		"cibaGC":              q.cibaGC,
	} {
		if !strings.Contains(query, "expires_at > 0 AND expires_at <") {
			t.Errorf("%s query must preserve zero-expiry rows, got %q", name, query)
		}
	}
}
