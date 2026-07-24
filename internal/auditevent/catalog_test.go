package auditevent_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/auditevent"
)

func TestCatalog_ValidUniqueDefinitions(t *testing.T) {
	t.Parallel()

	seen := make(map[auditevent.Name]struct{}, len(auditevent.Catalog()))
	for _, definition := range auditevent.Catalog() {
		if definition.Name == "" {
			t.Fatal("catalog contains an empty event name")
		}
		if _, duplicate := seen[definition.Name]; duplicate {
			t.Fatalf("duplicate event name %q", definition.Name)
		}
		seen[definition.Name] = struct{}{}
		if definition.Metric != auditevent.MetricNone && auditevent.MetricName(definition.Metric) == "" {
			t.Errorf("%q has metric %d without a registered family name", definition.Name, definition.Metric)
		}
	}
}

func TestCatalog_ReturnsCopy(t *testing.T) {
	t.Parallel()

	first := auditevent.Catalog()
	first[0].Name = "mutated"
	if second := auditevent.Catalog(); second[0].Name == "mutated" {
		t.Fatal("Catalog returned mutable package state")
	}
}

func TestCatalog_OperationalMetricMappings(t *testing.T) {
	t.Parallel()

	expected := map[auditevent.Name]auditevent.Definition{
		auditevent.AuditSessionDestroyFailed: {
			Name: auditevent.AuditSessionDestroyFailed, Metric: auditevent.MetricLogoutFailures, Label: "session_destroy",
		},
		auditevent.AuditLogoutTokenRevokeFailed: {
			Name: auditevent.AuditLogoutTokenRevokeFailed, Metric: auditevent.MetricLogoutFailures, Label: "token_revoke",
		},
		auditevent.AuditLogoutBackChannelResolveFailed: {
			Name: auditevent.AuditLogoutBackChannelResolveFailed, Metric: auditevent.MetricBackChannelLogout, Label: "resolve_failed",
		},
		auditevent.AuditLogoutBackChannelOverflow: {
			Name: auditevent.AuditLogoutBackChannelOverflow, Metric: auditevent.MetricBackChannelLogout, Label: "overflow",
		},
		auditevent.AuditDeviceCodePollObservationFailed: {
			Name: auditevent.AuditDeviceCodePollObservationFailed, Metric: auditevent.MetricDeviceCode, Label: "poll_observation.failed",
		},
		auditevent.AuditCIBAPollObservationFailed: {
			Name: auditevent.AuditCIBAPollObservationFailed, Metric: auditevent.MetricCIBA, Label: "poll_observation.failed",
		},
		auditevent.AuditDCRCascadeRefreshRevokeFailed: {
			Name: auditevent.AuditDCRCascadeRefreshRevokeFailed, Metric: auditevent.MetricDCR, Label: "cascade.refresh_revoke_failed",
		},
		auditevent.AuditDCRCascadeGrantRevokeFailed: {
			Name: auditevent.AuditDCRCascadeGrantRevokeFailed, Metric: auditevent.MetricDCR, Label: "cascade.grant_revoke_failed",
		},
		auditevent.AuditDCRCascadeAccessTokenRevokeFailed: {
			Name:   auditevent.AuditDCRCascadeAccessTokenRevokeFailed,
			Metric: auditevent.MetricDCR,
			Label:  "cascade.access_token_revoke_failed",
		},
		auditevent.AuditDCRCascadeOpaqueAccessTokenRevokeFailed: {
			Name:   auditevent.AuditDCRCascadeOpaqueAccessTokenRevokeFailed,
			Metric: auditevent.MetricDCR,
			Label:  "cascade.opaque_access_token_revoke_failed",
		},
	}
	for name, want := range expected {
		got, ok := auditevent.Lookup(string(name))
		if !ok {
			t.Errorf("Lookup(%q) missed operational event", name)
			continue
		}
		if got != want {
			t.Errorf("Lookup(%q) = %+v, want %+v", name, got, want)
		}
	}
}

// TestInTreeAuditEmissions_DoNotUseStringLiterals makes adding an in-tree
// audit.Event with an unregistered raw name fail at review time. Emitters use
// constants from this package; embedders remain free to send extension events
// through their own audit sink, and the metrics bridge forwards those without
// projecting them onto a catalog metric.
func TestInTreeAuditEmissions_DoNotUseStringLiterals(t *testing.T) {
	t.Parallel()

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	for _, directory := range []string{"internal", "op"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			assertNoRawAuditEventName(t, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", directory, err)
		}
	}
}

func assertNoRawAuditEventName(t *testing.T, path string) {
	t.Helper()

	fileset := token.NewFileSet()
	file, err := parser.ParseFile(fileset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok || !isAuditEventType(literal.Type) {
			return true
		}
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			identifier, ok := field.Key.(*ast.Ident)
			if !ok || identifier.Name != "Name" {
				continue
			}
			value, ok := field.Value.(*ast.BasicLit)
			if !ok || value.Kind != token.STRING {
				continue
			}
			name, unquoteErr := strconv.Unquote(value.Value)
			if unquoteErr != nil {
				t.Errorf("%s: invalid audit event literal: %v", fileset.Position(value.Pos()), unquoteErr)
				continue
			}
			t.Errorf("%s: audit event %q must use an auditevent catalog constant", fileset.Position(value.Pos()), name)
		}
		return true
	})
}

func isAuditEventType(expression ast.Expr) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Event" {
		return false
	}
	packageName, ok := selector.X.(*ast.Ident)
	return ok && packageName.Name == "audit"
}
