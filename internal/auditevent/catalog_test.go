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
		auditevent.AuditGrantManagementRevokeFailed: {
			Name:   auditevent.AuditGrantManagementRevokeFailed,
			Metric: auditevent.MetricNone,
		},
		auditevent.AuditRefreshPriorAccessTokenRevokeFailed: {
			Name:   auditevent.AuditRefreshPriorAccessTokenRevokeFailed,
			Metric: auditevent.MetricTokenRevokeFailures,
			Label:  "prior_access_token",
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

// auditNamesReservedForEmbedders lists catalog rows the OP is
// deliberately not the source of. The names exist so an embedder can
// report these events under the same vocabulary as the rest of the
// catalog, and the public godoc says as much for each of them. They are
// not expected to gain an in-tree emitter.
var auditNamesReservedForEmbedders = map[auditevent.Name]string{
	auditevent.AuditAccountCreated:             "account provisioning runs on an account plane the OP does not host",
	auditevent.AuditAccountDeleted:             "account deletion runs on an account plane the OP does not host",
	auditevent.AuditAccountEmailAdded:          "email management is an account-plane action, not an OIDC flow step",
	auditevent.AuditAccountEmailVerified:       "email verification is an account-plane action, not an OIDC flow step",
	auditevent.AuditAccountEmailRemoved:        "email management is an account-plane action, not an OIDC flow step",
	auditevent.AuditAccountEmailSetPrimary:     "email management is an account-plane action, not an OIDC flow step",
	auditevent.AuditAccountPasskeyRegistered:   "passkey enrolment is an account-plane action; the OP only verifies at login",
	auditevent.AuditAccountPasskeyRemoved:      "passkey removal is an account-plane action; the OP only verifies at login",
	auditevent.AuditAccountTOTPEnabled:         "TOTP enrolment is an account-plane action; the OP only verifies at login",
	auditevent.AuditAccountTOTPDisabled:        "TOTP removal is an account-plane action; the OP only verifies at login",
	auditevent.AuditAccountPasswordChanged:     "password changes run on an account plane the OP does not host",
	auditevent.AuditAccountRecoveryRegenerated: "recovery-code management runs on an account plane the OP does not host",
	auditevent.AuditRecoverySupportEscalation:  "support-desk escalation is a help-desk workflow outside the OP",
	auditevent.AuditAccountFederationLinked:    "identity linking is owned by the embedder's account plane",
	auditevent.AuditAccountFederationUnlinked:  "identity linking is owned by the embedder's account plane",
	auditevent.AuditRateLimitExceeded:          "the library implements no generic HTTP rate limit; throttle decisions are the embedder's",
	auditevent.AuditRateLimitBypassed:          "the library implements no generic HTTP rate limit; throttle decisions are the embedder's",
	auditevent.AuditMFARequired:                "the chain has no once-per-attempt point to fire from; a factor prompt repeats on every retry",
	auditevent.AuditStepUpRequired:             "step-up is the resource server's decision; the OP sees an ordinary authorization request",
	auditevent.AuditStepUpSuccess:              "step-up is the resource server's decision; only it knows whether the new attempt satisfied it",
	auditevent.AuditCIBAAuthDeviceApproved:     "the authentication device calls CIBARequestStore.Approve directly; no library code sits between that call and the store",
	auditevent.AuditCIBAAuthDeviceDenied:       "the authentication device calls CIBARequestStore.Deny directly; the OP's own denial is the poll-abuse lockout, which has its own name",
}

// auditNamesNotYetWired lists catalog rows whose documentation says
// they fire and which no in-tree emitter reaches. Every entry is a
// recorded defect rather than a design decision: the event is
// advertised on the public catalog, and a subscriber that alerts on it
// is alerting on a signal that never arrives. Where the row also
// carries a metric projection, the corresponding Prometheus series
// stays at zero for that label.
//
// The map is expected to shrink as emitters land and must never grow:
// a new catalog row arrives together with the code that emits it.
var auditNamesNotYetWired = map[auditevent.Name]string{
	auditevent.AuditConsentGrantedDelta:    "an incremental grant is recorded as a plain consent.granted",
	auditevent.AuditConsentRevoked:         "consent withdrawal is recorded only as grant_management.revoked",
	auditevent.AuditConsentSkippedExisting: "reuse of a stored consent is recorded nowhere",
	auditevent.AuditLogoutRPInitiated:      "the end-session endpoint records session events but not the RP-initiated marker",
	auditevent.AuditPKCEViolation:          "a failed code_verifier check returns a protocol error with no audit record",
	auditevent.AuditRedirectURIMismatch:    "a rejected redirect_uri returns a protocol error with no audit record",
	auditevent.AuditAlgLegacyUsed:          "no path reports admitting a legacy algorithm",
}

// TestCatalogNames_ReachAnEmitterOrAreDeclaredUnemitted is the converse
// of TestInTreeAuditEmissions_DoNotUseStringLiterals: that test keeps
// emissions inside the catalog, this one keeps the catalog inside the
// set of events that actually happen. A row that no code path reaches
// is a promise the OP does not keep, so it has to be declared as such
// in one of the two maps above with a reason. A declared row that IS
// reached fails too — a stale "never fires" note misleads exactly like
// an unwired catalog row.
func TestCatalogNames_ReachAnEmitterOrAreDeclaredUnemitted(t *testing.T) {
	t.Parallel()

	root, sources := parseAuditSources(t)
	constants := auditNameConstants(t, sources)
	aliases := auditNameAliases(sources, constants)
	reached := reachedAuditNames(root, sources, constants, aliases)

	for _, definition := range auditevent.Catalog() {
		name := definition.Name
		reservedReason, reserved := auditNamesReservedForEmbedders[name]
		unwiredReason, unwired := auditNamesNotYetWired[name]
		sites := reached[name]
		switch {
		case reserved && unwired:
			t.Errorf("%q is declared in both maps; it belongs in exactly one", name)
		case len(sites) > 0 && reserved:
			t.Errorf("%q is declared reserved for embedders (%s) but the OP emits it at %s: drop the declaration",
				name, reservedReason, sites[0])
		case len(sites) > 0 && unwired:
			t.Errorf("%q is declared as never emitted (%s) but is emitted at %s: drop the declaration",
				name, unwiredReason, sites[0])
		case len(sites) == 0 && !reserved && !unwired:
			t.Errorf("%q is registered in the catalog but no in-tree code path emits it: "+
				"add the emitter, or declare it in auditNamesReservedForEmbedders / auditNamesNotYetWired with a reason",
				name)
		}
	}
	for _, declared := range []map[auditevent.Name]string{auditNamesReservedForEmbedders, auditNamesNotYetWired} {
		for name := range declared {
			if _, ok := auditevent.Lookup(string(name)); !ok {
				t.Errorf("%q is declared as never emitted but is not a catalog row", name)
			}
		}
	}
}

// auditSource is one parsed non-test file of the module's own packages.
type auditSource struct {
	path        string
	packageName string
	fileset     *token.FileSet
	file        *ast.File
}

// declaringFiles are read for the names they declare and skipped when
// looking for emitters. catalog.go names every catalog constant and
// op/audit.go aliases every one of them, so scanning either for
// references would mark the whole catalog as reached — they declare the
// vocabulary rather than use it.
func declaringFiles(root string) map[string]bool {
	return map[string]bool{
		filepath.Join(root, "internal", "auditevent", "catalog.go"): true,
		filepath.Join(root, "op", "audit.go"):                       true,
	}
}

func parseAuditSources(t *testing.T) (string, []auditSource) {
	t.Helper()

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))

	var sources []auditSource
	for _, directory := range []string{"internal", "op"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fileset := token.NewFileSet()
			file, parseErr := parser.ParseFile(fileset, path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			sources = append(sources, auditSource{
				path:        path,
				packageName: file.Name.Name,
				fileset:     fileset,
				file:        file,
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", directory, err)
		}
	}
	if len(sources) == 0 {
		t.Fatal("no source files found")
	}
	return root, sources
}

// auditNameConstants maps each catalog constant's identifier to the
// wire name it holds. Emitters name the constant rather than the wire
// string, so resolving an emission needs this direction.
func auditNameConstants(t *testing.T, sources []auditSource) map[string]auditevent.Name {
	t.Helper()

	constants := make(map[string]auditevent.Name)
	for _, source := range sources {
		if source.packageName != "auditevent" {
			continue
		}
		for _, declaration := range source.file.Decls {
			generic, ok := declaration.(*ast.GenDecl)
			if !ok || generic.Tok != token.CONST {
				continue
			}
			for _, specification := range generic.Specs {
				value, ok := specification.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, identifier := range value.Names {
					if index >= len(value.Values) {
						continue
					}
					literal, ok := value.Values[index].(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						continue
					}
					unquoted, err := strconv.Unquote(literal.Value)
					if err != nil {
						t.Fatalf("%s: %v", source.fileset.Position(literal.Pos()), err)
					}
					constants[identifier.Name] = auditevent.Name(unquoted)
				}
			}
		}
	}
	registered := make(map[auditevent.Name]bool, len(constants))
	for _, name := range constants {
		registered[name] = true
	}
	for _, definition := range auditevent.Catalog() {
		if !registered[definition.Name] {
			t.Fatalf("catalog row %q has no named constant to resolve emissions against", definition.Name)
		}
	}
	return constants
}

// auditNameAliases maps "package.Identifier" to the catalog name that
// identifier stands for. Most emitters do not name auditevent directly:
// packages re-declare the names they use as local constants, some of
// them exported and read from a second package, so an emission site is
// only resolvable through this map. Aliases of aliases are resolved by
// repeating the pass until it stops finding new ones.
func auditNameAliases(sources []auditSource, constants map[string]auditevent.Name) map[string]auditevent.Name {
	aliases := make(map[string]auditevent.Name)
	// Each pass that learns something adds at least one entry to a
	// finite map, so the loop terminates on the first quiet pass.
	for found := 1; found > 0; {
		found = 0
		for _, source := range sources {
			if source.packageName == "auditevent" {
				continue
			}
			for _, declaration := range source.file.Decls {
				generic, ok := declaration.(*ast.GenDecl)
				if !ok || (generic.Tok != token.CONST && generic.Tok != token.VAR) {
					continue
				}
				for _, specification := range generic.Specs {
					value, ok := specification.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for index, identifier := range value.Names {
						if index >= len(value.Values) {
							continue
						}
						name, ok := resolveAuditName(value.Values[index], source.packageName, constants, aliases)
						if !ok {
							continue
						}
						key := source.packageName + "." + identifier.Name
						if _, known := aliases[key]; !known {
							aliases[key] = name
							found++
						}
					}
				}
			}
		}
	}
	return aliases
}

// reachedAuditNames maps each catalog name to the positions where code
// hands it to the audit path. A name counts as reached when it is
// referenced outside its own declaration: either directly as the Name
// of an audit.Event literal, or passed to a helper that builds the
// event — several packages funnel a whole family of events through one
// emit helper, so requiring the literal alone would report those
// families as unreached.
func reachedAuditNames(
	root string,
	sources []auditSource,
	constants map[string]auditevent.Name,
	aliases map[string]auditevent.Name,
) map[auditevent.Name][]string {
	skipped := declaringFiles(root)
	reached := make(map[auditevent.Name][]string)
	for _, source := range sources {
		if skipped[source.path] {
			continue
		}
		ast.Inspect(source.file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.ValueSpec:
				// A declaration that introduces an alias is not a use of it.
				for _, value := range typed.Values {
					if _, ok := resolveAuditName(value, source.packageName, constants, aliases); ok {
						return false
					}
				}
			case *ast.SelectorExpr, *ast.Ident:
				expression, _ := node.(ast.Expr)
				name, ok := resolveAuditName(expression, source.packageName, constants, aliases)
				if !ok {
					return true
				}
				reached[name] = append(reached[name], source.fileset.Position(node.Pos()).String())
				return false
			}
			return true
		})
	}
	return reached
}

// resolveAuditName reads the catalog name an expression stands for.
// Emitters write it as auditevent.AuditX, as string(auditevent.AuditX),
// as a package-local alias, or as an alias exported by another package,
// and conversions wrap any of those.
func resolveAuditName(
	expression ast.Expr,
	packageName string,
	constants map[string]auditevent.Name,
	aliases map[string]auditevent.Name,
) (auditevent.Name, bool) {
	switch typed := expression.(type) {
	case *ast.CallExpr:
		if len(typed.Args) == 1 {
			return resolveAuditName(typed.Args[0], packageName, constants, aliases)
		}
	case *ast.SelectorExpr:
		qualifier, ok := typed.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		if qualifier.Name == "auditevent" {
			name, ok := constants[typed.Sel.Name]
			return name, ok
		}
		name, ok := aliases[qualifier.Name+"."+typed.Sel.Name]
		return name, ok
	case *ast.Ident:
		name, ok := aliases[packageName+"."+typed.Name]
		return name, ok
	}
	return "", false
}
