package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree materialises a synthetic repository and returns its root.
// Paths are slash-separated and relative, the way the checks address
// them.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

// indexTree builds the source index for a synthetic repository.
func indexTree(t *testing.T, files map[string]string) *index {
	t.Helper()
	ix, err := buildIndex(writeTree(t, files))
	if err != nil {
		t.Fatalf("buildIndex: %v", err)
	}
	return ix
}

// emptyAllowlist returns an allowlist with no rows.
func emptyAllowlist(t *testing.T) *allowlist {
	t.Helper()
	al, err := loadAllowlist(filepath.Join(t.TempDir(), "absent.txt"))
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	return al
}

// ids reduces findings to the identifiers they name.
func ids(findings []finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.id)
	}
	return out
}

// wantIDs asserts the findings name exactly the expected identifiers.
func wantIDs(t *testing.T, findings []finding, want ...string) {
	t.Helper()
	got := ids(findings)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("findings = %v; want %v", got, want)
	}
}

func TestCheckSymbols_ReportsAConstantNoLibraryPathReads(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/policy.go": `package op

const (
	// Applied is read by the library.
	Applied = "applied"

	// Abandoned is read by nothing.
	Abandoned = "abandoned"
)
`,
		"internal/engine/engine.go": `package engine

func Decide() string { return "applied" }
`,
		"op/use.go": `package op

func pick() string { return Applied }
`,
	})
	wantIDs(t, checkSymbols(ix, emptyAllowlist(t)), "op.Abandoned")
}

// A test asserting on a sentinel proves the value exists, not that the
// library can ever hand it to a caller. Counting test files as reach
// would make the whole gate agree with every abandoned sentinel that
// has a unit test.
func TestCheckSymbols_DoesNotCountATestAsReach(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/errors.go": `package op

import "errors"

// ErrNeverReturned is compared against but never produced.
var ErrNeverReturned = errors.New("never returned")
`,
		"op/errors_test.go": `package op

import (
	"errors"
	"testing"
)

func TestSentinel(t *testing.T) {
	if !errors.Is(ErrNeverReturned, ErrNeverReturned) {
		t.Fatal("no")
	}
}
`,
	})
	wantIDs(t, checkSymbols(ix, emptyAllowlist(t)), "op.ErrNeverReturned")
}

// A demo naming a symbol shows the name exists; it does not show the OP
// producing the value. Counting demos would let any finding be answered
// by adding the symbol to an example.
func TestCheckSymbols_DoesNotCountAnExampleAsReach(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/policy.go": `package op

// Unread is named only by a demo.
const Unread = "unread"
`,
		"examples/01-minimal/main.go": `package main

import "github.com/libraz/go-oidc-provider/op"

func main() { _ = op.Unread }
`,
	})
	wantIDs(t, checkSymbols(ix, emptyAllowlist(t)), "op.Unread")
}

// A public package routinely gives an internal default a name an
// embedder can reach. The library applies the internal name, so the
// re-export is reached through what it aliases.
func TestCheckSymbols_FollowsAReExportToWhatItAliases(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/email.go": `package op

import "github.com/libraz/go-oidc-provider/internal/emailotp"

// DefaultCodeTTL is the embedder-facing name for the internal default.
const DefaultCodeTTL = emailotp.DefaultCodeTTL
`,
		"internal/emailotp/emailotp.go": `package emailotp

import "time"

const DefaultCodeTTL = 5 * time.Minute

func window() time.Duration { return DefaultCodeTTL }
`,
	})
	if got := checkSymbols(ix, emptyAllowlist(t)); len(got) != 0 {
		t.Fatalf("re-export reported as unreached: %v", ids(got))
	}
}

// iota is the value, not a declaration. Resolving through it would make
// every enumeration in the tree look reached.
func TestCheckSymbols_DoesNotResolveAnEnumerationThroughIota(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/enum.go": `package op

type Posture int

const (
	// PostureUnset is never named.
	PostureUnset Posture = iota
)
`,
	})
	wantIDs(t, checkSymbols(ix, emptyAllowlist(t)), "op.PostureUnset")
}

func TestCheckSymbols_HonoursTheAllowlist(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/policy.go": `package op

// Reserved is deliberately unread.
const Reserved = "reserved"
`,
	})
	root := writeTree(t, map[string]string{
		"api/unreached.txt": "symbol\top.Reserved\tembedder-supplied vocabulary the library never selects\n",
	})
	al, err := loadAllowlist(filepath.Join(root, "api", "unreached.txt"))
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	if got := checkSymbols(ix, al); len(got) != 0 {
		t.Fatalf("allowlisted symbol reported: %v", ids(got))
	}
	if got := al.stale(); len(got) != 0 {
		t.Fatalf("consulted row reported stale: %v", ids(got))
	}
}

// eventTree is the smallest tree that exercises the event check: a
// registry, the public aliases, and one emitter.
func eventTree(aliasDoc, emitterBody string) map[string]string {
	return map[string]string{
		"internal/auditevent/catalog.go": `package auditevent

type Name string

const (
	AuditThingHappened Name = "thing.happened"
	AuditThingReserved Name = "thing.reserved"
)
`,
		"op/audit.go": `package op

import "github.com/libraz/go-oidc-provider/internal/auditevent"

type AuditEvent string

const (
	AuditThingHappened = AuditEvent(auditevent.AuditThingHappened)
` + aliasDoc + `	AuditThingReserved = AuditEvent(auditevent.AuditThingReserved)
)
`,
		"internal/authn/emit.go": `package authn

import "github.com/libraz/go-oidc-provider/internal/auditevent"

func emit() string {
	` + emitterBody + `
	return string(auditevent.AuditThingHappened)
}
`,
	}
}

func TestCheckEvents_RequiresTheMarkerWhenNothingEmits(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, eventTree("\n\t// AuditThingReserved names a distinction.\n", ""))
	findings := checkEvents(ix, emptyAllowlist(t))
	wantIDs(t, findings, "thing.reserved")
	if !strings.Contains(findings[0].detail, reservedMarker) {
		t.Fatalf("finding does not name the marker: %s", findings[0].detail)
	}
}

func TestCheckEvents_AcceptsTheMarkerWhenNothingEmits(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, eventTree("\n\t// Reserved vocabulary: the library never emits this.\n", ""))
	if got := checkEvents(ix, emptyAllowlist(t)); len(got) != 0 {
		t.Fatalf("marked event reported: %v", ids(got))
	}
}

// The converse direction is the one that rots: a caveat left behind
// after the instrumentation lands tells an operator to ignore a live
// signal.
func TestCheckEvents_RejectsTheMarkerOnAnEmittedEvent(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, eventTree(
		"\n\t// Reserved vocabulary: the library never emits this.\n",
		"_ = auditevent.AuditThingReserved",
	))
	findings := checkEvents(ix, emptyAllowlist(t))
	wantIDs(t, findings, "thing.reserved")
	if !strings.Contains(findings[0].detail, "drop the caveat") {
		t.Fatalf("finding does not ask for the caveat to go: %s", findings[0].detail)
	}
}

// A paragraph above the first of several constants describes all of
// them until the next paragraph. A check reading only spec.Doc would
// report the second and third member as unmarked.
func TestCheckEvents_InheritsTheMarkerAcrossAGroup(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"internal/auditevent/catalog.go": `package auditevent

type Name string

const (
	AuditOne Name = "one.reserved"
	AuditTwo Name = "two.reserved"
)
`,
		"op/audit.go": `package op

import "github.com/libraz/go-oidc-provider/internal/auditevent"

type AuditEvent string

// Reserved vocabulary: the library emits neither of these.
const (
	AuditOne = AuditEvent(auditevent.AuditOne)
	AuditTwo = AuditEvent(auditevent.AuditTwo)
)
`,
	})
	if got := checkEvents(ix, emptyAllowlist(t)); len(got) != 0 {
		t.Fatalf("inherited marker not seen: %v", ids(got))
	}
}

func TestCheckEvents_ReportsACatalogueEntryWithNoPublicName(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"internal/auditevent/catalog.go": `package auditevent

type Name string

const AuditOrphan Name = "orphan.event"
`,
		"op/audit.go": `package op

type AuditEvent string
`,
	})
	findings := checkEvents(ix, emptyAllowlist(t))
	wantIDs(t, findings, "orphan.event")
	if !strings.Contains(findings[0].detail, "no public op constant") {
		t.Fatalf("unexpected detail: %s", findings[0].detail)
	}
}

func TestCheckMessages_ReportsAKeyNoSurfaceRenders(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"internal/i18n/embedded/en.json": `{"login.title": "Sign in", "login.ghost": "Nothing"}`,
		"op/interaction/htmldriver.go": `package interaction

func heading() string { return "login.title" }
`,
	}
	root := writeTree(t, files)
	ix, err := buildIndex(root)
	if err != nil {
		t.Fatalf("buildIndex: %v", err)
	}
	findings, keys, err := checkMessages(root, ix, emptyAllowlist(t))
	if err != nil {
		t.Fatalf("checkMessages: %v", err)
	}
	if keys != 2 {
		t.Fatalf("seed key count = %d; want 2", keys)
	}
	wantIDs(t, findings, "login.ghost")
}

// The seed catalogue names every key it defines. Counting the bundle
// itself as a rendering site would clear every key at once.
func TestCheckMessages_DoesNotCountTheSeedBundleAsRendering(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"internal/i18n/embedded/en.json": `{"login.ghost": "Nothing"}`,
		"internal/i18n/bundle.go": `package i18n

func fallback() string { return "login.ghost" }
`,
	})
	ix, err := buildIndex(root)
	if err != nil {
		t.Fatalf("buildIndex: %v", err)
	}
	findings, _, err := checkMessages(root, ix, emptyAllowlist(t))
	if err != nil {
		t.Fatalf("checkMessages: %v", err)
	}
	wantIDs(t, findings, "login.ghost")
}

func TestCheckIndexes_ReportsAnIndexOnlyTheSchemaNames(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/storeadapter/dynamodb/schema.go": `package dynamodb

const (
	indexByGrant  = "by_grant"
	indexByHandle = "by_handle"
)

func tables() []string { return []string{indexByGrant, indexByHandle} }
`,
		"op/storeadapter/dynamodb/grants.go": `package dynamodb

func lookup() string { return indexByGrant }
`,
	})
	wantIDs(t, checkIndexes(ix, emptyAllowlist(t)), "by_handle")
}

func TestLoadAllowlist_RejectsARowWithoutAReason(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"api/unreached.txt": "symbol\top.Thing\t\n",
	})
	_, err := loadAllowlist(filepath.Join(root, "api", "unreached.txt"))
	if err == nil || !strings.Contains(err.Error(), "empty reason") {
		t.Fatalf("err = %v; want an empty-reason rejection", err)
	}
}

func TestLoadAllowlist_RejectsAnUnknownKind(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"api/unreached.txt": "widget\tthing\tbecause\n",
	})
	_, err := loadAllowlist(filepath.Join(root, "api", "unreached.txt"))
	if err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Fatalf("err = %v; want an unknown-kind rejection", err)
	}
}

// An allowlist nobody prunes becomes the residue it was added to
// prevent, so a row the tree has outgrown fails like any other finding.
func TestAllowlist_StaleRowIsAFinding(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"api/unreached.txt": "symbol\top.Deleted\tno longer declared anywhere\n",
	})
	al, err := loadAllowlist(filepath.Join(root, "api", "unreached.txt"))
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	ix := indexTree(t, map[string]string{"op/policy.go": "package op\n"})
	if got := checkSymbols(ix, al); len(got) != 0 {
		t.Fatalf("unexpected findings: %v", ids(got))
	}
	wantIDs(t, al.stale(), "op.Deleted")
}

// An empty index reports every row reachable, which is indistinguishable
// from a clean tree. The floors are what tell the two apart.
func TestScanCounts_RefusesToReportOnAnEmptyIndex(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		files  int
		counts scanCounts
		want   string
	}{
		{"no files", 0, scanCounts{}, "the walk is broken"},
		{"no symbols", minFiles, scanCounts{}, "public packages moved"},
		{"no events", minFiles, scanCounts{symbols: minSymbolCandidat}, "auditevent"},
		{
			"no messages", minFiles,
			scanCounts{symbols: minSymbolCandidat, events: minAuditEvents},
			"en.json",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.counts.assertScanReachedSources(&index{files: tc.files})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want one naming %q", err, tc.want)
			}
		})
	}
}
