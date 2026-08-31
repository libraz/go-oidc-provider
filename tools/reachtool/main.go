// Command reachtool fails the build on vocabulary this repository
// declares and nothing reaches.
//
// Four kinds of declaration go stale silently, because no compiler and
// no linter has an opinion about any of them:
//
//   - an exported constant or sentinel error in a public package that
//     no code path ever produces or consults;
//   - a catalogued audit event whose godoc lets an operator believe the
//     OP emits it when no handler does;
//   - a seeded message key no surface renders;
//   - a DynamoDB secondary index the schema provisions and no read
//     path queries.
//
// Each one reads, from the outside, exactly like a working feature. An
// embedder writing `errors.Is(err, op.ErrSomething)` gets a branch that
// compiles, runs, and is never taken; an operator alerting on the
// absence of an audit event gets silence and concludes the situation
// did not arise. The declaration is a claim about behaviour, and
// nothing about it changes when the behaviour goes away.
//
// The gate is deliberately source-only: it parses rather than builds,
// so it keeps answering while an unrelated package is mid-edit, and it
// counts uses in library code only — a demo naming a symbol shows the
// name exists, not that the OP ever produces the value.
//
// Deliberate exceptions live in the allowlist, one row each with the
// reason nothing reading the entry is the correct state. A row that
// stops applying fails too: an allowlist nobody prunes becomes the same
// residue it was added to prevent.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// Floors below which a clean report means the scan is broken rather
// than the tree being clean. Every check resolves against an index that
// could be empty — a moved package, a wrong root, a walk that descended
// into nothing — and an empty index reports every row reachable.
const (
	minFiles          = 200
	minSymbolCandidat = 20
	minAuditEvents    = 50
	minMessageKeys    = 10
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "reachtool: %v\n", err)
		os.Exit(1)
	}
}

// run executes the gate and returns a non-nil error when the tree has
// findings, so the caller's exit status is the gate's verdict.
func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("reachtool", flag.ContinueOnError)
	fs.SetOutput(out)
	root := fs.String("root", ".", "repository root to scan")
	allowPath := fs.String("allowlist", "", "allowlist file (default <root>/api/unreached.txt)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		return fmt.Errorf("resolve root: %w", err)
	}
	if *allowPath == "" {
		*allowPath = filepath.Join(absRoot, "api", "unreached.txt")
	}

	ix, err := buildIndex(absRoot)
	if err != nil {
		return err
	}
	al, err := loadAllowlist(*allowPath)
	if err != nil {
		return err
	}

	findings, counts, err := checkAll(absRoot, ix, al)
	if err != nil {
		return err
	}
	if err := counts.assertScanReachedSources(ix); err != nil {
		return err
	}
	findings = append(findings, al.stale()...)

	_, _ = fmt.Fprintf(out, "reachtool: %d files, %d public symbols, %d audit events, %d message keys, %d indexes\n",
		ix.files, counts.symbols, counts.events, counts.messages, counts.indexes)
	if len(findings) == 0 {
		_, _ = fmt.Fprintf(out, "reachtool: OK (%d allowlisted)\n", len(al.rows))
		return nil
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].kind != findings[j].kind {
			return findings[i].kind < findings[j].kind
		}
		return findings[i].id < findings[j].id
	})
	for _, f := range findings {
		_, _ = fmt.Fprintf(out, "  - %s\n", f)
	}
	return fmt.Errorf("%d declared-but-unreached findings", len(findings))
}

// scanCounts records how much each check had to look at, so a clean
// report can be told apart from a scan that found nothing to report on.
type scanCounts struct {
	symbols  int
	events   int
	messages int
	indexes  int
}

// checkAll runs every check and returns their findings and sizes.
func checkAll(root string, ix *index, al *allowlist) ([]finding, scanCounts, error) {
	var counts scanCounts
	findings := checkSymbols(ix, al)
	for _, d := range ix.decls {
		if publicPkg(d.pkg) && isExported(d.name) && symbolCandidate(d) {
			counts.symbols++
		}
	}

	findings = append(findings, checkEvents(ix, al)...)
	for _, d := range ix.declsIn(auditEventPkg) {
		if d.kind == kindConst && d.typeName == "Name" && d.str != "" {
			counts.events++
		}
	}

	messages, keys, err := checkMessages(root, ix, al)
	if err != nil {
		return nil, counts, err
	}
	counts.messages = keys
	findings = append(findings, messages...)

	findings = append(findings, checkIndexes(ix, al)...)
	for _, d := range ix.declsIn(dynamoPkg) {
		if d.kind == kindConst && d.str != "" && len(d.name) > len("index") && d.name[:len("index")] == "index" {
			counts.indexes++
		}
	}
	return findings, counts, nil
}

// assertScanReachedSources refuses to report a clean tree when the
// index behind the report is too small to have checked anything.
func (c scanCounts) assertScanReachedSources(ix *index) error {
	switch {
	case ix.files < minFiles:
		return fmt.Errorf("scan parsed %d Go files (want at least %d): the walk is broken, not the tree", ix.files, minFiles)
	case c.symbols < minSymbolCandidat:
		return fmt.Errorf("scan found %d public constants and sentinels (want at least %d): "+
			"the public packages moved or were not walked", c.symbols, minSymbolCandidat)
	case c.events < minAuditEvents:
		return fmt.Errorf("scan found %d catalogued audit events (want at least %d): %s did not resolve",
			c.events, minAuditEvents, auditEventPkg)
	case c.messages < minMessageKeys:
		return fmt.Errorf("scan found %d seed message keys (want at least %d): %s did not resolve",
			c.messages, minMessageKeys, messagesFile)
	default:
		return nil
	}
}
