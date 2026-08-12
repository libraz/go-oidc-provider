package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// advisoryFileName is the catalog-adjacent inventory paired with this
// subcommand. It lives next to <feature>.yaml files but is excluded
// from the FeatureFile loader (catalog.go skips `_*.yaml`).
const advisoryFileName = "_advisories.yaml"

// advisoryStatusCovered / Tracking / OutOfScope mirror the YAML enum.
const (
	advisoryStatusCovered    = "covered"
	advisoryStatusTracking   = "tracking"
	advisoryStatusOutOfScope = "out-of-scope"
)

// advisoryInventory is the on-disk shape of _advisories.yaml. The
// schema version pins forward-compatibility; bump it on incompatible
// changes.
type advisoryInventory struct {
	SchemaVersion int              `yaml:"schema_version"`
	Description   string           `yaml:"description,omitempty"`
	Advisories    []*advisoryEntry `yaml:"advisories"`
	byID          map[string]*advisoryEntry
}

// advisoryEntry mirrors one entry under advisories[].
type advisoryEntry struct {
	ID               string `yaml:"id"`
	Severity         string `yaml:"severity"`
	Source           string `yaml:"source"`
	Threat           string `yaml:"threat"`
	Status           string `yaml:"status"`
	Notes            string `yaml:"notes,omitempty"`
	OutOfScopeReason string `yaml:"out_of_scope_reason,omitempty"`
}

// advisoryHit is one occurrence of `// Tracks: <id>` (or a bare
// CVE-XXXX / GHSA-xxxx mention) in Go source. The same advisory may
// appear in multiple hits across files; the report dedups by ID and
// lists every (file, line, func) tuple.
type advisoryHit struct {
	ID   string
	File string // repo-relative
	Line int    // 1-indexed
	Func string // enclosing test/fuzz function name, "" when at file scope

	// Marked is true when the comment group carrying the ID also
	// carries the `Tracks` marker word. A bare mention in prose ("not
	// affected by CVE-X") is not a claim of coverage.
	Marked bool
	// Asserting is true when the enclosing function takes a
	// *testing.T / *testing.F / *testing.B parameter, i.e. the comment
	// sits somewhere that can fail. A doc comment on production code
	// cannot.
	Asserting bool
}

// Covers reports whether the hit is evidence that the advisory is
// actually exercised: an intentional marker at a site that can fail.
// Everything else is a mention, which the report still lists but which
// no longer satisfies `status: covered`.
func (h advisoryHit) Covers() bool { return h.Marked && h.Asserting }

// advisoryRegex matches CVE-YYYY-NNNN(NNN?) and GHSA-xxxx-xxxx-xxxx
// regardless of surrounding context. Comments often carry parenthetic
// asides that intermix multiple IDs on one line; we extract every
// match.
var advisoryRegex = regexp.MustCompile(
	`CVE-[0-9]{4}-[0-9]{4,8}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}`,
)

// trackMarkerRegex matches the marker word that turns a mention into a
// claim. The word is matched on its own rather than as "Tracks:" so a
// qualified header ("Tracks (parse-DoS class):") or an inline sentence
// ("Tracks CVE-... and the broader disclosure") counts the same.
var trackMarkerRegex = regexp.MustCompile(`\bTracks\b`)

// advisoryIDPattern is the exact CVE / GHSA shape an inventory entry
// must use as its ID.
var advisoryIDPattern = regexp.MustCompile(`^(CVE-[0-9]{4}-[0-9]{4,8}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$`)

// advisoryThreatPattern guards the threat-model reference every entry
// carries.
var advisoryThreatPattern = regexp.MustCompile(`^T-[0-9]+$`)

// loadAdvisoryInventory reads _advisories.yaml from dir and validates
// structural invariants the JSON schema cannot express (severity /
// status enums, threat pattern, out_of_scope_reason requirement).
func loadAdvisoryInventory(dir string) (*advisoryInventory, error) {
	path := filepath.Join(dir, advisoryFileName)
	inv, err := decodeAdvisoryInventory(path)
	if err != nil {
		return nil, err
	}

	var problems []string
	inv.byID = make(map[string]*advisoryEntry, len(inv.Advisories))
	for i, a := range inv.Advisories {
		where := fmt.Sprintf("%s advisories[%d] (%s)", path, i, a.ID)
		problems = append(problems, checkAdvisoryEntry(where, a)...)
		// IDs index the inventory and are what source comments cite, so
		// a duplicate would make one of the two entries unreachable.
		if prev, dup := inv.byID[a.ID]; dup {
			problems = append(problems, fmt.Sprintf("%s: duplicate id %q (first seen as severity=%s)", where, a.ID, prev.Severity))
		} else {
			inv.byID[a.ID] = a
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("advisory inventory invalid (%d issue(s)):\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	return inv, nil
}

// decodeAdvisoryInventory parses the inventory file and pins its schema
// version. Unknown keys are rejected so a typo cannot silently drop a
// field the gate reads.
func decodeAdvisoryInventory(path string) (*advisoryInventory, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is operator-controlled.
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var inv advisoryInventory
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&inv); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if inv.SchemaVersion != 1 {
		return nil, fmt.Errorf("%s: schema_version=%d, want 1", path, inv.SchemaVersion)
	}
	return &inv, nil
}

// checkAdvisoryEntry enforces every field-level invariant of one entry:
// the ID shape the source scanner matches on, the severity and status
// enums the dashboard buckets by, the threat reference that ties the
// entry to the threat model, a non-empty source so the claim is
// traceable, and the out_of_scope_reason coupling — declaring an
// advisory out of scope is the one way to drop it from the gate, so it
// always has to carry the reason that justifies the exclusion.
func checkAdvisoryEntry(where string, a *advisoryEntry) []string {
	var problems []string
	if !advisoryIDPattern.MatchString(a.ID) {
		problems = append(problems, fmt.Sprintf("%s: id %q does not match CVE-/GHSA- pattern", where, a.ID))
	}
	if a.Severity != "P0" && a.Severity != "P1" && a.Severity != "P2" {
		problems = append(problems, fmt.Sprintf("%s: severity %q must be P0|P1|P2", where, a.Severity))
	}
	if !advisoryThreatPattern.MatchString(a.Threat) {
		problems = append(problems, fmt.Sprintf("%s: threat %q must match T-[0-9]+", where, a.Threat))
	}
	if strings.TrimSpace(a.Source) == "" {
		problems = append(problems, where+": source MUST be non-empty")
	}
	return append(problems, checkAdvisoryStatus(where, a)...)
}

// checkAdvisoryStatus enforces the status enum and its coupling with
// out_of_scope_reason. A reason left behind on an entry that came back
// in scope would document an exclusion that no longer applies.
func checkAdvisoryStatus(where string, a *advisoryEntry) []string {
	var problems []string
	switch a.Status {
	case advisoryStatusCovered, advisoryStatusTracking, advisoryStatusOutOfScope:
	default:
		problems = append(problems, fmt.Sprintf("%s: status %q must be covered|tracking|out-of-scope", where, a.Status))
	}
	if a.Status == advisoryStatusOutOfScope && strings.TrimSpace(a.OutOfScopeReason) == "" {
		problems = append(problems, where+": status=out-of-scope requires out_of_scope_reason")
	}
	if a.Status != advisoryStatusOutOfScope && a.OutOfScopeReason != "" {
		problems = append(problems, where+": out_of_scope_reason is only valid when status=out-of-scope")
	}
	return problems
}

// scanSource walks each root recursively, parses every *.go file with
// go/parser (ParseComments), and emits one advisoryHit per (advisory ID,
// file:line) pair. The enclosing function name is the nearest *ast.FuncDecl
// such that funcDecl.Pos() <= comment.Pos() <= funcDecl.End(); top-of-file
// CommentGroups attached to a leading FuncDecl through *ast.FuncDecl.Doc are
// also matched. File-scope comments emit hits with Func="".
func scanSource(roots []string) ([]advisoryHit, error) {
	var hits []advisoryHit
	for _, root := range roots {
		rootHits, err := scanSourceRoot(root)
		if err != nil {
			return nil, err
		}
		hits = append(hits, rootHits...)
	}
	sortAdvisoryHits(hits)
	return hits, nil
}

// scanSourceRoot walks one root and collects the hits of every Go file
// under it.
func scanSourceRoot(root string) ([]advisoryHit, error) {
	var hits []advisoryHit
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		switch {
		case walkErr != nil:
			return walkErr
		case d.IsDir():
			if isUntaggedTree(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		case !strings.HasSuffix(path, ".go"):
			return nil
		}
		fhits, err := scanGoFile(path)
		if err != nil {
			return err
		}
		hits = append(hits, fhits...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}
	return hits, nil
}

// isUntaggedTree reports whether a directory holds vendored or
// generated code this repository never tags, and which would otherwise
// contribute advisory mentions nobody here wrote.
func isUntaggedTree(name string) bool {
	switch name {
	case "vendor", "testdata", ".git", "node_modules":
		return true
	}
	return false
}

// sortAdvisoryHits orders hits by ID, then file, then line, so the
// report and the JSON output are stable across runs.
func sortAdvisoryHits(hits []advisoryHit) {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].ID != hits[j].ID {
			return hits[i].ID < hits[j].ID
		}
		if hits[i].File != hits[j].File {
			return hits[i].File < hits[j].File
		}
		return hits[i].Line < hits[j].Line
	})
}

// scanGoFile parses one Go file and returns every advisoryHit found in
// its comments. Function attribution uses position containment: a
// comment whose Pos is between funcDecl.Pos() (or its leading Doc.Pos
// when present) and funcDecl.End() inclusive belongs to that func.
//
// Each hit also records whether it is a claim of coverage rather than a
// passing mention: the marker word is looked for across the whole
// comment group (a `Tracks:` header followed by an indented list of IDs
// is one group, so every ID under it inherits the marker), and the
// enclosing function is checked for a testing parameter.
func scanGoFile(path string) ([]advisoryHit, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	ranges := collectFuncRanges(file)

	var out []advisoryHit
	for _, cg := range file.Comments {
		// The marker is looked for across the whole group, so a
		// `Tracks:` header followed by an indented list of IDs marks
		// every ID under it.
		marked := trackMarkerRegex.MatchString(cg.Text())
		for _, c := range cg.List {
			fn, asserting := ranges.enclosing(c.Pos())
			out = append(out, advisoryHitsInComment(c.Text, advisoryHit{
				File:      path,
				Line:      fset.Position(c.Pos()).Line,
				Func:      fn,
				Marked:    marked,
				Asserting: asserting,
			})...)
		}
	}
	return out, nil
}

// funcRange is the source span of one function declaration, widened to
// include its leading doc comment so a `Tracks:` header written above
// the func is attributed to it.
type funcRange struct {
	name       string
	start, end token.Pos
	asserting  bool
}

// funcRanges is every function span in one file, in declaration order.
type funcRanges []funcRange

// collectFuncRanges records the span of every function declared in the
// file together with whether it can fail.
func collectFuncRanges(file *ast.File) funcRanges {
	var ranges funcRanges
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		start := fd.Pos()
		if fd.Doc != nil {
			start = fd.Doc.Pos()
		}
		ranges = append(ranges, funcRange{
			name:      fd.Name.Name,
			start:     start,
			end:       fd.End(),
			asserting: takesTestingParam(fd),
		})
	}
	return ranges
}

// enclosing returns the name of the function containing pos and whether
// that function can fail. A comment outside every function is at file
// scope and reports "" — the shape a doc comment on a package or a
// const block has.
func (rs funcRanges) enclosing(pos token.Pos) (name string, asserting bool) {
	for _, r := range rs {
		if pos >= r.start && pos <= r.end {
			return r.name, r.asserting
		}
	}
	return "", false
}

// advisoryHitsInComment extracts every distinct advisory ID from one
// comment, stamping each onto a copy of proto. IDs are deduped within
// the comment so a line that cites the same advisory three times for
// emphasis is still one hit.
func advisoryHitsInComment(text string, proto advisoryHit) []advisoryHit {
	var out []advisoryHit
	seen := map[string]bool{}
	for _, m := range advisoryRegex.FindAllString(text, -1) {
		if seen[m] {
			continue
		}
		seen[m] = true
		hit := proto
		hit.ID = m
		out = append(out, hit)
	}
	return out
}

// takesTestingParam reports whether fd accepts a *testing.T, *testing.F
// or *testing.B. That is the property the gate needs: it distinguishes a
// site that can fail the build from a doc comment on production code.
// Checking the parameter rather than a Test/Fuzz name prefix keeps
// shared assertion helpers — the exported store-contract suites, for one
// — counting as coverage.
func takesTestingParam(fd *ast.FuncDecl) bool {
	if fd.Type.Params == nil {
		return false
	}
	for _, field := range fd.Type.Params.List {
		star, ok := field.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "testing" {
			continue
		}
		switch sel.Sel.Name {
		case "T", "F", "B":
			return true
		}
	}
	return false
}

// runAdvisories is the entry point for the `advisories` subcommand. It
// loads the inventory, scans the source roots, and either prints the
// human-readable report or emits JSON to out. When check is true, drift
// / orphan / mis-status problems exit non-zero.
func runAdvisories(out io.Writer, catalogDir, cwd string, sourceRoots []string, check, asJSON bool) error {
	inv, err := loadAdvisoryInventory(catalogDir)
	if err != nil {
		return err
	}
	scanRoots := make([]string, len(sourceRoots))
	for i, r := range sourceRoots {
		scanRoots[i] = filepath.Join(cwd, r)
	}
	hits, err := scanSource(scanRoots)
	if err != nil {
		return err
	}
	hitsByID := bucketHitsByID(hits, cwd)

	problems := advisoryStatusDrift(inv, hitsByID)
	problems = append(problems, advisoryOrphans(inv, hitsByID)...)
	sort.Strings(problems)

	if asJSON {
		return emitAdvisoriesJSON(out, inv, hitsByID, problems)
	}
	emitAdvisoriesText(out, inv, hitsByID, problems)
	if check && len(problems) > 0 {
		return &exitError{code: 1, message: fmt.Sprintf(
			"scenariotool: advisories gate failed (%d issue(s))", len(problems),
		)}
	}
	return nil
}

// bucketHitsByID groups hits by advisory ID, rewriting each file path
// relative to cwd so the report stays readable.
func bucketHitsByID(hits []advisoryHit, cwd string) map[string][]advisoryHit {
	hitsByID := map[string][]advisoryHit{}
	for _, h := range hits {
		if cwd != "" {
			if rel, err := filepath.Rel(cwd, h.File); err == nil {
				h.File = rel
			}
		}
		hitsByID[h.ID] = append(hitsByID[h.ID], h)
	}
	return hitsByID
}

// advisoryStatusDrift reports entries whose declared status disagrees
// with what the source actually shows. `covered` has to be backed by a
// marker at a site that can fail, and `tracking` has to not be — an
// entry left at tracking after the test landed understates the coverage
// the repository has, which is how a real gap gets lost in the noise.
// out-of-scope entries carry no drift check beyond the
// out_of_scope_reason the loader already enforces.
func advisoryStatusDrift(inv *advisoryInventory, hitsByID map[string][]advisoryHit) []string {
	var problems []string
	for _, a := range inv.Advisories {
		covering := coveringHits(hitsByID[a.ID])
		switch a.Status {
		case advisoryStatusCovered:
			if len(covering) == 0 {
				problems = append(problems, describeUncovered(a.ID, hitsByID[a.ID]))
			}
		case advisoryStatusTracking:
			if len(covering) > 0 {
				problems = append(problems, fmt.Sprintf(
					"%s: status=tracking but found %d `Tracks:` reference(s) in a test — flip status to covered (first hit: %s:%d %s)",
					a.ID, len(covering), covering[0].File, covering[0].Line, covering[0].Func,
				))
			}
		case advisoryStatusOutOfScope:
		}
	}
	return problems
}

// advisoryOrphans reports source that claims to track an ID the
// inventory does not list. Only marked hits count — an unrelated
// advisory named in passing prose is not a claim that this repository
// tracks it.
func advisoryOrphans(inv *advisoryInventory, hitsByID map[string][]advisoryHit) []string {
	var problems []string
	for id, hs := range hitsByID {
		if _, ok := inv.byID[id]; ok {
			continue
		}
		marked := markedHits(hs)
		if len(marked) == 0 {
			continue
		}
		problems = append(problems, fmt.Sprintf(
			"%s: orphan — `// Tracks: %s` at %s:%d but no entry in %s",
			id, id, marked[0].File, marked[0].Line, advisoryFileName,
		))
	}
	return problems
}

// coveringHits narrows hits to the ones that satisfy `status: covered`.
func coveringHits(hs []advisoryHit) []advisoryHit {
	var out []advisoryHit
	for _, h := range hs {
		if h.Covers() {
			out = append(out, h)
		}
	}
	return out
}

// markedHits narrows hits to the ones carrying the marker word,
// regardless of where they sit.
func markedHits(hs []advisoryHit) []advisoryHit {
	var out []advisoryHit
	for _, h := range hs {
		if h.Marked {
			out = append(out, h)
		}
	}
	return out
}

// describeUncovered explains why a `covered` entry has no coverage. The
// three causes need different fixes, and a message that named only the
// first would send the reader looking for a comment that is already
// there.
func describeUncovered(id string, hs []advisoryHit) string {
	switch marked := markedHits(hs); {
	case len(hs) == 0:
		return fmt.Sprintf(
			"%s: status=covered but no `// Tracks: %s` found in source", id, id,
		)
	case len(marked) == 0:
		return fmt.Sprintf(
			"%s: status=covered but the %d mention(s) of it carry no `Tracks` marker — a passing reference is not coverage (first: %s:%d)",
			id, len(hs), hs[0].File, hs[0].Line,
		)
	default:
		where := marked[0].Func
		if where == "" {
			where = "file scope"
		}
		return fmt.Sprintf(
			"%s: status=covered but every `Tracks` marker sits outside a test — %s:%d is in %s, which takes no *testing.T/F/B, so nothing can fail",
			id, marked[0].File, marked[0].Line, where,
		)
	}
}

// emitAdvisoriesText prints the human-readable dashboard.
func emitAdvisoriesText(out io.Writer, inv *advisoryInventory, hitsByID map[string][]advisoryHit, problems []string) {
	covered, tracking, oos := countAdvisoryStatuses(inv)
	_, _ = fmt.Fprintf(out, "scenariotool advisories: %d total (covered %d, tracking %d, out-of-scope %d)\n",
		len(inv.Advisories), covered, tracking, oos)

	byStatus := map[string][]*advisoryEntry{}
	for _, a := range inv.Advisories {
		byStatus[a.Status] = append(byStatus[a.Status], a)
	}
	for _, st := range []string{advisoryStatusCovered, advisoryStatusTracking, advisoryStatusOutOfScope} {
		entries := byStatus[st]
		if len(entries) == 0 {
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
		_, _ = fmt.Fprintf(out, "\n# %s (%d)\n", st, len(entries))
		for _, a := range entries {
			_, _ = fmt.Fprintf(out, "  %s [%s] %s\n", a.ID, a.Severity, a.Threat)
			printAdvisoryHits(out, hitsByID[a.ID])
		}
	}
	if len(problems) > 0 {
		_, _ = fmt.Fprintf(out, "\n# drift / orphans (%d)\n", len(problems))
		for _, p := range problems {
			_, _ = fmt.Fprintf(out, "  %s\n", p)
		}
	}
}

// countAdvisoryStatuses tallies the inventory by status for the
// dashboard header.
func countAdvisoryStatuses(inv *advisoryInventory) (covered, tracking, oos int) {
	for _, a := range inv.Advisories {
		switch a.Status {
		case advisoryStatusCovered:
			covered++
		case advisoryStatusTracking:
			tracking++
		case advisoryStatusOutOfScope:
			oos++
		}
	}
	return covered, tracking, oos
}

// printAdvisoryHits lists where one entry is cited. The "(mention)"
// suffix is the whole point of the listing: a hit with no marker, or
// one outside a test, is why an entry can be cited everywhere and
// covered nowhere.
func printAdvisoryHits(out io.Writer, hits []advisoryHit) {
	for _, h := range hits {
		note := ""
		if !h.Covers() {
			note = "  (mention)"
		}
		if h.Func != "" {
			_, _ = fmt.Fprintf(out, "      %s:%d  %s%s\n", h.File, h.Line, h.Func, note)
		} else {
			_, _ = fmt.Fprintf(out, "      %s:%d%s\n", h.File, h.Line, note)
		}
	}
}

// emitAdvisoriesJSON emits a stable shape suitable for CI parsing.
func emitAdvisoriesJSON(out io.Writer, inv *advisoryInventory, hitsByID map[string][]advisoryHit, problems []string) error {
	type hitDTO struct {
		File string `json:"file"`
		Line int    `json:"line"`
		Func string `json:"func,omitempty"`
		// Covers separates evidence from mention so CI consumers can
		// count coverage without re-deriving the rule.
		Covers bool `json:"covers"`
	}
	type entryDTO struct {
		ID       string   `json:"id"`
		Severity string   `json:"severity"`
		Threat   string   `json:"threat"`
		Status   string   `json:"status"`
		Source   string   `json:"source"`
		Hits     []hitDTO `json:"hits"`
	}
	doc := struct {
		Total    int        `json:"total"`
		Entries  []entryDTO `json:"entries"`
		Problems []string   `json:"problems"`
	}{
		Total:    len(inv.Advisories),
		Problems: problems,
	}
	for _, a := range inv.Advisories {
		e := entryDTO{ID: a.ID, Severity: a.Severity, Threat: a.Threat, Status: a.Status, Source: a.Source}
		for _, h := range hitsByID[a.ID] {
			e.Hits = append(e.Hits, hitDTO{File: h.File, Line: h.Line, Func: h.Func, Covers: h.Covers()})
		}
		doc.Entries = append(doc.Entries, e)
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
