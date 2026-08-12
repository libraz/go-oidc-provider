package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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

// loadAdvisoryInventory reads _advisories.yaml from dir and validates
// structural invariants the JSON schema cannot express (severity /
// status enums, threat pattern, out_of_scope_reason requirement).
func loadAdvisoryInventory(dir string) (*advisoryInventory, error) {
	path := filepath.Join(dir, advisoryFileName)
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
	inv.byID = make(map[string]*advisoryEntry, len(inv.Advisories))
	var problems []string
	idPattern := regexp.MustCompile(`^(CVE-[0-9]{4}-[0-9]{4,8}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$`)
	threatPattern := regexp.MustCompile(`^T-[0-9]+$`)
	for i, a := range inv.Advisories {
		where := fmt.Sprintf("%s advisories[%d] (%s)", path, i, a.ID)
		if !idPattern.MatchString(a.ID) {
			problems = append(problems, fmt.Sprintf("%s: id %q does not match CVE-/GHSA- pattern", where, a.ID))
		}
		if a.Severity != "P0" && a.Severity != "P1" && a.Severity != "P2" {
			problems = append(problems, fmt.Sprintf("%s: severity %q must be P0|P1|P2", where, a.Severity))
		}
		if !threatPattern.MatchString(a.Threat) {
			problems = append(problems, fmt.Sprintf("%s: threat %q must match T-[0-9]+", where, a.Threat))
		}
		switch a.Status {
		case advisoryStatusCovered, advisoryStatusTracking, advisoryStatusOutOfScope:
		default:
			problems = append(problems, fmt.Sprintf("%s: status %q must be covered|tracking|out-of-scope", where, a.Status))
		}
		if a.Status == advisoryStatusOutOfScope && strings.TrimSpace(a.OutOfScopeReason) == "" {
			problems = append(problems, fmt.Sprintf("%s: status=out-of-scope requires out_of_scope_reason", where))
		}
		if a.Status != advisoryStatusOutOfScope && a.OutOfScopeReason != "" {
			problems = append(problems, fmt.Sprintf("%s: out_of_scope_reason is only valid when status=out-of-scope", where))
		}
		if strings.TrimSpace(a.Source) == "" {
			problems = append(problems, fmt.Sprintf("%s: source MUST be non-empty", where))
		}
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
	return &inv, nil
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
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				name := d.Name()
				// Skip vendored and generated trees that we never tag.
				if name == "vendor" || name == "testdata" || name == ".git" || name == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
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
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].ID != hits[j].ID {
			return hits[i].ID < hits[j].ID
		}
		if hits[i].File != hits[j].File {
			return hits[i].File < hits[j].File
		}
		return hits[i].Line < hits[j].Line
	})
	return hits, nil
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
	type funcRange struct {
		name       string
		start, end token.Pos
		asserting  bool
	}
	var ranges []funcRange
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
	enclosing := func(pos token.Pos) (string, bool) {
		for _, r := range ranges {
			if pos >= r.start && pos <= r.end {
				return r.name, r.asserting
			}
		}
		return "", false
	}
	var out []advisoryHit
	for _, cg := range file.Comments {
		marked := trackMarkerRegex.MatchString(cg.Text())
		for _, c := range cg.List {
			matches := advisoryRegex.FindAllString(c.Text, -1)
			if len(matches) == 0 {
				continue
			}
			line := fset.Position(c.Pos()).Line
			fn, asserting := enclosing(c.Pos())
			seen := map[string]bool{}
			for _, m := range matches {
				if seen[m] {
					continue // dedupe within the same comment line
				}
				seen[m] = true
				out = append(out, advisoryHit{
					ID: m, File: path, Line: line, Func: fn,
					Marked: marked, Asserting: asserting,
				})
			}
		}
	}
	return out, nil
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
// human-readable report or emits JSON. When check is true, drift /
// orphan / mis-status problems exit non-zero.
func runAdvisories(catalogDir, cwd string, sourceRoots []string, check, asJSON bool) error {
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
	// Bucket hits by ID, with relative paths for readable output.
	hitsByID := map[string][]advisoryHit{}
	for _, h := range hits {
		rel := h.File
		if cwd != "" {
			if r, err := filepath.Rel(cwd, h.File); err == nil {
				rel = r
			}
		}
		h.File = rel
		hitsByID[h.ID] = append(hitsByID[h.ID], h)
	}

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
			// Tags allowed but optional — no drift check beyond the
			// out_of_scope_reason which the loader already enforces.
		}
	}
	// Orphan detection: source claims to track an ID the inventory does
	// not list. Only marked hits count — an unrelated advisory named in
	// passing prose is not a claim that this repository tracks it.
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
	sort.Strings(problems)

	if asJSON {
		return emitAdvisoriesJSON(inv, hitsByID, problems)
	}
	emitAdvisoriesText(inv, hitsByID, problems)
	if check && len(problems) > 0 {
		return &exitError{code: 1, message: fmt.Sprintf(
			"scenariotool: advisories gate failed (%d issue(s))", len(problems),
		)}
	}
	return nil
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
func emitAdvisoriesText(inv *advisoryInventory, hitsByID map[string][]advisoryHit, problems []string) {
	var covered, tracking, oos int
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
	fmt.Printf("scenariotool advisories: %d total (covered %d, tracking %d, out-of-scope %d)\n",
		len(inv.Advisories), covered, tracking, oos)

	// Group by status for the dashboard.
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
		fmt.Printf("\n# %s (%d)\n", st, len(entries))
		for _, a := range entries {
			fmt.Printf("  %s [%s] %s\n", a.ID, a.Severity, a.Threat)
			for _, h := range hitsByID[a.ID] {
				// The suffix is the whole point of the listing: a hit
				// with no marker, or one outside a test, is why an
				// entry can be cited everywhere and covered nowhere.
				note := ""
				if !h.Covers() {
					note = "  (mention)"
				}
				if h.Func != "" {
					fmt.Printf("      %s:%d  %s%s\n", h.File, h.Line, h.Func, note)
				} else {
					fmt.Printf("      %s:%d%s\n", h.File, h.Line, note)
				}
			}
		}
	}
	if len(problems) > 0 {
		fmt.Printf("\n# drift / orphans (%d)\n", len(problems))
		for _, p := range problems {
			fmt.Printf("  %s\n", p)
		}
	}
}

// emitAdvisoriesJSON emits a stable shape suitable for CI parsing.
func emitAdvisoriesJSON(inv *advisoryInventory, hitsByID map[string][]advisoryHit, problems []string) error {
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
	out := struct {
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
		out.Entries = append(out.Entries, e)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
