// Command stabilitytool enumerates the public API that carries a stability
// marker, and pins each enumeration to a checked-in report.
//
// The op package documents two markers. An API whose godoc starts with
// "Experimental:" may change without a major bump, which makes the marked
// set the exemption list and everything else implicitly stable. An API whose
// godoc starts with "Stable since vX.Y" names the release its contract was
// frozen in. Both are prose, so both drift silently unless something derives
// them from the source and compares them against a report; -kind selects
// which of the two this run handles.
//
// The two reports differ in what a diff means. The experimental report is a
// snapshot: a marker that appears, moves, or disappears is a reviewable
// change. The stable report is history. A recorded version describes a
// release that already shipped, so a row may be added but the version in an
// existing row must never be rewritten — the godoc would then be making a
// claim about a published release that the published release does not
// support. That asymmetry is enforced, not documented: adding a row is
// sometimes right and -allow-backfill exists for it, changing a recorded
// version never is and has no escape hatch.
//
// Usage:
//
//	stabilitytool -root <dir> -module <path>                    # print the report
//	stabilitytool -root <dir> -module <path> -write f           # regenerate f
//	stabilitytool -root <dir> -module <path> -check f           # fail on drift
//	stabilitytool ... -kind stable                              # the "Stable since" report
//	stabilitytool ... -kind stable -write f -allow-backfill     # admit a late marker
package main

import (
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// experimentalMarker introduces the rationale for an exemption. The convention
// is documented in op/doc.go.
const experimentalMarker = "Experimental:"

// stableMarker introduces the release a contract was frozen in ("Stable since
// v0.9"). A symbol carrying both markers is contradictory and is reported as
// an error by either kind of scan.
const stableMarker = "Stable since"

// packageSymbol stands for "every symbol in this package" and is emitted
// when the marker sits on the package doc rather than on a declaration.
// A package-scoped marker cannot name a subset, so neither can the
// report; the godoc that carries the marker is where the scope is
// argued. Sorting puts the row ahead of that package's symbol rows.
const packageSymbol = "*"

// reportKind selects which marker a run enumerates. The two scans share the
// walk, the symbol naming, and the drift check, and differ only in which
// marker classify looks for and in what a row records.
type reportKind string

const (
	kindExperimental reportKind = "experimental"
	kindStable       reportKind = "stable"
)

// marker is the doc-comment prefix this kind enumerates.
func (k reportKind) marker() string {
	if k == kindStable {
		return stableMarker
	}
	return experimentalMarker
}

// other is the marker whose presence on the same symbol is a contradiction.
func (k reportKind) other() string {
	if k == kindStable {
		return experimentalMarker
	}
	return stableMarker
}

// entry is one marked symbol. Version carries the vMAJOR.MINOR from a
// "Stable since" marker and is empty for the experimental kind.
type entry struct {
	ImportPath string
	Symbol     string
	Version    string
}

func main() {
	var (
		root     = flag.String("root", "op", "directory tree to scan, relative to the working directory")
		module   = flag.String("module", "", "module path that -root maps onto (required)")
		kindArg  = flag.String("kind", string(kindExperimental), "which marker to report: experimental or stable")
		write    = flag.String("write", "", "regenerate the report at this path")
		checkArg = flag.String("check", "", "compare against the report at this path and exit non-zero on drift")
		backfill = flag.Bool("allow-backfill", false,
			"stable only: allow a new row to claim a version the report already enumerates, "+
				"for a symbol that genuinely shipped in that release without a marker. "+
				"There is no counterpart for rewriting the version of a row that is already "+
				"recorded: adding a row is sometimes right, changing a recorded one never is")
	)
	flag.Parse()

	if err := run(config{
		root:          *root,
		module:        *module,
		kind:          reportKind(*kindArg),
		write:         *write,
		check:         *checkArg,
		allowBackfill: *backfill,
		out:           os.Stdout,
	}); err != nil {
		fail(err)
	}
}

// config is the parsed command line. main is a thin shell around run so the
// mode logic — and in particular the rule that -write is gated by the same
// invariants as -check — is reachable from a test rather than only from a
// built binary.
type config struct {
	root          string
	module        string
	kind          reportKind
	write         string
	check         string
	allowBackfill bool
	out           io.Writer
}

func run(cfg config) error {
	if cfg.module == "" {
		return errors.New("-module is required")
	}
	if cfg.kind != kindExperimental && cfg.kind != kindStable {
		return fmt.Errorf("-kind %q: want %q or %q", cfg.kind, kindExperimental, kindStable)
	}
	if cfg.allowBackfill && cfg.kind != kindStable {
		return fmt.Errorf("-allow-backfill applies to -kind %s only", kindStable)
	}

	entries, err := scan(cfg.root, cfg.module, cfg.kind)
	if err != nil {
		return err
	}
	report := render(cfg.kind, entries)

	// The history invariants are checked against whichever report this run
	// is about to write or compare, so -write cannot launder a rewritten
	// version into the baseline that the next -check would then accept.
	if cfg.kind == kindStable {
		baseline := cfg.write
		if baseline == "" {
			baseline = cfg.check
		}
		if baseline != "" {
			if err := checkHistory(baseline, entries, cfg.allowBackfill); err != nil {
				return err
			}
		}
	}

	switch {
	case cfg.write != "":
		// The report is a generated artefact in the working tree; git
		// records only the exec bit, so nothing downstream depends on
		// the group / other bits being set.
		return os.WriteFile(cfg.write, []byte(report), 0o600)
	case cfg.check != "":
		return check(cfg.check, report, cfg.kind)
	default:
		_, err := io.WriteString(cfg.out, report)
		return err
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "stabilitytool:", err)
	os.Exit(1)
}

// check compares the freshly derived report against the checked-in one and
// describes the drift in terms of symbols rather than diff hunks, so the
// failure names what to do about it.
func check(path, report string, kind reportKind) error {
	recorded, err := os.ReadFile(path) //nolint:gosec // path is an operator-supplied build-tool flag.
	if err != nil {
		return err
	}
	if string(recorded) == report {
		return nil
	}
	added, removed := diff(parseReport(string(recorded)), parseReport(report))
	var b strings.Builder
	fmt.Fprintf(&b, "%s is out of date\n", path)
	for _, s := range added {
		fmt.Fprintf(&b, "  + %s\n", s)
	}
	for _, s := range removed {
		fmt.Fprintf(&b, "  - %s\n", s)
	}
	if kind == kindStable {
		b.WriteString("the marked-stable surface changed; run 'make stability' and " +
			"confirm the new rows name the release being prepared")
	} else {
		b.WriteString("the experimental surface changed; run 'make stability' and " +
			"confirm the change belongs in the release notes")
	}
	return errors.New(b.String())
}

// checkHistory enforces the two invariants that make the stable report a
// record rather than a snapshot. Both are answerable from the checked-in
// baseline alone, so neither needs a git tag or a version flag.
//
// A: a version already recorded for a symbol is never rewritten. The godoc
// would otherwise claim a contract for a release that shipped without it,
// and nothing downstream can tell the two apart.
//
// B: a symbol absent from the baseline may not claim a version the baseline
// already enumerates. The baseline is the marked surface of that release, so
// a symbol missing from it was not marked in it. Retroactively marking a
// symbol that genuinely shipped unmarked is legitimate — the convention is
// sparse and most exported symbols carry no marker — which is what
// allowBackfill is for. There is no equivalent for A.
//
// A missing baseline is not an error: the first write of a report has
// nothing to contradict.
func checkHistory(path string, entries []entry, allowBackfill bool) error {
	recorded, err := os.ReadFile(path) //nolint:gosec // path is an operator-supplied build-tool flag.
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	base := readBaseline(string(recorded))
	rewritten, unshipped := historyViolations(base, entries, allowBackfill)
	if len(rewritten) == 0 && len(unshipped) == 0 {
		return nil
	}
	return errors.New(historyReport(path, rewritten, unshipped))
}

// baseline is the checked-in report read back as the two questions the
// invariants ask of it: what version did we record for this symbol, and
// which versions has the report enumerated at all.
type baseline struct {
	version    map[string]string
	enumerated map[string]bool
}

func readBaseline(recorded string) baseline {
	b := baseline{version: map[string]string{}, enumerated: map[string]bool{}}
	for _, row := range parseReport(recorded) {
		importPath, symbol, version, ok := parseRow(row)
		if !ok {
			continue
		}
		b.version[importPath+"\t"+symbol] = version
		b.enumerated[version] = true
	}
	return b
}

// historyViolations splits the offending symbols by invariant so the
// report can explain each with its own remedy. A symbol can only offend
// one of the two: A applies to rows the baseline knows, B to rows it
// does not.
func historyViolations(base baseline, entries []entry, allowBackfill bool) (rewritten, unshipped []string) {
	for _, e := range entries {
		was, known := base.version[e.ImportPath+"\t"+e.Symbol]
		switch {
		case known && was != e.Version:
			rewritten = append(rewritten, fmt.Sprintf("%s\t%s: recorded %s, godoc now says %s",
				e.ImportPath, e.Symbol, was, e.Version))
		case !known && !allowBackfill && base.enumerated[e.Version]:
			unshipped = append(unshipped, fmt.Sprintf("%s\t%s: claims %s, which the report already enumerates",
				e.ImportPath, e.Symbol, e.Version))
		}
	}
	return rewritten, unshipped
}

func historyReport(path string, rewritten, unshipped []string) string {
	var b strings.Builder
	if len(rewritten) > 0 {
		fmt.Fprintf(&b, "%s records a different version for these symbols:\n", path)
		for _, s := range rewritten {
			fmt.Fprintf(&b, "  %s\n", s)
		}
		b.WriteString("a recorded \"Stable since\" describes a release that already shipped; " +
			"restore the recorded version in the godoc rather than the report")
	}
	if len(unshipped) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s does not list these symbols under the version they claim:\n", path)
		for _, s := range unshipped {
			fmt.Fprintf(&b, "  %s\n", s)
		}
		b.WriteString("the report enumerates what each release marked, so a symbol missing from " +
			"one was not marked in it; name the release being prepared, or pass -allow-backfill " +
			"when the symbol genuinely shipped in that release without a marker")
	}
	return b.String()
}

// parseReport returns the symbol lines of a report, ignoring the comment
// header so the header can be reworded without looking like drift.
func parseReport(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// parseRow splits a stable report row back into its columns.
func parseRow(line string) (importPath, symbol, version string, ok bool) {
	parts := strings.Split(line, "\t")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func diff(old, current []string) (added, removed []string) {
	inOld := make(map[string]bool, len(old))
	for _, s := range old {
		inOld[s] = true
	}
	inCurrent := make(map[string]bool, len(current))
	for _, s := range current {
		inCurrent[s] = true
	}
	for _, s := range current {
		if !inOld[s] {
			added = append(added, s)
		}
	}
	for _, s := range old {
		if !inCurrent[s] {
			removed = append(removed, s)
		}
	}
	return added, removed
}

func render(kind reportKind, entries []entry) string {
	var b strings.Builder
	if kind == kindStable {
		b.WriteString("# Public API that names the release its contract was frozen in.\n")
		b.WriteString("# Every row carries a \"Stable since vX.Y\" godoc marker; the third\n")
		b.WriteString("# column is that version. Absence from this report means the symbol\n")
		b.WriteString("# carries no marker, not that it is unstable.\n")
		b.WriteString("# A \"*\" symbol means the marker is on the package doc: the package\n")
		b.WriteString("# has existed since that release. A later row for a symbol in the\n")
		b.WriteString("# same package names when that symbol arrived, and does not\n")
		b.WriteString("# contradict it.\n")
		b.WriteString("# This file is a record, not a snapshot: a row may be added, but the\n")
		b.WriteString("# version of an existing row is never rewritten, because it describes\n")
		b.WriteString("# a release that already shipped.\n")
		b.WriteString("# Generated by tools/stabilitytool and regenerated at release time;\n")
		b.WriteString("# run 'make stability' to refresh.\n")
		for _, e := range entries {
			fmt.Fprintf(&b, "%s\t%s\t%s\n", e.ImportPath, e.Symbol, e.Version)
		}
		return b.String()
	}
	b.WriteString("# Public API exempt from the SemVer promise.\n")
	b.WriteString("# Every row here carries an \"Experimental:\" godoc marker and may\n")
	b.WriteString("# change in a minor release. Anything not listed is stable.\n")
	b.WriteString("# A \"*\" symbol means the marker is on the package doc and covers\n")
	b.WriteString("# the package; the godoc itself is where the scope is argued.\n")
	b.WriteString("# Generated by tools/stabilitytool; run 'make stability' to refresh.\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "%s\t%s\n", e.ImportPath, e.Symbol)
	}
	return b.String()
}

// scan walks root, parses every non-test Go file, and returns the marked
// symbols sorted by import path then symbol.
func scan(root, module string, kind reportKind) ([]entry, error) {
	var (
		entries []entry
		problem []string
	)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		importPath, err := importPathFor(path, root, module)
		if err != nil {
			return err
		}
		found, issues, err := scanFile(path, importPath, kind)
		if err != nil {
			return err
		}
		entries = append(entries, found...)
		problem = append(problem, issues...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(problem) > 0 {
		return nil, fmt.Errorf("malformed stability markers:\n  %s", strings.Join(problem, "\n  "))
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ImportPath != entries[j].ImportPath {
			return entries[i].ImportPath < entries[j].ImportPath
		}
		return entries[i].Symbol < entries[j].Symbol
	})
	return dedupe(entries), nil
}

// dedupe drops repeated rows. Go allows a package comment in more than one
// file of the same package, which would otherwise emit the package row once
// per file and make the report depend on file count rather than on markers.
func dedupe(entries []entry) []entry {
	out := entries[:0]
	var previous entry
	for i, e := range entries {
		if i > 0 && e == previous {
			continue
		}
		out = append(out, e)
		previous = e
	}
	return out
}

// importPathFor maps a file path back onto the import path of its package.
func importPathFor(path, root, module string) (string, error) {
	dir := filepath.Dir(path)
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return "", err
	}
	if rel == "." {
		return module, nil
	}
	return module + "/" + filepath.ToSlash(rel), nil
}

func scanFile(path, importPath string, kind reportKind) (entries []entry, issues []string, err error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, nil, err
	}
	// The package doc is scanned alongside the declarations. A package can
	// declare its whole surface exempt, and reading only file.Decls made
	// that declaration invisible to a report whose contract is "anything
	// absent is stable" — the marker existed, was published on pkg.go.dev,
	// and still left the package implicitly promised.
	if file.Doc != nil {
		e, issue := classify(kind, importPath, packageSymbol, file.Doc, fset, file.Package)
		entries, issues = collect(entries, issues, e, issue)
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			name, ok := funcSymbol(d)
			if !ok {
				continue
			}
			e, issue := classify(kind, importPath, name, d.Doc, fset, d.Pos())
			entries, issues = collect(entries, issues, e, issue)
		case *ast.GenDecl:
			entries, issues = scanGenDecl(d, importPath, kind, fset, entries, issues)
		}
	}
	return entries, issues, nil
}

// scanGenDecl handles type, const, and var groups. A grouped declaration can
// carry the marker on the group or on an individual spec, and both forms
// appear in this repository, so each spec falls back to the group's doc.
func scanGenDecl(
	d *ast.GenDecl,
	importPath string,
	kind reportKind,
	fset *token.FileSet,
	entries []entry,
	issues []string,
) ([]entry, []string) {
	for _, spec := range d.Specs {
		s, ok := describeSpec(spec, d)
		if !ok || !ast.IsExported(s.name) {
			continue
		}
		e, issue := classify(kind, importPath, s.name, s.doc, fset, s.pos)
		entries, issues = collect(entries, issues, e, issue)
		if s.structT != nil {
			entries, issues = scanStructFields(s.structT, importPath, s.name, kind, fset, entries, issues)
		}
	}
	return entries, issues
}

// specInfo is what a spec contributes to the report: the symbol it names,
// the doc the marker would be on, the position to blame in a diagnostic,
// and the struct body to descend into when there is one.
type specInfo struct {
	name    string
	doc     *ast.CommentGroup
	pos     token.Pos
	structT *ast.StructType
}

// describeSpec reduces the two spec shapes this repository uses to one
// value. A spec's own doc wins over the group's; falling back to the
// group is what lets a marker sit on either.
func describeSpec(spec ast.Spec, d *ast.GenDecl) (specInfo, bool) {
	info := specInfo{doc: d.Doc, pos: d.Pos()}
	switch s := spec.(type) {
	case *ast.TypeSpec:
		info.name = s.Name.Name
		info.structT, _ = s.Type.(*ast.StructType)
	case *ast.ValueSpec:
		if len(s.Names) == 0 {
			return specInfo{}, false
		}
		info.name = s.Names[0].Name
	default:
		return specInfo{}, false
	}
	if doc := specDoc(spec); doc != nil {
		info.doc = doc
	}
	info.pos = spec.Pos()
	return info, true
}

func specDoc(spec ast.Spec) *ast.CommentGroup {
	switch s := spec.(type) {
	case *ast.TypeSpec:
		return s.Doc
	case *ast.ValueSpec:
		return s.Doc
	}
	return nil
}

// scanStructFields descends into the fields of an exported struct type. A
// field is a public surface of its own: an embedder writes to it, and the
// markers on this repository's configuration structs sit on individual
// fields rather than on the enclosing type. Stopping at the TypeSpec left
// those markers unread, so a field could be marked, published, and never
// enter either report.
//
// Only named exported fields are emitted. An anonymous embedded field
// promotes the surface of the type it names, and that type is enumerated
// where it is declared.
func scanStructFields(
	structT *ast.StructType,
	importPath, typeName string,
	kind reportKind,
	fset *token.FileSet,
	entries []entry,
	issues []string,
) ([]entry, []string) {
	if structT.Fields == nil {
		return entries, issues
	}
	for _, field := range structT.Fields.List {
		// A field's marker is usually a doc comment, but the trailing
		// line comment is the same statement written sideways, so both
		// are read.
		doc := field.Doc
		if doc == nil {
			doc = field.Comment
		}
		if doc == nil {
			continue
		}
		for _, ident := range field.Names {
			if !ast.IsExported(ident.Name) {
				continue
			}
			e, issue := classify(kind, importPath, typeName+"."+ident.Name, doc, fset, ident.Pos())
			entries, issues = collect(entries, issues, e, issue)
		}
	}
	return entries, issues
}

func collect(entries []entry, issues []string, e *entry, issue string) ([]entry, []string) {
	if e != nil {
		entries = append(entries, *e)
	}
	if issue != "" {
		issues = append(issues, issue)
	}
	return entries, issues
}

// funcSymbol names a function or a method on an exported receiver. Methods on
// unexported receivers are not part of the public surface.
func funcSymbol(d *ast.FuncDecl) (string, bool) {
	if d.Recv == nil {
		return d.Name.Name, ast.IsExported(d.Name.Name)
	}
	if !ast.IsExported(d.Name.Name) || len(d.Recv.List) == 0 {
		return "", false
	}
	recv := receiverName(d.Recv.List[0].Type)
	if recv == "" || !ast.IsExported(recv) {
		return "", false
	}
	return recv + "." + d.Name.Name, true
}

func receiverName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return receiverName(t.X)
	case *ast.IndexExpr: // generic receiver, for example Foo[T]
		return receiverName(t.X)
	case *ast.IndexListExpr:
		return receiverName(t.X)
	}
	return ""
}

// markerLineIndex returns the offset of the first occurrence of marker that
// begins a line, or -1 when the doc carries none.
//
// Requiring the line start is what separates a marker from prose that
// merely names one. op/doc.go describes the convention in a sentence —
// `a symbol whose godoc begins with "Experimental:" ...` — and a
// substring search reads that as marking the symbol it documents. On a
// declaration the mistake exempts one symbol; on a package doc, which is
// where that sentence actually lives, it would exempt the entire public
// API from the SemVer promise while the report still looked generated.
// The same reasoning applies to "Stable since": prose that discusses the
// convention must not enter the record of what shipped when.
func markerLineIndex(text, marker string) int {
	for offset := 0; offset <= len(text); {
		line := text[offset:]
		if end := strings.IndexByte(line, '\n'); end >= 0 {
			line = line[:end]
		}
		if strings.HasPrefix(line, marker) {
			return offset
		}
		next := strings.IndexByte(text[offset:], '\n')
		if next < 0 {
			return -1
		}
		offset += next + 1
	}
	return -1
}

// classify decides whether a symbol belongs in this kind's report and reports
// a malformed marker.
func classify(
	kind reportKind,
	importPath, name string,
	doc *ast.CommentGroup,
	fset *token.FileSet,
	pos token.Pos,
) (*entry, string) {
	if doc == nil {
		return nil, ""
	}
	text := doc.Text()
	idx := markerLineIndex(text, kind.marker())
	if idx < 0 {
		return nil, ""
	}
	where := fset.Position(pos)
	// A symbol cannot be both exempt from the promise and covered by it.
	// Whichever kind is running says so, so the contradiction cannot hide
	// behind the report nobody regenerated.
	if markerLineIndex(text, kind.other()) >= 0 {
		return nil, fmt.Sprintf("%s:%d: %s carries both %q and %q",
			where.Filename, where.Line, name, experimentalMarker, stableMarker)
	}
	rest := text[idx+len(kind.marker()):]
	if kind == kindStable {
		version, ok := stableVersion(rest)
		if !ok {
			return nil, fmt.Sprintf("%s:%d: %s has %q that does not read as %q",
				where.Filename, where.Line, name, stableMarker, stableMarker+" vMAJOR.MINOR")
		}
		return &entry{ImportPath: importPath, Symbol: name, Version: version}, ""
	}
	// A marker with no rationale is an error because the whole point of the
	// exemption is to tell an embedder what is expected to change.
	if strings.TrimSpace(rest) == "" {
		return nil, fmt.Sprintf("%s:%d: %s has %q with no rationale",
			where.Filename, where.Line, name, experimentalMarker)
	}
	return &entry{ImportPath: importPath, Symbol: name}, ""
}

// stableVersion reads the vMAJOR.MINOR that must follow the marker on the
// same line. The version is the whole point of the marker, so a marker that
// does not carry one is malformed rather than ignored — silently dropping it
// would leave the symbol out of the record with no diff to notice.
//
// Only the release pair is accepted. A patch component would let the same
// contract be recorded under two spellings, and the marker names the release
// a contract froze in, which patch releases do not change.
func stableVersion(rest string) (string, bool) {
	if end := strings.IndexByte(rest, '\n'); end >= 0 {
		rest = rest[:end]
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", false
	}
	// The marker is written as a sentence, so the version is routinely
	// followed by the sentence's period.
	version := strings.TrimSuffix(fields[0], ".")
	if !isReleaseVersion(version) {
		return "", false
	}
	return version, true
}

func isReleaseVersion(s string) bool {
	rest, ok := strings.CutPrefix(s, "v")
	if !ok {
		return false
	}
	major, minor, ok := strings.Cut(rest, ".")
	if !ok {
		return false
	}
	return isDigits(major) && isDigits(minor)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
