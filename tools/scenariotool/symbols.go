package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// The catalog cites code in prose so a reviewer can check an
// out-of-scope claim against the tree. A citation is only worth the
// paper it is written on if something notices when it stops being
// true, which a hand-written "file.go:123" never does: the line moves
// on the next edit and the reference silently starts pointing at an
// unrelated function.
//
// Citations are therefore written as `package.Symbol`, and this file
// resolves them against the declarations the repository actually
// makes. A rename or deletion on the other side fails the validator
// rather than leaving a sentence that reads correctly and is wrong.

// skippedCitationExts are the file suffixes that mark a token as a
// path reference rather than a symbol reference. They are left alone:
// a bare filename does not rot the way a line number does, and
// rewriting every one of them is a separate decision from this gate.
//
//nolint:gochecknoglobals // closed table; treated as a constant.
var skippedCitationExts = []string{".go", ".yaml", ".yml", ".json", ".md", ".sh", ".sql", ".html", ".js"}

// skippedSourceDirs are directory names never scanned for
// declarations: version control, the gitignored design-doc tree, and
// vendored / generated trees that declare nothing the catalog cites.
//
//nolint:gochecknoglobals // closed table; treated as a constant.
var skippedSourceDirs = map[string]bool{
	".git": true, "backup": true, "node_modules": true, "testdata": true, ".github": true,
}

// citationRe matches a candidate `package.Symbol` or
// `pkg/path.Type.Member` token in prose. Matching is deliberately
// permissive; [Catalog.unresolvedSymbolCitations] applies the rules
// that decide which matches are actually claims about this repository.
var citationRe = regexp.MustCompile(
	`\b((?:[a-z][a-z0-9_]*/)*[a-z][a-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)(?:\.([A-Za-z_][A-Za-z0-9_]*))?`,
)

// lineCitationRe matches a hand-written "file.go:123" reference. These
// are rejected outright rather than resolved: a line number is correct
// only until the next edit to the file above it, and nothing about the
// reference changes when it stops being true. Every one of them in this
// catalog was found pointing at unrelated code.
var lineCitationRe = regexp.MustCompile(`[A-Za-z0-9_./-]+\.go:\d+(?:-\d+)?`)

// symbolIndex answers "does this repository declare <package>.<Symbol>?".
//
// Packages are addressable two ways because the catalog cites them both
// ways: by directory path when the name alone would be ambiguous
// (`internal/clientauth.verifySignature`) and by package name when it
// reads better and is unique enough (`op.WithMTLSProxy`).
type symbolIndex struct {
	// byPath maps a repo-relative package directory to every name it
	// declares, including "Type.Method" and "Type.Field" pairs.
	byPath map[string]map[string]struct{}

	// byName maps a package name to the directories declaring it. A
	// name shared by several directories resolves if ANY of them
	// declares the symbol — the catalog's bare-name citations do not
	// carry enough information to disambiguate, and demanding they do
	// would trade a real check for a spelling convention.
	byName map[string][]string

	// packageNames maps a package directory to its declared package
	// name. It is filled during the walk and consumed once to build
	// byName.
	packageNames map[string]string
}

// buildSymbolIndex parses every Go file under root and records what it
// declares. Parsing is source-only: the index is built from the AST
// rather than from a build, so it still answers while an unrelated
// package is mid-edit and does not compile.
func buildSymbolIndex(root string) (*symbolIndex, error) {
	ix := &symbolIndex{
		byPath:       map[string]map[string]struct{}{},
		byName:       map[string][]string{},
		packageNames: map[string]string{},
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedSourceDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		// Test files are skipped on purpose. The catalog cites the
		// shipping surface; a symbol that exists only in a _test.go
		// file is not something an out-of-scope claim may lean on.
		// Skipping them also keeps an external `package foo_test` from
		// masking the real package name for its own directory.
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		return ix.addFile(fset, root, path)
	})
	if err != nil {
		return nil, fmt.Errorf("index go sources under %q: %w", root, err)
	}
	for pkgDir := range ix.byPath {
		name := ix.packageNames[pkgDir]
		ix.byName[name] = append(ix.byName[name], pkgDir)
	}
	for _, dirs := range ix.byName {
		sort.Strings(dirs)
	}
	return ix, nil
}

// addFile records one file's declarations. A file that does not parse
// is skipped rather than fatal: a tree mid-edit must not turn this
// gate into a build error with a confusing message.
func (ix *symbolIndex) addFile(fset *token.FileSet, root, path string) error {
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil //nolint:nilerr // an unparseable file contributes nothing; it is not this gate's failure to report.
	}
	rel, err := filepath.Rel(root, filepath.Dir(path))
	if err != nil {
		return err
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		rel = ""
	}
	names, ok := ix.byPath[rel]
	if !ok {
		names = map[string]struct{}{}
		ix.byPath[rel] = names
	}
	ix.packageNames[rel] = f.Name.Name
	for _, decl := range f.Decls {
		addDecl(names, decl)
	}
	return nil
}

// addDecl records the names one declaration introduces.
func addDecl(names map[string]struct{}, decl ast.Decl) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		names[d.Name.Name] = struct{}{}
		if recv := receiverTypeName(d); recv != "" {
			names[recv+"."+d.Name.Name] = struct{}{}
		}
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			addSpec(names, spec)
		}
	}
}

// addSpec records the names one spec inside a const / var / type
// declaration introduces, including a type's fields and interface
// methods so the catalog can cite `Type.Member`.
func addSpec(names map[string]struct{}, spec ast.Spec) {
	switch s := spec.(type) {
	case *ast.ValueSpec:
		for _, n := range s.Names {
			names[n.Name] = struct{}{}
		}
	case *ast.TypeSpec:
		names[s.Name.Name] = struct{}{}
		addTypeMembers(names, s.Name.Name, s.Type)
	}
}

// addTypeMembers records `Type.Field` for a struct and `Type.Method`
// for an interface. Embedded entries contribute their own type name so
// a promoted member cited through the outer type still resolves.
func addTypeMembers(names map[string]struct{}, typeName string, expr ast.Expr) {
	var fields *ast.FieldList
	switch t := expr.(type) {
	case *ast.StructType:
		fields = t.Fields
	case *ast.InterfaceType:
		fields = t.Methods
	default:
		return
	}
	if fields == nil {
		return
	}
	for _, f := range fields.List {
		if len(f.Names) == 0 {
			if embedded := exprTypeName(f.Type); embedded != "" {
				names[typeName+"."+embedded] = struct{}{}
			}
			continue
		}
		for _, n := range f.Names {
			names[typeName+"."+n.Name] = struct{}{}
		}
	}
}

// receiverTypeName returns the bare type name a method hangs off,
// stripping pointer and generic decoration.
func receiverTypeName(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return ""
	}
	return exprTypeName(d.Recv.List[0].Type)
}

// exprTypeName reduces a type expression to its bare identifier.
func exprTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return exprTypeName(t.X)
	case *ast.IndexExpr:
		return exprTypeName(t.X)
	case *ast.IndexListExpr:
		return exprTypeName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	default:
		return ""
	}
}

// declaredSymbols reports how many names the index recorded across
// every package it walked.
//
// The count is what tells "every citation resolved" apart from "the
// scan read nothing to resolve against". Both produce an empty problem
// list, and only the first of them is a clean catalog.
func (ix *symbolIndex) declaredSymbols() int {
	n := 0
	for _, names := range ix.byPath {
		n += len(names)
	}
	return n
}

// checkSymbolIndexReachedSources refuses to report on citations when
// the index built for them holds no declaration at all.
//
// Nothing to resolve against means every citation is dropped as "not a
// claim about this repository", which is indistinguishable from a
// catalog whose every citation is correct. A root that exists but holds
// no Go source — the wrong directory, a tree that was moved — would
// otherwise turn the check off without saying so.
func checkSymbolIndexReachedSources(root string, ix *symbolIndex) error {
	if ix.declaredSymbols() > 0 {
		return nil
	}
	return fmt.Errorf("no Go declarations found under %q: the citation check would resolve nothing "+
		"and report every row clean, so the scan is treated as broken rather than as a clean catalog", root)
}

// knownPath reports whether p addresses a package directory this
// repository contains.
func (ix *symbolIndex) knownPath(p string) bool {
	_, ok := ix.byPath[p]
	return ok
}

// knownName reports whether p is the name of a package this repository
// declares.
func (ix *symbolIndex) knownName(p string) bool {
	return len(ix.byName[p]) > 0
}

// resolve reports whether the cited symbol is declared. pkg addresses
// the package either by directory path or by name; member is the
// optional second segment of a `Type.Member` citation.
func (ix *symbolIndex) resolve(pkg, symbol, member string) bool {
	dirs := ix.byName[pkg]
	if ix.knownPath(pkg) {
		dirs = append([]string{pkg}, dirs...)
	}
	want := symbol
	if member != "" {
		want = symbol + "." + member
	}
	for _, dir := range dirs {
		if _, ok := ix.byPath[dir][want]; ok {
			return true
		}
	}
	return false
}

// unresolvedSymbolCitations returns one problem per prose citation that
// names this repository but does not resolve to a declaration.
//
// Two rules decide what counts as a claim worth checking, and both
// exist to keep the gate free of false positives on prose that merely
// looks like a citation:
//
//   - A path-qualified token (`internal/clientauth.verifySignature`) is
//     checked whenever the path is a real package directory. The `/`
//     makes the intent unambiguous, so unexported symbols are fair game.
//   - A bare token (`op.WithMTLSProxy`) is checked only when the symbol
//     is exported. The lowercase shape is reserved for the audit event
//     names the catalog quotes constantly — `grant.error`,
//     `interaction.chooser` — which are wire strings, not Go symbols.
func (c *Catalog) unresolvedSymbolCitations(ix *symbolIndex) []string {
	var problems []string
	seen := map[string]bool{}
	for _, ff := range c.Files {
		for _, r := range ff.Rows {
			for _, field := range citedFields(r) {
				problems = append(problems, field.problems(ix, ff.Path, r.ID, seen)...)
			}
		}
	}
	return problems
}

// citedField is one prose field of one row: the text a citation may
// appear in, and the name to report it under.
type citedField struct{ name, text string }

// citedFields names the fields of a row that carry prose. A field that
// is not listed here is never checked, so a new prose field has to be
// added deliberately rather than inheriting the gate by accident.
func citedFields(r *Row) []citedField {
	return []citedField{
		{"behaviour", r.Behaviour},
		{"notes", r.Notes},
		{"out_of_scope_reason", r.OutOfScopeReason},
	}
}

// problems reports the citations in one field that the gate rejects.
// seen is shared across every field of every row so one bad citation
// repeated in several places is reported once.
func (f citedField) problems(ix *symbolIndex, path, rowID string, seen map[string]bool) []string {
	var out []string
	report := func(cite, reason string) {
		key := rowID + "\x00" + f.name + "\x00" + cite
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, fmt.Sprintf("%s: %s %s %s", path, rowID, f.name, reason))
	}
	for _, cite := range lineCitationRe.FindAllString(f.text, -1) {
		report(cite, fmt.Sprintf(
			"cites %s by line number; cite package.Symbol instead so a rename breaks visibly", cite,
		))
	}
	for _, cite := range unresolvedInText(ix, f.text) {
		report(cite, fmt.Sprintf("cites %s, which this repository does not declare", cite))
	}
	return out
}

// unresolvedInText returns the citations in one prose field that name a
// known package but no known symbol.
func unresolvedInText(ix *symbolIndex, text string) []string {
	if text == "" {
		return nil
	}
	var out []string
	for _, m := range citationRe.FindAllStringSubmatch(text, -1) {
		whole, pkg, symbol, member := m[0], m[1], m[2], m[3]
		if hasSkippedExt(whole) {
			continue
		}
		qualified := strings.Contains(pkg, "/")
		switch {
		case qualified && !ix.knownPath(pkg):
			continue // not a claim about this repository
		case !qualified && !ix.knownName(pkg):
			continue
		case !qualified && !isExported(symbol):
			continue // audit event name, not a symbol reference
		}
		if !ix.resolve(pkg, symbol, member) {
			out = append(out, whole)
		}
	}
	return out
}

// hasSkippedExt reports whether the token ends in a source / data file
// suffix, which marks it as a path reference rather than a symbol.
func hasSkippedExt(token string) bool {
	for _, ext := range skippedCitationExts {
		if strings.HasSuffix(token, ext) {
			return true
		}
	}
	return false
}

// isExported reports whether name begins with an upper-case letter.
func isExported(name string) bool {
	for _, r := range name {
		return unicode.IsUpper(r)
	}
	return false
}

// repoRootFromCatalogDir derives the repository root from the catalog
// directory, which sits at <root>/test/scenarios/catalog. The tool is
// invoked with an absolute -dir by scripts/scenario.sh and with the
// repo-relative default otherwise; both reduce correctly.
//
// A directory that does not reduce is an error rather than a fallback
// to the working directory. The fallback reads as harmless — the scan
// still runs, still finds Go files — but the wrapper runs the tool from
// its own module, so the index would describe the tool instead of the
// repository under test: every citation naming a package of that
// repository is then dropped as "not a claim about this tree" and the
// validator reports a clean catalog having resolved nothing.
func repoRootFromCatalogDir(dir string) (string, error) {
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Clean(dir))))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("catalog dir %q does not sit at <repo root>/test/scenarios/catalog "+
			"(no go.mod under %q), so the citation check has no tree to resolve against", dir, root)
	}
	return root, nil
}
