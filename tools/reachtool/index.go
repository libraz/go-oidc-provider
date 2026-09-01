package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
)

// declKind distinguishes the two declaration forms the checks reason
// about. Types and functions are deliberately absent: an unreferenced
// exported function or type is what `unused` and the public API report
// already speak about, while a constant or a sentinel is invisible to
// both — nothing reads a value that is only ever declared.
type declKind int

const (
	kindConst declKind = iota
	kindVar
)

// decl is one package-level const or var the scan recorded.
type decl struct {
	pkg      string // repo-relative package directory, "" for the module root
	file     string // repo-relative file path
	line     int
	name     string
	kind     declKind
	typeName string   // explicit type of the value spec, empty when inferred
	refs     []string // identifiers the spec's value expression names
	doc      string   // effective doc comment, inherited within a group
	str      string   // the literal when the value is a plain string constant
	alias    string   // the declaration this one re-exports, empty when it is not an alias
}

// pos renders the declaration site the way an editor jump expects.
func (d decl) pos() string { return fmt.Sprintf("%s:%d", d.file, d.line) }

// qualified addresses a declaration the way an allowlist row does:
// the repo-relative package directory, a dot, and the name.
func (d decl) qualified() string {
	if d.pkg == "" {
		return d.name
	}
	return d.pkg + "." + d.name
}

// index is the whole-repository source index every check resolves
// against.
//
// It is built from the AST rather than from a build, for the same
// reason the catalog's citation index is: the gate has to keep
// answering while an unrelated package does not compile, and a check
// that only runs on a green tree is a check nobody runs while they are
// breaking something.
type index struct {
	decls []decl

	// uses maps an identifier to the repo-relative files that name it
	// in code. Declaration names are excluded, so a symbol nothing
	// reads has an empty entry even though its own declaration was
	// parsed. Doc comments never contribute: a `[ErrFoo]` reference in
	// prose is not a use, and it is exactly what makes a text search
	// report an abandoned sentinel as live.
	uses map[string]map[string]bool

	// literals maps a string constant to the repo-relative files whose
	// code contains it. Message keys are reached through literals, not
	// identifiers.
	literals map[string]map[string]bool

	// consults is uses minus the sites that only enumerate. A value
	// listed by its own String() and IsValid() is named by the library
	// and consulted by nothing, and the difference between those two
	// statements is the difference between a flag that works and a flag
	// that is parsed, validated, and then ignored. See isPlumbing.
	consults map[string]map[string]bool

	files int
}

// skippedDirs are directory names the walk never descends into:
// version control, the gitignored design-doc tree, fixture trees, and
// vendored sources. None of them declare or reach the vocabulary under
// test, and testdata in particular holds golden files whose contents
// would make an unrendered message key look rendered.
func skippedDirs() map[string]bool {
	return map[string]bool{
		".git": true, ".github": true, "backup": true, "node_modules": true, "testdata": true,
	}
}

// buildIndex parses every non-test Go file under root and records what
// it declares and what it names.
//
// Test files are excluded on purpose, and that exclusion is the whole
// point of the gate. A sentinel a test asserts on but no code path
// produces is precisely the shape this catches: the test proves the
// value exists, not that the library can ever hand it to a caller.
func buildIndex(root string) (*index, error) {
	ix := &index{
		uses:     map[string]map[string]bool{},
		literals: map[string]map[string]bool{},
		consults: map[string]map[string]bool{},
	}
	skip := skippedDirs()
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		return ix.addFile(fset, root, path)
	})
	if err != nil {
		return nil, fmt.Errorf("index go sources under %q: %w", root, err)
	}
	return ix, nil
}

// addFile records one file's declarations and identifier uses. A file
// that does not parse contributes nothing rather than failing the run:
// a tree mid-edit must not turn this gate into a confusing build error.
func (ix *index) addFile(fset *token.FileSet, root, path string) error {
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil //nolint:nilerr // an unparseable file contributes nothing; reporting it is not this gate's job.
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	rel = filepath.ToSlash(rel)
	pkg := filepath.ToSlash(filepath.Dir(rel))
	if pkg == "." {
		pkg = ""
	}
	ix.files++
	ix.addDecls(fset, pkg, rel, f)
	ix.addUses(rel, f)
	ix.addConsults(rel, f)
	return nil
}

// addDecls records the package-level const and var specs one file
// declares, carrying each group's doc comment forward across the specs
// that do not have one of their own.
//
// The inheritance mirrors how the declaration reads: a paragraph
// written above the first of several constants describes all of them
// until the next paragraph appears. A check that only looked at
// spec.Doc would see the second and third member of such a block as
// undocumented and report a marker as missing that a reader plainly
// sees.
func (ix *index) addDecls(fset *token.FileSet, pkg, rel string, f *ast.File) {
	for _, d := range f.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		var kind declKind
		switch gen.Tok {
		case token.CONST:
			kind = kindConst
		case token.VAR:
			kind = kindVar
		default:
			continue
		}
		doc := gen.Doc.Text()
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if own := vs.Doc.Text(); own != "" {
				doc = own
			}
			ix.addValueSpec(fset, pkg, rel, kind, doc, vs)
		}
	}
}

// addValueSpec records one const / var spec.
func (ix *index) addValueSpec(fset *token.FileSet, pkg, rel string, kind declKind, doc string, vs *ast.ValueSpec) {
	typeName := ""
	if id, ok := vs.Type.(*ast.Ident); ok {
		typeName = id.Name
	}
	for i, name := range vs.Names {
		var value ast.Expr
		if i < len(vs.Values) {
			value = vs.Values[i]
		}
		ix.decls = append(ix.decls, decl{
			pkg:      pkg,
			file:     rel,
			line:     fset.Position(name.Pos()).Line,
			name:     name.Name,
			kind:     kind,
			typeName: typeName,
			refs:     namedIdents(value),
			doc:      doc,
			str:      stringValue(value),
			alias:    aliasTarget(value),
		})
	}
}

// namedIdents lists the identifiers a value expression names, so an
// alias declaration can be linked back to what it aliases.
func namedIdents(expr ast.Expr) []string {
	if expr == nil {
		return nil
	}
	var out []string
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			out = append(out, id.Name)
		}
		return true
	})
	return out
}

// aliasTarget returns the declaration a spec re-exports, when its value
// is a bare reference to one.
//
// A public package routinely gives an internal default or sentinel a
// name an embedder can reach — `DefaultCodeTTL`, `ErrUnknownUser`. The
// library then applies the internal name, never the public one, so
// measuring the alias by its own name reports every re-export as dead.
// The value being applied is what reach is about, so the question is
// asked of the target instead.
//
// iota is not a target: it is the value, not a declaration, and every
// enumeration in the tree would otherwise resolve through it.
func aliasTarget(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		if e.Name == "iota" {
			return ""
		}
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	default:
		return ""
	}
}

// stringValue returns the value of a plain string literal, or "" for
// anything else.
func stringValue(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return s
}

// addUses records every identifier and string literal one file names in
// code.
//
// Declaration names are skipped so a declaration never counts as its
// own use — which is the difference between this gate and grep, and the
// reason it can say "nothing reads this" at all. ast.Inspect visits a
// node before its children, so marking a declaring node's identifiers
// on the way in is enough to have them recognised when they are
// visited.
func (ix *index) addUses(rel string, f *ast.File) {
	declared := declaredIdents(f)
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				if s, err := strconv.Unquote(node.Value); err == nil {
					record(ix.literals, s, rel)
				}
			}
		case *ast.Ident:
			if !declared[node] {
				record(ix.uses, node.Name, rel)
			}
		}
		return true
	})
}

// addConsults records the identifier uses that are not part of a type's
// own enumeration plumbing.
//
// The symbol check asks whether the library names a declaration
// anywhere. That question is answered "yes" by a constant that appears
// only in its own String() and IsValid(), which is how a feature flag
// can be parsed, validated, advertised, and never branched on. This
// second index answers the narrower question — does anything act on it
// — by dropping the declarations whose whole job is to enumerate.
func (ix *index) addConsults(rel string, f *ast.File) {
	declared := declaredIdents(f)
	for _, d := range f.Decls {
		if isPlumbing(d) {
			continue
		}
		ast.Inspect(d, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && !declared[id] {
				record(ix.consults, id.Name, rel)
			}
			return true
		})
	}
}

// plumbingFuncs are the method and function names whose body exists to
// list a type's values rather than to act on one. A use inside one of
// these says the value is spelled out somewhere, not that anything
// depends on it.
//
// The set is deliberately short. A name like Validate or Apply is left
// out because those routinely carry real logic, and a check that
// discounted them would start reporting live symbols.
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var plumbingFuncs = map[string]bool{
	"String":        true,
	"GoString":      true,
	"IsValid":       true,
	"Values":        true,
	"All":           true,
	"MarshalText":   true,
	"UnmarshalText": true,
	"MarshalJSON":   true,
	"UnmarshalJSON": true,
}

// isPlumbing reports whether a top-level declaration exists to enumerate
// values rather than to act on them: one of the plumbing methods above,
// or a package-level table literal keyed by them.
func isPlumbing(d ast.Decl) bool {
	switch node := d.(type) {
	case *ast.FuncDecl:
		return plumbingFuncs[node.Name.Name]
	case *ast.GenDecl:
		if node.Tok != token.VAR && node.Tok != token.CONST {
			return false
		}
		return isTableDecl(node)
	default:
		return false
	}
}

// isTableDecl reports whether every value in a package-level var or
// const group is a map or slice literal — the shape a lookup table
// takes. Such a table names each member of an enumeration exactly once
// and branches on none of them.
func isTableDecl(gen *ast.GenDecl) bool {
	found := false
	for _, spec := range gen.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || len(vs.Values) == 0 {
			return false
		}
		for _, v := range vs.Values {
			lit, ok := v.(*ast.CompositeLit)
			if !ok {
				return false
			}
			switch lit.Type.(type) {
			case *ast.MapType, *ast.ArrayType:
				found = true
			default:
				return false
			}
		}
	}
	return found
}

// consultedIn reports whether any file that acts on the identifier
// satisfies want.
func (ix *index) consultedIn(name string, want func(file string) bool) bool {
	for file := range ix.consults[name] {
		if want(file) {
			return true
		}
	}
	return false
}

// declaredIdents collects the identifiers that introduce a name rather
// than reach one: the package clause, declaration names, struct fields
// and interface methods, parameters, and import aliases.
func declaredIdents(f *ast.File) map[*ast.Ident]bool {
	out := map[*ast.Ident]bool{}
	mark := func(ids ...*ast.Ident) {
		for _, id := range ids {
			if id != nil {
				out[id] = true
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.File:
			mark(node.Name)
		case *ast.FuncDecl:
			mark(node.Name)
		case *ast.ValueSpec:
			mark(node.Names...)
		case *ast.TypeSpec:
			mark(node.Name)
		case *ast.Field:
			mark(node.Names...)
		case *ast.ImportSpec:
			mark(node.Name)
		}
		return true
	})
	return out
}

// record adds one file to the set stored under key.
func record(m map[string]map[string]bool, key, file string) {
	files, ok := m[key]
	if !ok {
		files = map[string]bool{}
		m[key] = files
	}
	files[file] = true
}

// usedIn reports whether any file naming the identifier satisfies want.
func (ix *index) usedIn(name string, want func(file string) bool) bool {
	for file := range ix.uses[name] {
		if want(file) {
			return true
		}
	}
	return false
}

// declsIn returns the declarations one package directory makes.
func (ix *index) declsIn(pkg string) []decl {
	var out []decl
	for _, d := range ix.decls {
		if d.pkg == pkg {
			out = append(out, d)
		}
	}
	return out
}

// isExported reports whether name begins with an upper-case letter.
func isExported(name string) bool {
	if name == "" {
		return false
	}
	c := name[0]
	return c >= 'A' && c <= 'Z'
}

// hasSegment reports whether the slash-separated path contains segment.
func hasSegment(path, segment string) bool {
	if path == "" {
		return false
	}
	for _, s := range strings.Split(path, "/") {
		if s == segment {
			return true
		}
	}
	return false
}
