package hygiene_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A struct field the library declares but never assigns is invisible
// from inside the type: it compiles, it has a godoc paragraph
// describing behaviour, and it reads as the zero value forever. Two
// consecutive sweeps of "declared but not wired" public symbols were
// done by hand and both missed this shape, because a hand sweep starts
// from the option list and a field is not an option.
//
// The types below are the ones whose fields are consumed as request
// state — a rule predicate, an SPI input, a verifier setting. For each,
// the field set the library actually assigns is derived from the source
// and compared against the field set the type declares.
//
// # Scope, stated precisely
//
// This scans keyed composite literals of the watched types in the
// library's own non-test sources (internal/ and op/). It therefore sees:
//
//   - a declared exported field that no library construction site ever
//     assigns, and
//   - a field assigned at one construction site of a type and omitted
//     at another, for the types marked symmetric.
//
// It does NOT see: fields an embedder is expected to fill (the library
// never constructs those), values assigned after construction rather
// than in the literal, construction through a helper that takes the
// field as a parameter, or a field assigned a value that is itself the
// zero value. It is a check on *whether* a field is wired, not on what
// it is wired to.
//
// Adding a type here is cheap and is the intended response to finding
// another instance of this class.
var declaredFieldWatch = []watchedType{
	{
		declFile:  "op/loginflow.go",
		declName:  "ClientHints",
		literals:  []string{"ClientHints"},
		minSites:  2,
		symmetric: true,
		why: "the login-flow orchestrator and the ACR resolver both build the public LoginContext; " +
			"a predicate cannot tell which face produced the value it reads",
	},
	{
		declFile:  "internal/authn/captcha.go",
		declName:  "CaptchaInput",
		literals:  []string{"CaptchaInput"},
		minSites:  2,
		symmetric: true,
		why: "the threshold-triggered captcha and the StepCaptcha adapter both call the same " +
			"embedder CaptchaVerifier, which cannot tell which one is calling it",
	},
	{
		declFile:  "op/interaction/prompt.go",
		declName:  "CaptchaPromptData",
		literals:  []string{"CaptchaPromptData", "interaction.CaptchaPromptData"},
		minSites:  2,
		symmetric: true,
		why: "both captcha prompt emission points feed the same SPA renderer, which bootstraps the " +
			"upstream widget from this data",
	},
	{
		declFile:  "internal/tokens/verify.go",
		declName:  "AccessTokenVerifier",
		literals:  []string{"AccessTokenVerifier", "tokens.AccessTokenVerifier"},
		minSites:  4,
		symmetric: false,
		why: "every endpoint that accepts a JWT access token builds one; a setting left off one of " +
			"them is a token that endpoint alone accepts",
	},
	{
		declFile:  "op/subject/subject.go",
		declName:  "GeneratorInput",
		literals:  []string{"GeneratorInput", "SubjectGeneratorInput", "subject.GeneratorInput"},
		minSites:  2,
		symmetric: true,
		why: "the pairwise and passthrough projector arms hand the same input type to the embedder's " +
			"Generator",
	},
}

// watchedType names one struct whose declared exported fields are
// compared against the fields the library assigns.
type watchedType struct {
	// declFile is the repo-relative file declaring the struct.
	declFile string
	// declName is the type name as declared in declFile.
	declName string
	// literals lists every identifier a composite literal of this type
	// may be written with, including package qualifiers and the public
	// aliases the op package re-exports it under. Aliases are listed
	// explicitly rather than resolved, so the check never silently
	// stops finding a type it used to find.
	literals []string
	// minSites is the number of construction sites expected. A scan
	// finding fewer has broken rather than passed.
	minSites int
	// symmetric requires every construction site to assign the same
	// field set. Set it for types built by two or more faces that a
	// downstream consumer cannot distinguish.
	symmetric bool
	// why explains, in the failure message, what breaks when the sets
	// diverge.
	why string
}

// scanRoots are the library's own source trees. examples/ and test/
// are excluded: they are consumers, and a consumer legitimately builds
// a partial value.
var scanRoots = []string{"internal", "op"}

// TestDeclaredFieldsAreWired asserts that each watched struct's
// exported fields are actually assigned by the library, and that the
// faces of a symmetric type assign the same set.
func TestDeclaredFieldsAreWired(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	sites := collectLiteralSites(t, root)

	for _, w := range declaredFieldWatch {
		t.Run(w.declName, func(t *testing.T) {
			t.Parallel()

			declared := declaredExportedFields(t, filepath.Join(root, w.declFile), w.declName)
			if len(declared) == 0 {
				t.Fatalf("%s declares no exported fields in %s; the extraction is broken rather than the source",
					w.declName, w.declFile)
			}

			found := sitesFor(sites, w.literals)
			if len(found) < w.minSites {
				t.Fatalf("found %d construction site(s) for %s, expected at least %d; "+
					"the scan stopped matching (renamed type, new alias, or a builder function replaced the literal) "+
					"rather than the source having improved",
					len(found), w.declName, w.minSites)
			}

			assigned := map[string]bool{}
			for _, s := range found {
				for f := range s.fields {
					assigned[f] = true
				}
			}
			for _, f := range declared {
				if !assigned[f] {
					t.Errorf("%s.%s is declared and documented but no library construction site assigns it, "+
						"so it reads as the zero value on every request: %s",
						w.declName, f, w.why)
				}
			}
			if !w.symmetric {
				return
			}
			for _, s := range found {
				for _, f := range declared {
					if !assigned[f] || s.fields[f] {
						continue
					}
					t.Errorf("%s constructs %s without %s, which %s does assign: %s",
						s.where, w.declName, f, otherSite(found, s, f), w.why)
				}
			}
		})
	}
}

// literalSite is one keyed composite literal found in the library.
type literalSite struct {
	// name is the literal's type expression as written ("CaptchaInput"
	// or "interaction.CaptchaPromptData").
	name string
	// where is the repo-relative file:line of the literal.
	where string
	// fields is the set of field names the literal assigns.
	fields map[string]bool
}

// collectLiteralSites walks the library's non-test sources and records
// every keyed composite literal it finds, indexed by the literal's type
// expression as written.
func collectLiteralSites(tb testing.TB, root string) map[string][]literalSite {
	tb.Helper()

	out := map[string][]literalSite{}
	fset := token.NewFileSet()
	for _, sub := range scanRoots {
		err := filepath.WalkDir(filepath.Join(root, sub), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				tb.Fatalf("parse %s: %v", path, perr)
			}
			rel, _ := filepath.Rel(root, path)
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || lit.Type == nil {
					return true
				}
				name := typeExprName(lit.Type)
				if name == "" {
					return true
				}
				out[name] = append(out[name], literalSite{
					name:   name,
					where:  rel + ":" + fsetLine(fset, lit.Pos()),
					fields: literalFieldNames(lit),
				})
				return true
			})
			return nil
		})
		if err != nil {
			tb.Fatalf("walk %s: %v", sub, err)
		}
	}
	return out
}

// typeExprName renders the type expression of a composite literal as
// the source spells it. Anything that is not a bare or qualified
// identifier (slice, map, array literals) returns "".
func typeExprName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		if !ok {
			return ""
		}
		return pkg.Name + "." + t.Sel.Name
	default:
		return ""
	}
}

// literalFieldNames returns the field names a keyed composite literal
// assigns. A positional literal yields an empty set: the check cannot
// map positions to names without type information, and the library
// writes struct literals keyed.
func literalFieldNames(lit *ast.CompositeLit) map[string]bool {
	out := map[string]bool{}
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		out[key.Name] = true
	}
	return out
}

// declaredExportedFields returns the exported field names of the named
// struct, in declaration order. Embedded fields are skipped: they carry
// no name of their own to assign.
func declaredExportedFields(tb testing.TB, path, typeName string) []string {
	tb.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		tb.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name.Name != typeName {
			return true
		}
		st, ok := spec.Type.(*ast.StructType)
		if !ok || st.Fields == nil {
			return false
		}
		for _, f := range st.Fields.List {
			for _, name := range f.Names {
				if name.IsExported() {
					out = append(out, name.Name)
				}
			}
		}
		return false
	})
	sort.Strings(out)
	return out
}

// sitesFor gathers every recorded site whose literal name matches one
// of the accepted spellings.
func sitesFor(sites map[string][]literalSite, literals []string) []literalSite {
	var out []literalSite
	for _, name := range literals {
		out = append(out, sites[name]...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].where < out[j].where })
	return out
}

// otherSite names a site that does assign field, for the failure
// message. It makes the asymmetry concrete: the reader gets both ends
// of the disagreement without going looking.
func otherSite(sites []literalSite, exclude literalSite, field string) string {
	for _, s := range sites {
		if s.where != exclude.where && s.fields[field] {
			return s.where
		}
	}
	return "another site"
}

// fsetLine renders a position's line number.
func fsetLine(fset *token.FileSet, pos token.Pos) string {
	p := fset.Position(pos)
	return itoa(p.Line)
}

// itoa avoids pulling strconv in for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
