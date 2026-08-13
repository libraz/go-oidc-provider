package hygiene_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/i18n"
)

// Every string the library hands a renderer as an i18n key — the
// [interaction.FieldSpec.Label] of a form field, the [interaction.Prompt.Type]
// a screen is titled by — is resolved against the locale catalogue at
// render time, and there is no compiler edge between the two. A key with
// no catalogue entry does not fail: it renders as itself, so the user is
// shown "chooser.session_id" as the label of the field they are being
// asked to fill in.
//
// Enumerating those keys in a table here would reproduce the same drift
// one layer up, so the emission set is recovered from the AST. A factor
// that starts emitting a new label fails this test until the catalogue
// grows the entry, in every shipped locale.

// labelScanRoots are the trees whose emissions the catalogue must
// answer: the built-in factors and interactions, plus the op package's
// own login-flow compiler, which emits a captcha label of its own.
//
// op subpackages are deliberately out of scope. op/testkit is test
// scaffolding whose prompt exists to be driven by a test, not read by a
// user, and holding the shipped catalogue responsible for its key would
// put test fixtures in a production bundle.
var labelScanRoots = []scanRoot{
	{path: "../../internal/authn", recurse: true},
	// Depth one only: op/testkit declares a prompt type that exists to
	// be driven by a test, not read by a user, and holding the shipped
	// catalogue responsible for it would put test scaffolding in a
	// production bundle.
	{path: "../../op", recurse: false},
}

// scanRoot is a tree to parse and whether to descend into it.
type scanRoot struct {
	path    string
	recurse bool
}

// keyReferenceRoots are the trees a catalogue entry may be reached
// from. The library trees are where a key is resolved at render time;
// examples/ is where a key the library ships for embedders to override
// is demonstrated. A key named by neither is reachable from nothing.
var keyReferenceRoots = []scanRoot{
	{path: "../../internal", recurse: true},
	{path: "../../op", recurse: true},
	{path: "../../examples", recurse: true},
}

// emissions is the key set recovered from the library's own source.
type emissions struct {
	// labels are the strings passed as FieldSpec.Label.
	labels []string
	// promptTypes are the strings used as Prompt.Type, both as literals
	// and through the exported PromptType constants each factor declares.
	promptTypes []string
}

// TestInteractionKeysResolveInEveryShippedLocale is the forward
// direction: everything the library emits must have an entry, in every
// bundle the library ships. A missing entry in one locale is worse than
// a missing entry in all of them, because it only surfaces for the users
// who selected that locale.
func TestInteractionKeysResolveInEveryShippedLocale(t *testing.T) {
	t.Parallel()

	emitted := scanEmissions(t)
	if len(emitted.labels) == 0 || len(emitted.promptTypes) == 0 {
		t.Fatal("the source scan found no labels or no prompt types; the scan is broken, not the catalogue")
	}

	bundles, err := i18n.DefaultBundles()
	if err != nil {
		t.Fatalf("i18n.DefaultBundles: %v", err)
	}
	if len(bundles) < 2 {
		t.Fatalf("only %d shipped bundle(s); the cross-locale check needs the full seed set", len(bundles))
	}

	for _, bundle := range bundles {
		for _, key := range emitted.labels {
			if value, ok := bundle.Get(key, nil); !ok || value == "" {
				t.Errorf("locale %q has no entry for FieldSpec.Label %q: the field renders with the raw key as its label",
					bundle.Tag(), key)
			}
		}
		for _, key := range emitted.promptTypes {
			if value, ok := bundle.Get(key, nil); !ok || value == "" {
				t.Errorf("locale %q has no entry for Prompt.Type %q: the screen is titled with the raw prompt identifier",
					bundle.Tag(), key)
			}
		}
	}
}

// TestInteractionCatalogueKeysAreReachable is the whole reverse
// direction: no seed-catalogue entry may be unreachable from every
// shipped source. A dead entry is worse than a missing one, because its
// presence reads as coverage — the bundle looks like it answers a
// screen it will never be consulted for, and the screen it was written
// for renders hardcoded English or the raw key instead. That is exactly
// how a translated logout page shipped as an English one.
//
// Reachable means the key is named as a string literal somewhere in the
// tree: by the library, which resolves it at render time, or by a
// shipped example, which demonstrates overriding it. Both are derived
// by scanning, so there is no exemption list to fall out of date.
func TestInteractionCatalogueKeysAreReachable(t *testing.T) {
	t.Parallel()

	referenced := referencedStringLiterals(t)
	emitted := scanEmissions(t)
	keys := seedCatalogueKeys(t)
	if len(keys) == 0 {
		t.Fatal("the seed catalogues yielded no keys; the scan is broken, not the catalogue")
	}

	for _, key := range keys {
		if referenced[key] || slices.Contains(emitted.labels, key) || slices.Contains(emitted.promptTypes, key) {
			continue
		}
		t.Errorf("the seed catalogue carries %q but nothing in the tree names it: "+
			"no library render path resolves it and no example overrides it, so the surface it "+
			"describes is either unlocalized or gone", key)
	}
}

// referencedStringLiterals returns every string literal appearing in
// non-test Go source under [keyReferenceRoots]. Scanning literals
// rather than call sites keeps the check independent of how a key
// reaches the resolver — a message lookup, a template data field, an
// embedder's override map in an example all count equally.
func referencedStringLiterals(tb testing.TB) map[string]bool {
	tb.Helper()
	out := map[string]bool{}
	for _, root := range keyReferenceRoots {
		for _, path := range goSources(tb, root) {
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				// Examples are separate modules under build tags; a file
				// this parser cannot read is not evidence about the
				// catalogue, so skip rather than fail.
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if expr, ok := n.(ast.Expr); ok {
					if value, ok := literalString(expr); ok {
						out[value] = true
					}
				}
				return true
			})
		}
	}
	return out
}

// TestInteractionCatalogueHasNoUnreachableFieldKeys narrows the same
// question to the field keys, where the answer is sharper: a key that
// is an emitted prompt type followed by a further segment names a field
// under that screen, so some FieldSpec must emit exactly it. A rename
// on one side shows up here as a specific mismatch rather than as a
// generic "nothing names this".
func TestInteractionCatalogueHasNoUnreachableFieldKeys(t *testing.T) {
	t.Parallel()

	emitted := scanEmissions(t)
	bundles, err := i18n.DefaultBundles()
	if err != nil {
		t.Fatalf("i18n.DefaultBundles: %v", err)
	}

	checked := 0
	for _, bundle := range bundles {
		for _, key := range catalogueKeys(t, bundle) {
			owner, ok := promptTypeNamespace(key, emitted.promptTypes)
			if !ok {
				continue
			}
			checked++
			if !slices.Contains(emitted.labels, key) {
				t.Errorf("locale %q carries %q, a field under the %q screen that no FieldSpec emits: "+
					"either the label moved and this entry is dead, or the field is emitting a key the catalogue misspells",
					bundle.Tag(), key, owner)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no catalogue key fell under an emitted prompt type; the namespace match is broken, not the catalogue")
	}
}

// promptTypeNamespace reports the emitted prompt type that owns key,
// when key names a field beneath one. The longest match wins so
// "auth.email_otp.send" is preferred over a hypothetical
// "auth.email_otp".
func promptTypeNamespace(key string, promptTypes []string) (string, bool) {
	best := ""
	for _, promptType := range promptTypes {
		if !strings.HasPrefix(key, promptType+".") {
			continue
		}
		if len(promptType) > len(best) {
			best = promptType
		}
	}
	return best, best != ""
}

// catalogueKeys returns every key the bundle carries, sorted so failure
// output is stable. Bundle exposes lookup rather than enumeration, so
// the key list is recovered by probing the union of both shipped
// catalogues' raw JSON.
func catalogueKeys(tb testing.TB, bundle *i18n.Bundle) []string {
	tb.Helper()
	keys := make([]string, 0, len(seedCatalogueKeys(tb)))
	for _, key := range seedCatalogueKeys(tb) {
		if _, ok := bundle.Get(key, nil); ok {
			keys = append(keys, key)
		}
	}
	return keys
}

// seedCatalogueKeys reads the key names straight out of the shipped
// JSON files. The bundles are the source of truth for values; the files
// are the only place the key list itself exists.
func seedCatalogueKeys(tb testing.TB) []string {
	tb.Helper()
	var keys []string
	root := filepath.Join("..", "..", "internal", "i18n", "embedded")
	entries, err := filepath.Glob(filepath.Join(root, "*.json"))
	if err != nil {
		tb.Fatalf("glob seed catalogues: %v", err)
	}
	if len(entries) == 0 {
		tb.Fatalf("no seed catalogues under %s; the path is wrong", root)
	}
	for _, path := range entries {
		for _, key := range jsonObjectKeys(tb, path) {
			if !slices.Contains(keys, key) {
				keys = append(keys, key)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// jsonObjectKeys returns the top-level member names of a JSON object
// file. The seed catalogues are flat dotted-key maps, so this is the
// whole key list.
func jsonObjectKeys(tb testing.TB, path string) []string {
	tb.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		tb.Fatalf("read %s: %v", path, err)
	}
	var object map[string]string
	if err := json.Unmarshal(raw, &object); err != nil {
		tb.Fatalf("decode %s: %v", path, err)
	}
	out := make([]string, 0, len(object))
	for key := range object {
		out = append(out, key)
	}
	return out
}

// scanEmissions parses the library's non-test sources under
// [labelScanRoots] and recovers the label / prompt-type key sets.
func scanEmissions(tb testing.TB) emissions {
	tb.Helper()
	var out emissions
	for _, root := range labelScanRoots {
		for _, path := range goSources(tb, root) {
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				tb.Fatalf("parse %s: %v", path, err)
			}
			collectConstPromptTypes(file, &out)
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				switch {
				case typeNameMentions(lit.Type, "FieldSpec"):
					collectFieldSpecLabels(lit, &out)
				case typeNameMentions(lit.Type, "Prompt"):
					if value, ok := stringField(lit, "Type"); ok {
						out.promptTypes = addUnique(out.promptTypes, value)
					}
				}
				return true
			})
		}
	}
	sort.Strings(out.labels)
	sort.Strings(out.promptTypes)
	return out
}

// collectFieldSpecLabels reads Label off a FieldSpec literal and, when
// the literal is a []FieldSpec, off each of its elements. Slice
// elements carry no Type of their own, so the enclosing literal is the
// only place the type is written.
func collectFieldSpecLabels(lit *ast.CompositeLit, out *emissions) {
	if value, ok := stringField(lit, "Label"); ok {
		out.labels = addUnique(out.labels, value)
	}
	for _, element := range lit.Elts {
		nested, ok := element.(*ast.CompositeLit)
		if !ok {
			continue
		}
		if value, ok := stringField(nested, "Label"); ok {
			out.labels = addUnique(out.labels, value)
		}
	}
}

// collectConstPromptTypes records the string constants each factor
// declares for its prompt type. A prompt literal usually writes
// `Type: PromptType`, so the constant is the only place the value is
// spelled.
func collectConstPromptTypes(file *ast.File, out *emissions) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if !strings.Contains(name.Name, "PromptType") || i >= len(value.Values) {
					continue
				}
				if literal, ok := literalString(value.Values[i]); ok {
					out.promptTypes = addUnique(out.promptTypes, literal)
				}
			}
		}
	}
}

// typeNameMentions reports whether the composite literal's type
// expression names the given struct, with or without a package
// qualifier and through a slice element type.
func typeNameMentions(expr ast.Expr, name string) bool {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name == name
	case *ast.SelectorExpr:
		return typed.Sel.Name == name
	case *ast.ArrayType:
		return typeNameMentions(typed.Elt, name)
	case *ast.StarExpr:
		return typeNameMentions(typed.X, name)
	default:
		return false
	}
}

// stringField returns the string literal assigned to the named field of
// a composite literal.
func stringField(lit *ast.CompositeLit, field string) (string, bool) {
	for _, element := range lit.Elts {
		kv, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != field {
			continue
		}
		return literalString(kv.Value)
	}
	return "", false
}

// literalString unquotes expr when it is an untagged string literal.
func literalString(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

// goSources lists the non-test .go files under root, descending into
// subdirectories only when the root asks for it.
func goSources(tb testing.TB, root scanRoot) []string {
	tb.Helper()
	var out []string
	err := filepath.WalkDir(root.path, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root.path && !root.recurse {
				return fs.SkipDir
			}
			return nil
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		tb.Fatalf("walk %s: %v", root.path, err)
	}
	if len(out) == 0 {
		tb.Fatalf("no Go sources under %s; the scan root is wrong", root.path)
	}
	return out
}

func addUnique(dst []string, value string) []string {
	if value == "" || slices.Contains(dst, value) {
		return dst
	}
	return append(dst, value)
}
