package hygiene_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The SPA login mount is documented as fully replaceable: an embedder
// may delete the bundle in examples/ and write their own front end
// against the JSON contract. That makes the envelope vocabulary a
// public API surface with no compiler behind it — the endpoint emits a
// discriminated union of JSON objects, and the only description of the
// union an embedder can read lives in a doc comment.
//
// A terminal envelope the front end does not recognise is not a
// rendering defect: the two terminal shapes ARE the delivery of the
// authorization response, so an unhandled one strands the flow with the
// client never receiving code or error. These tests re-derive the
// emitted set from the endpoint's own source and pin it against the
// documented set and against the reference front end, so a third
// envelope cannot be added in silence.

const (
	// spaEndpointDir holds the endpoint that emits the envelopes.
	spaEndpointDir = "../../internal/authorizeendpoint"

	// spaContractDoc holds the public godoc that enumerates them.
	spaContractDoc = "../../op/options_authn.go"

	// spaContractDocSymbols are the exported symbols whose doc comments
	// carry the enumeration. Either may hold it; both must stay true.
	spaContractType   = "SPAUI"
	spaContractOption = "WithSPAUI"
)

// spaDocTypePattern matches the "type" member of an envelope written
// out in a doc comment, e.g. {"type":"redirect","location":"<url>"}.
// Prose that merely names a value in quotes does not match, so the
// enumeration has to be written as the shape an embedder receives.
var spaDocTypePattern = regexp.MustCompile(`"type"\s*:\s*"([^"]+)"`)

// TestSPAEnvelopeVocabulary_IsDocumented pins the emitted envelope
// vocabulary against the vocabulary the public godoc enumerates, in
// both directions: an envelope the endpoint can emit but the godoc does
// not describe is a shape no independently written front end can
// handle, and a documented envelope the endpoint cannot emit sends one
// down a branch that never fires.
func TestSPAEnvelopeVocabulary_IsDocumented(t *testing.T) {
	t.Parallel()

	emitted := emittedEnvelopeTypes(t)
	if len(emitted) == 0 {
		t.Fatal("no envelope types recovered from the endpoint source; the scan is broken, not the godoc")
	}
	documented := documentedEnvelopeTypes(t)
	if len(documented) == 0 {
		t.Fatalf("the godoc for %s / %s enumerates no envelope at all; an embedder writing their own "+
			"front end has no contract to implement", spaContractType, spaContractOption)
	}

	for _, name := range emitted {
		if !slices.Contains(documented, name) {
			t.Errorf("the SPA state route can emit a %q envelope, but no public godoc describes it: "+
				"a front end written against the documentation alone drops it (documented: %v)",
				name, documented)
		}
	}
	for _, name := range documented {
		if !slices.Contains(emitted, name) {
			t.Errorf("the godoc documents a %q envelope the endpoint never emits: "+
				"a front end branches on a shape that cannot arrive (emitted: %v)", name, emitted)
		}
	}
}

// TestSPAEnvelopeVocabulary_ReferenceBundleHandlesAll pins the third
// leg. The bundle every SPA example serves is the one front end in the
// tree that has to consume the whole vocabulary; an envelope it does
// not name reaches its prompt renderer instead, which is the shipped
// SPA failing to complete a flow the OP delivered correctly.
func TestSPAEnvelopeVocabulary_ReferenceBundleHandlesAll(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile(filepath.Clean(spaBundlePath))
	if err != nil {
		t.Fatalf("read SPA bundle: %v", err)
	}
	handler := rendererBody(t, string(src), "deliverTerminal")
	for _, name := range emittedEnvelopeTypes(t) {
		if !strings.Contains(handler, `"`+name+`"`) {
			t.Errorf("deliverTerminal never names the %q envelope; the bundle hands it to the prompt "+
				"renderer and the authorization response is never delivered to the client", name)
		}
	}
}

// emittedEnvelopeTypes returns every value the endpoint can put in an
// envelope's "type" member, recovered from the package source rather
// than from a hand-kept list — a list would reproduce one layer up the
// drift these tests exist to catch.
//
// The scan collects every string-keyed map literal carrying a "type"
// key, which over-approximates on purpose: a map with that key that is
// not an envelope still surfaces here and fails loudly, which is the
// safe direction for a guard whose whole job is to notice additions.
func emittedEnvelopeTypes(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(spaEndpointDir)
	if err != nil {
		t.Fatalf("read endpoint directory: %v", err)
	}
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(spaEndpointDir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		files = append(files, file)
	}

	consts := stringConstants(files)
	var out []string
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isStringKeyedMap(lit.Type) {
				return true
			}
			value, found := mapEntry(lit, "type")
			if !found {
				return true
			}
			name, resolved := resolveString(value, consts)
			if !resolved {
				t.Errorf("%s: the \"type\" member of an envelope is not a string constant this scan can "+
					"resolve; the vocabulary cannot be pinned while it is computed at runtime",
					fset.Position(lit.Pos()))
				return true
			}
			if !slices.Contains(out, name) {
				out = append(out, name)
			}
			return true
		})
	}
	slices.Sort(out)
	return out
}

// documentedEnvelopeTypes returns the envelope "type" values written
// into the public godoc of the SPA surface.
func documentedEnvelopeTypes(t *testing.T) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Clean(spaContractDoc), nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", spaContractDoc, err)
	}

	var docs []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.GenDecl:
			// A type declaration carries its doc on the GenDecl when the
			// block declares a single type, which is how SPAUI is written.
			for _, spec := range node.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name.Name != spaContractType {
					continue
				}
				docs = append(docs, docText(node.Doc), docText(ts.Doc))
			}
		case *ast.FuncDecl:
			if node.Name.Name == spaContractOption {
				docs = append(docs, docText(node.Doc))
			}
		}
		return true
	})
	if len(docs) == 0 {
		t.Fatalf("%s declares neither %s nor %s; the doc scan is looking at the wrong file",
			spaContractDoc, spaContractType, spaContractOption)
	}

	var out []string
	for _, doc := range docs {
		for _, match := range spaDocTypePattern.FindAllStringSubmatch(doc, -1) {
			if !slices.Contains(out, match[1]) {
				out = append(out, match[1])
			}
		}
	}
	slices.Sort(out)
	return out
}

// docText renders a doc comment as plain text, tolerating a nil group.
func docText(doc *ast.CommentGroup) string {
	if doc == nil {
		return ""
	}
	return doc.Text()
}

// stringConstants maps every package-level string constant name to its
// value so an envelope written with a named constant resolves.
func stringConstants(files []*ast.File) map[string]string {
	out := map[string]string{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if value, ok := basicStringLit(vs.Values[i]); ok {
						out[name.Name] = value
					}
				}
			}
		}
	}
	return out
}

// isStringKeyedMap reports whether expr is a map type with string keys.
func isStringKeyedMap(expr ast.Expr) bool {
	mapType, ok := expr.(*ast.MapType)
	if !ok {
		return false
	}
	key, ok := mapType.Key.(*ast.Ident)
	return ok && key.Name == "string"
}

// mapEntry returns the value expression stored under key in lit.
func mapEntry(lit *ast.CompositeLit, key string) (ast.Expr, bool) {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		name, ok := basicStringLit(kv.Key)
		if ok && name == key {
			return kv.Value, true
		}
	}
	return nil, false
}

// resolveString reduces expr to a string, following a package-level
// constant by name.
func resolveString(expr ast.Expr, consts map[string]string) (string, bool) {
	if value, ok := basicStringLit(expr); ok {
		return value, true
	}
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return "", false
	}
	value, ok := consts[ident.Name]
	return value, ok
}

// basicStringLit unquotes expr when it is an untagged string literal.
func basicStringLit(expr ast.Expr) (string, bool) {
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
