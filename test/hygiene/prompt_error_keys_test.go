package hygiene_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// promptErrorCodes recovers every PromptError* string constant declared in
// op/interaction from its source, so a code added later is held to the
// catalogue without anyone remembering to extend a table here.
func promptErrorCodes(tb testing.TB) map[string]string {
	tb.Helper()
	codes := map[string]string{}
	for _, path := range goSources(tb, scanRoot{path: "../../op/interaction", recurse: false}) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			tb.Fatalf("parse %s: %v", path, err)
		}
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
					if !strings.HasPrefix(name.Name, "PromptError") || i >= len(value.Values) {
						continue
					}
					if literal, ok := literalString(value.Values[i]); ok {
						codes[name.Name] = literal
					}
				}
			}
		}
	}
	return codes
}

// TestPromptErrorCodesHaveCatalogueKeys pins that every PromptError code
// maps to a catalogue key and that the key resolves in every shipped
// locale. A code with no key reaches the SPA with an empty message.
func TestPromptErrorCodesHaveCatalogueKeys(t *testing.T) {
	t.Parallel()

	codes := promptErrorCodes(t)
	if len(codes) == 0 {
		t.Fatal("the source scan found no PromptError constants; the scan is broken, not the catalogue")
	}
	bundles, err := i18n.DefaultBundles()
	if err != nil {
		t.Fatalf("i18n.DefaultBundles: %v", err)
	}
	if len(bundles) < 2 {
		t.Fatalf("only %d shipped bundle(s); the cross-locale check needs the full seed set", len(bundles))
	}

	for name, code := range codes {
		key := interaction.PromptErrorMessageKey(code)
		if key == "" {
			t.Errorf("%s (%q) has no catalogue key: PromptErrorMessageKey returns empty", name, code)
			continue
		}
		for _, bundle := range bundles {
			if value, ok := bundle.Get(key, nil); !ok || value == "" {
				t.Errorf("locale %q has no entry for %q, the message key of %s", bundle.Tag(), key, name)
			}
		}
	}

	if key := interaction.PromptErrorMessageKey("not_a_code"); key != "" {
		t.Errorf("PromptErrorMessageKey of an unknown code = %q, want empty", key)
	}
}
