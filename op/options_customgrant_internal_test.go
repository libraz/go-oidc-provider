package op

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"slices"
	"strconv"
	"testing"

	"github.com/libraz/go-oidc-provider/op/grant"
)

// stubTokenExchangePolicy satisfies [TokenExchangePolicy] for the
// registration-only paths below. The option layer stores the value and
// nothing in these tests drives a request, so Allow is never invoked.
type stubTokenExchangePolicy struct{}

//nolint:nilnil // interface contract: a nil decision with a nil error allows with provider defaults.
func (stubTokenExchangePolicy) Allow(context.Context, TokenExchangeRequest) (*TokenExchangeDecision, error) {
	return nil, nil
}

// TestBuiltinGrantTypeWires_CoversEveryEnumeratedGrantType asserts the
// collision set still follows the [grant.Type] enumeration. The
// assertion is trivially true while the set is derived; it exists to
// fail loudly if the derivation is ever replaced by a transcribed
// literal, which is the shape that let two grant types go missing.
func TestBuiltinGrantTypeWires_CoversEveryEnumeratedGrantType(t *testing.T) {
	t.Parallel()

	for ordinal := grant.Type(0); ; ordinal++ {
		if wire := ordinal.String(); ordinal.IsValid() && wire != "" {
			if _, ok := builtinGrantTypeWires[wire]; !ok {
				t.Errorf("grant type %q is implemented by the OP but absent from the "+
					"custom-grant collision set", wire)
			}
		}
		if ordinal == math.MaxUint8 {
			break
		}
	}
}

// TestBuiltinGrantTypeWires_CoversEveryInTreeExtensionGrant asserts
// every extension grant the OP implements itself is in the collision
// set. Extension grants have no [grant.Type] constant — they are
// enabled by their own Register option and dispatched by the same
// lookup table the embedder's custom handlers ride. Registration order
// puts embedder handlers first, so a custom handler answering to an
// in-tree extension grant's name wins the lookup and takes the wire
// away from the OP's implementation, along with every check that
// implementation applies.
//
// The config here registers the extension grants but no custom
// handlers, so everything customGrantNamesFor reports is in-tree.
func TestBuiltinGrantTypeWires_CoversEveryInTreeExtensionGrant(t *testing.T) {
	t.Parallel()

	cfg := &config{}
	if err := RegisterTokenExchange(stubTokenExchangePolicy{}).apply(cfg); err != nil {
		t.Fatalf("RegisterTokenExchange: %v", err)
	}
	names := customGrantNamesFor(cfg)
	if len(names) == 0 {
		t.Fatal("no in-tree extension grants reported; this guard is blind")
	}
	for _, name := range names {
		if _, ok := builtinGrantTypeWires[name]; !ok {
			t.Errorf("extension grant %q is implemented by the OP but absent from the "+
				"custom-grant collision set: a WithCustomGrant registration under that "+
				"name would displace the in-tree handler silently", name)
		}
	}
}

// TestBuiltinGrantTypeWires_CoversEveryNativelyRoutedGrantType reads
// the token endpoint's grant_type dispatch switch and asserts every
// wire it names is in the collision set. That switch is the routing
// authority: a grant_type it matches never reaches the custom-grant
// dispatcher, so a handler accepted under that name is silently dead
// code, and a wire the switch stops naming becomes overridable. The
// test parses the source instead of restating the list so the two stay
// coupled without anyone remembering to edit both.
func TestBuiltinGrantTypeWires_CoversEveryNativelyRoutedGrantType(t *testing.T) {
	t.Parallel()

	const grantSwitchSource = "../internal/tokenendpoint/handler.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, grantSwitchSource, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", grantSwitchSource, err)
	}
	wires := grantTypeSwitchCases(file)
	if len(wires) == 0 {
		t.Fatalf("no grant_type dispatch cases found in %s; the switch moved and this "+
			"guard is blind", grantSwitchSource)
	}
	for _, wire := range wires {
		if _, ok := builtinGrantTypeWires[wire]; !ok {
			t.Errorf("grant_type %q is routed natively by the token endpoint but is absent "+
				"from the custom-grant collision set: a WithCustomGrant registration under "+
				"that name is accepted and then never dispatched", wire)
		}
	}
}

// TestStaticClientAllowedGrantTypes_MatchesTheImplementedSet asserts
// the static-client whitelist and the custom-grant collision set are
// drawn from the same derivation. The two answer different questions —
// which grants a trusted seed may name, and which names an embedder may
// not claim — but both enumerate the grants the library implements, and
// a second transcription of that list is exactly the shape that drifted
// before. With no custom grants registered the two must agree entry for
// entry.
func TestStaticClientAllowedGrantTypes_MatchesTheImplementedSet(t *testing.T) {
	t.Parallel()

	cfg := &config{}
	allowed := cfg.staticClientAllowedGrantTypes()
	if len(allowed) != len(builtinGrantTypeWires) {
		t.Errorf("static-client whitelist has %d entries, collision set has %d: %v",
			len(allowed), len(builtinGrantTypeWires), allowed)
	}
	for _, wire := range allowed {
		if _, ok := builtinGrantTypeWires[wire]; !ok {
			t.Errorf("static-client whitelist admits grant_type %q, which the OP does not "+
				"implement", wire)
		}
	}
}

// TestBuiltinGrantTypeWireList_OrderIsWireVisible pins the order, not
// just the membership. Dynamic client registration copies this list
// verbatim into a client that registered without naming its
// grant_types, so the order reaches the registration response and the
// persisted record: it is wire output, not an internal detail. The
// list is derived from the grant.Type enumeration, which means
// reordering those constants would silently reorder a published
// document. Adding a grant is expected and this test should be updated
// with it; reordering one is not.
func TestBuiltinGrantTypeWireList_OrderIsWireVisible(t *testing.T) {
	t.Parallel()

	want := []string{
		"authorization_code",
		"refresh_token",
		"client_credentials",
		"urn:ietf:params:oauth:grant-type:device_code",
		"urn:openid:params:grant-type:ciba",
		TokenExchangeGrantType,
	}
	got := builtinGrantTypeWireList()
	if !slices.Equal(got, want) {
		t.Errorf("built-in grant wire order changed\n got: %v\nwant: %v", got, want)
	}
}

// grantTypeSwitchCases collects the string literals of every case arm
// in the token endpoint's switch on the parsed grant_type form value.
// The empty-string arm (the "grant_type is required" branch) names no
// wire and is skipped.
func grantTypeSwitchCases(file *ast.File) []string {
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		tag, ok := sw.Tag.(*ast.Ident)
		if !ok || tag.Name != "grantType" {
			return true
		}
		for _, stmt := range sw.Body.List {
			clause, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			out = append(out, caseStringLiterals(clause)...)
		}
		return true
	})
	return out
}

// caseStringLiterals unquotes the string-literal expressions of a
// single case arm, dropping non-literal and empty values.
func caseStringLiterals(clause *ast.CaseClause) []string {
	out := make([]string, 0, len(clause.List))
	for _, expr := range clause.List {
		lit, ok := expr.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		wire, err := strconv.Unquote(lit.Value)
		if err != nil || wire == "" {
			continue
		}
		out = append(out, wire)
	}
	return out
}
