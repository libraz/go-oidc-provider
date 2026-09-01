package main

import "testing"

// TestCheckConsulted_ReportsAFlagOnlyItsOwnPlumbingNames is the case
// the check was added for. The constant is named — by String and by a
// lookup table — so the symbol check is satisfied, and nothing branches
// on it. That is a flag which is accepted, validated and advertised
// while changing no behaviour.
func TestCheckConsulted_ReportsAFlagOnlyItsOwnPlumbingNames(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/feature.go": `package op

type Flag string

const (
	// Live is branched on below.
	Live Flag = "live"

	// Inert appears in the plumbing and nowhere else.
	Inert Flag = "inert"
)

func (f Flag) String() string {
	switch f {
	case Live:
		return "live"
	case Inert:
		return "inert"
	}
	return ""
}

var allFlags = []Flag{Live, Inert}

func (f Flag) IsValid() bool {
	for _, c := range allFlags {
		if c == f {
			return true
		}
	}
	return false
}
`,
		"op/use.go": `package op

func gate(f Flag) bool { return f == Live }
`,
	})
	// The old question is satisfied for both: each name occurs.
	wantIDs(t, checkSymbols(ix, emptyAllowlist(t)))
	// The narrower question separates them.
	wantIDs(t, checkConsulted(ix, emptyAllowlist(t)), "op.Inert")
}

// TestCheckConsulted_StaysQuietWhenSomethingBranches keeps the check
// from reporting a constant that is doing its job.
func TestCheckConsulted_StaysQuietWhenSomethingBranches(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/feature.go": `package op

type Flag string

const Live Flag = "live"

func (f Flag) String() string { return string(f) }
`,
		"internal/gate/gate.go": `package gate

func on(s string) bool { return s == "live" }
`,
		"op/use.go": `package op

func gate(f Flag) bool { return f == Live }
`,
	})
	wantIDs(t, checkConsulted(ix, emptyAllowlist(t)))
}

// TestCheckConsulted_LeavesTheUnnamedToTheSymbolCheck stops the two
// checks reporting the same declaration twice: a constant nothing names
// at all is the symbol check's finding, and repeating it here would
// double every entry in a report that is read for its length.
func TestCheckConsulted_LeavesTheUnnamedToTheSymbolCheck(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/policy.go": `package op

// Orphan is named by nothing at all.
const Orphan = "orphan"
`,
	})
	wantIDs(t, checkSymbols(ix, emptyAllowlist(t)), "op.Orphan")
	wantIDs(t, checkConsulted(ix, emptyAllowlist(t)))
}

// TestCheckConsulted_DoesNotCountATestAsBranching mirrors the symbol
// check's rule. A test naming a constant proves the value exists, not
// that a shipped path depends on it.
func TestCheckConsulted_DoesNotCountATestAsBranching(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/feature.go": `package op

type Flag string

const Inert Flag = "inert"

func (f Flag) String() string {
	if f == Inert {
		return "inert"
	}
	return ""
}
`,
		"op/feature_test.go": `package op

import "testing"

func TestInert(t *testing.T) {
	if Inert.String() != "inert" {
		t.Fatal("no")
	}
	_ = Inert
}
`,
	})
	wantIDs(t, checkConsulted(ix, emptyAllowlist(t)), "op.Inert")
}

// TestCheckConsulted_DoesNotCountAnExampleAsBranching keeps a demo from
// answering the question. An example that mentions a flag demonstrates
// the name; it does not make the library act on the value.
func TestCheckConsulted_DoesNotCountAnExampleAsBranching(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/feature.go": `package op

type Flag string

const Inert Flag = "inert"

func (f Flag) String() string {
	if f == Inert {
		return "inert"
	}
	return ""
}
`,
		"examples/01-demo/main.go": `package main

import "example/op"

func main() {
	if op.Inert != "" {
		println("demo")
	}
}
`,
	})
	wantIDs(t, checkConsulted(ix, emptyAllowlist(t)), "op.Inert")
}

// TestCheckConsulted_HonoursTheAllowlist keeps the escape hatch open
// for vocabulary whose whole contract is being enumerable.
func TestCheckConsulted_HonoursTheAllowlist(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/feature.go": `package op

type Flag string

const Inert Flag = "inert"

func (f Flag) String() string {
	if f == Inert {
		return "inert"
	}
	return ""
}
`,
	})
	// Without the row this is a finding; the assertion below is only
	// meaningful because of that.
	wantIDs(t, checkConsulted(ix, emptyAllowlist(t)), "op.Inert")
	root := writeTree(t, map[string]string{
		"api/unreached.txt": "consulted\top.Inert\tEmbedder vocabulary; the matching value lives in an internal package.\n",
	})
	al, err := loadAllowlist(root + "/api/unreached.txt")
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	wantIDs(t, checkConsulted(ix, al))
}

// TestCheckConsulted_IgnoresSentinelErrors keeps the check to constants.
// A sentinel's use is being returned and compared, which no plumbing
// name covers, so admitting them would only add noise.
func TestCheckConsulted_IgnoresSentinelErrors(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/errors.go": `package op

import "errors"

// ErrThing is returned by the library.
var ErrThing = errors.New("thing")
`,
		"op/use.go": `package op

func fail() error { return ErrThing }
`,
	})
	wantIDs(t, checkConsulted(ix, emptyAllowlist(t)))
}

// TestIsTableDecl_RequiresEveryValueToBeALiteralTable keeps the
// plumbing rule narrow: a var group holding real state must not be
// discounted just because one of its members is a slice.
func TestIsTableDecl_RequiresEveryValueToBeALiteralTable(t *testing.T) {
	t.Parallel()
	ix := indexTree(t, map[string]string{
		"op/feature.go": `package op

type Flag string

const Inert Flag = "inert"

var (
	table   = []Flag{Inert}
	current = pick()
)

func pick() Flag { return "" }
`,
	})
	// The group mixes a table with a computed value, so it is not
	// plumbing and the constant counts as consulted.
	wantIDs(t, checkConsulted(ix, emptyAllowlist(t)))
}
