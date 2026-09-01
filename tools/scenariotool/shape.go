package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Shape classifies what a catalog row actually demands of the
// implementation.
//
// The distinction is not cosmetic. A row that says an ID Token "MUST
// include auth_time" is satisfied by an implementation that emits
// auth_time with the wrong value, so a feature file made entirely of
// such rows can sit at 100% coverage while the central requirement of
// the spec section it cites is asserted nowhere. That is not a
// hypothetical: every row about auth_time on the authorization-code
// path asserted presence, and an exit that reported the wrong
// authentication time passed the whole suite.
type Shape string

const (
	// ShapePresence demands only that something appear or be absent.
	ShapePresence Shape = "presence"

	// ShapeValue demands a particular value, or a relationship between
	// two values.
	ShapeValue Shape = "value"

	// ShapeOrder demands a sequence: what happens before what, what is
	// consumed once, what may not be replayed.
	ShapeOrder Shape = "order"

	// ShapeIdentity demands that a thing refer to a particular
	// principal, client, grant or session rather than another.
	ShapeIdentity Shape = "identity"
)

// validShapes is the set a row may declare explicitly.
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var validShapes = map[Shape]bool{
	ShapePresence: true,
	ShapeValue:    true,
	ShapeOrder:    true,
	ShapeIdentity: true,
}

// shapePatterns infer a row's shape from its behaviour text when the row
// does not declare one. Inference is deliberately one-directional: a
// match promotes a row out of "presence", and no pattern ever demotes
// one. A misread therefore costs a file nothing — the gate only asks
// whether a file has *any* non-presence row — while a row the patterns
// cannot read is fixed by declaring `shape:` on it.
//
// Order matters, most specific first. "bound to the same client" is an
// identity claim that also contains the value pattern's "the same", so
// identity is tried before order and value.
//
//nolint:gochecknoglobals // compiled once; a per-call rebuild would recompile six regexps per row.
var shapePatterns = []struct {
	shape Shape
	re    *regexp.Regexp
}{
	{ShapeIdentity, regexp.MustCompile(`(?i)\b(bound to|belongs? to|issued (to|for)|the same (subject|client|grant|session|account|user)|another (subject|client|grant|session|account|user)|different (subject|client|grant|session|account|user)|other than)\b`)},
	{ShapeOrder, regexp.MustCompile(`(?i)\b(before|after|precede(s|d)?|follow(s|ed)?|order(ing|ed)?|sequence|already|once|second time|re-?us(e|ed)|re-?play(ed)?|rotat(e|ed|ion)|consum(e|ed|ption)|single-?use|idempotent)\b`)},
	{ShapeValue, regexp.MustCompile(`(?i)\b(equals?|equal to|match(es|ing)?|identical(ly)?|the same |unchanged|verbatim|exact(ly)?|reflect(s|ing)?|round-?trip|escaped)\b`)},
	{ShapeValue, regexp.MustCompile(`(?i)\bMUST (be|carry|report|use|return|resolve to|remain|hold) (the|that|its|a value)\b`)},
	{ShapeValue, regexp.MustCompile(`(?i)\b(value|timestamp|time) of\b`)},
	{ShapeValue, regexp.MustCompile(`(?i)\b(no (later|earlier) than|at least|at most|within|greater than|less than|bounded)\b`)},
}

// InferShape reports a row's shape: the declared value when the row sets
// one, otherwise the first pattern that reads its behaviour as more than
// presence, otherwise presence.
func (r *Row) InferShape() Shape {
	if r.Shape != "" {
		return Shape(r.Shape)
	}
	for _, p := range shapePatterns {
		if p.re.MatchString(r.Behaviour) {
			return p.shape
		}
	}
	return ShapePresence
}

// Declared reports whether the row states its shape rather than leaving
// it to inference.
func (r *Row) ShapeDeclared() bool { return r.Shape != "" }

// FileShape is the row-shape profile of one feature file.
type FileShape struct {
	File     *FeatureFile
	Counts   map[Shape]int
	InScope  int
	Declared int
}

// NonPresence is the number of in-scope rows demanding more than that
// something appears.
func (f FileShape) NonPresence() int {
	return f.InScope - f.Counts[ShapePresence]
}

// Ratio is the share of in-scope rows that demand more than presence.
func (f FileShape) Ratio() float64 {
	if f.InScope == 0 {
		return 0
	}
	return float64(f.NonPresence()) / float64(f.InScope)
}

// shapeFloor is the minimum number of in-scope rows a file needs before
// the gate judges its profile. Below it the ratio says more about the
// file's size than about its rows.
const shapeFloor = 3

// profileFile computes one file's shape profile. Out-of-scope rows are
// excluded: they assert nothing, so counting them would let a file dilute
// its own profile by declaring rows out of scope.
func profileFile(f *FeatureFile) FileShape {
	out := FileShape{File: f, Counts: map[Shape]int{}}
	for _, r := range f.Rows {
		if r.EffectiveStatus() == "out-of-scope" {
			continue
		}
		out.InScope++
		out.Counts[r.InferShape()]++
		if r.ShapeDeclared() {
			out.Declared++
		}
	}
	return out
}

// Profile returns every feature file's shape profile, ordered by ratio
// so the thinnest files come first. A file at the top is the next one
// whose coverage number is least informative.
func Profile(c *Catalog) []FileShape {
	out := make([]FileShape, 0, len(c.Files))
	for _, f := range c.Files {
		out = append(out, profileFile(f))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Ratio() != out[j].Ratio() {
			return out[i].Ratio() < out[j].Ratio()
		}
		return out[i].File.Feature < out[j].File.Feature
	})
	return out
}

// ShapeViolation is a feature file whose rows say only that things
// appear.
type ShapeViolation struct {
	Feature string
	InScope int
}

// CheckShapes returns the files that state nothing beyond presence and
// have not recorded why that is right for them.
func CheckShapes(c *Catalog) []ShapeViolation {
	var out []ShapeViolation
	for _, p := range Profile(c) {
		if p.File.ShapeExemptReason != "" {
			continue
		}
		if p.InScope >= shapeFloor && p.NonPresence() == 0 {
			out = append(out, ShapeViolation{Feature: p.File.Feature, InScope: p.InScope})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Feature < out[j].Feature })
	return out
}

// checkStaleExemptions reports files that carry a shape exemption they
// have since outgrown, so the reason does not outlive the condition.
func checkStaleExemptions(c *Catalog) []string {
	var out []string
	for _, p := range Profile(c) {
		if p.File.ShapeExemptReason != "" && p.NonPresence() > 0 {
			out = append(out, p.File.Feature)
		}
	}
	sort.Strings(out)
	return out
}

// runShape prints the row-shape dashboard, and in check mode fails on a
// feature file that demands nothing but presence.
func runShape(dir, feature string, check bool) error {
	cat, err := loadCatalog(dir)
	if err != nil {
		return err
	}

	profiles := Profile(cat)
	if feature != "" {
		var narrowed []FileShape
		for _, p := range profiles {
			if p.File.Feature == feature {
				narrowed = append(narrowed, p)
			}
		}
		if len(narrowed) == 0 {
			return fmt.Errorf("shape: no catalog file named %q", feature)
		}
		profiles = narrowed
	}

	fmt.Print(renderShapeReport(profiles))

	if !check {
		return nil
	}
	problems := shapeProblems(cat)
	if len(problems) > 0 {
		fmt.Println()
		return &exitError{code: 1, message: "scenariotool shape:\n  " + strings.Join(problems, "\n  ")}
	}
	fmt.Printf("\nshape OK — %d catalog files, none presence-only\n", len(profiles))
	return nil
}

// renderShapeReport formats the per-file dashboard.
func renderShapeReport(profiles []FileShape) string {
	var b strings.Builder
	b.WriteString("Row shape by feature — what the rows demand, not how many have tests.\n")
	b.WriteString("A file made only of presence rows is satisfied by an implementation\n")
	b.WriteString("that emits the right claims with the wrong contents.\n\n")
	fmt.Fprintf(&b, "%-32s %7s %9s %6s %6s %9s %8s\n",
		"FEATURE", "IN-SCOPE", "PRESENCE", "VALUE", "ORDER", "IDENTITY", "NON-PRES")
	for _, p := range profiles {
		if p.InScope == 0 {
			continue
		}
		fmt.Fprintf(&b, "%-32s %7d %9d %6d %6d %9d %7.0f%%%s\n",
			p.File.Feature, p.InScope,
			p.Counts[ShapePresence], p.Counts[ShapeValue],
			p.Counts[ShapeOrder], p.Counts[ShapeIdentity],
			p.Ratio()*100, shapeMark(p))
	}
	return b.String()
}

// shapeMark annotates the rows a reader should look at first.
func shapeMark(p FileShape) string {
	switch {
	case p.File.ShapeExemptReason != "":
		return "  (exempt)"
	case p.NonPresence() == 0 && p.InScope >= shapeFloor:
		return "  <- presence only"
	default:
		return ""
	}
}

// shapeProblems renders the gate's failures, in both directions: a file
// that says nothing beyond presence, and an exemption that has outlived
// the condition it described.
func shapeProblems(cat *Catalog) []string {
	violations := CheckShapes(cat)
	problems := make([]string, 0, len(violations))
	for _, v := range violations {
		problems = append(problems, fmt.Sprintf(
			"catalog file %q has %d in-scope rows and not one of them demands a value, an order or an identity; "+
				"an implementation that emits every claim with the wrong contents satisfies the whole file. "+
				"Add a row that pins what the claim must equal, or record shape_exempt_reason",
			v.Feature, v.InScope,
		))
	}
	for _, f := range checkStaleExemptions(cat) {
		problems = append(problems, fmt.Sprintf(
			"catalog file %q records shape_exempt_reason but now has rows beyond presence; drop the exemption", f,
		))
	}
	return problems
}
