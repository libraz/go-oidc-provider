package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Level records how deeply a gate exercises the surfaces it drives. The
// distinction is the whole point of the map: a surface reached only by
// static-level gates compiles, parses and lints, but nothing ever runs
// it, so a defect in it is invisible to every gate that claims it.
type Level string

const (
	// LevelStatic means the gate reads or compiles the surface without
	// executing it: formatters, vet, lint, and the parser-based gates.
	LevelStatic Level = "static"

	// LevelUnit means the gate runs the surface in-process, against the
	// in-memory reference store and an httptest server.
	LevelUnit Level = "unit"

	// LevelIntegration means the gate drives the surface as a deployed
	// artifact: a booted example process, a real browser, a real storage
	// backend, or the external conformance suite.
	LevelIntegration Level = "integration"
)

// levelRank orders the levels so a surface's strongest coverage can be
// reported. Higher is deeper.
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var levelRank = map[Level]int{LevelStatic: 1, LevelUnit: 2, LevelIntegration: 3}

// Map is the whole gate topology: which gates exist, which surfaces the
// project ships, and which gates actually drive which surface.
//
// It is the source of truth for api/gates.md. Nothing here is inferred
// from the tree — the tree is what the checks compare the claims to.
type Map struct {
	// Surfaces are the shipped areas a defect can live in.
	Surfaces []*Surface `yaml:"surfaces"`

	// Gates are the verification commands the project runs.
	Gates []*Gate `yaml:"gates"`

	// NonGates names Makefile targets that invoke a script but are not
	// verification gates (installers, formatters that rewrite, service
	// lifecycle helpers). Listing one is a claim that it can never fail
	// in a way that means "the tree is broken".
	NonGates []*NonGate `yaml:"non_gates"`

	bySurface map[string]*Surface
}

// Surface is one shipped area of the system.
type Surface struct {
	// ID is the stable identifier gates reference in their drives list.
	ID string `yaml:"id"`

	// Title is the human name used in the rendered matrix.
	Title string `yaml:"title"`

	// Paths are repository-relative files or directories that make up
	// the surface. Each entry must resolve, so a surface that moved
	// fails the gate rather than silently describing nothing.
	Paths []string `yaml:"paths"`

	// StaticOnlyReason, when set, declares that this surface is
	// deliberately covered by static-level gates alone. An empty value
	// means the surface must be driven by at least one gate that runs
	// it. This is the field that would have had to be written — and
	// defended — for the multi-account chooser path.
	StaticOnlyReason string `yaml:"static_only_reason,omitempty"`
}

// Gate is one verification command.
type Gate struct {
	// ID is the stable identifier used in the rendered matrix.
	ID string `yaml:"id"`

	// Target is the Makefile target that runs the gate, or the empty
	// string for a gate that only runs as a step inside another one
	// (the format checks inside scripts/verify.sh, for example).
	Target string `yaml:"target,omitempty"`

	// InVerify reports whether `make verify` runs this gate. A gate
	// outside verify is one a developer has to remember, which is how
	// the example harnesses went months without catching a live defect.
	InVerify bool `yaml:"in_verify"`

	// Answers states the question the gate actually answers, in one
	// line. It is deliberately narrow: the failure this map exists to
	// prevent is reading a green gate as a broader claim than it makes.
	Answers string `yaml:"answers"`

	// BlindTo lists classes of defect the gate cannot see by
	// construction. Not a wish list — each entry should be something
	// that has been reasoned about or observed.
	BlindTo []string `yaml:"blind_to"`

	// Level is how deeply the gate exercises what it drives.
	Level Level `yaml:"level"`

	// Drives names the surfaces this gate exercises.
	Drives []string `yaml:"drives"`
}

// NonGate is a Makefile target deliberately excluded from the map.
type NonGate struct {
	// Target is the Makefile target name.
	Target string `yaml:"target"`

	// Reason says why the target cannot report "the tree is broken".
	Reason string `yaml:"reason"`
}

// Load reads and structurally validates the map at path. Structural
// validation covers everything checkable without the tree: required
// fields, unique IDs, known levels, and drives entries that name a
// declared surface.
func Load(path string) (*Map, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is the checked-in gate map, supplied by the gate wrapper.
	if err != nil {
		return nil, fmt.Errorf("gatetool: read %s: %w", path, err)
	}
	var m Map
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("gatetool: parse %s: %w", path, err)
	}
	if err := m.index(); err != nil {
		return nil, err
	}
	return &m, nil
}

// index builds the surface lookup and rejects a map that cannot be
// interpreted at all.
func (m *Map) index() error {
	errs := m.indexSurfaces()
	errs = append(errs, m.checkGates()...)
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("gatetool: %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// indexSurfaces populates the surface lookup and reports the surfaces
// that cannot be interpreted.
func (m *Map) indexSurfaces() []string {
	m.bySurface = make(map[string]*Surface, len(m.Surfaces))
	var errs []string
	for _, s := range m.Surfaces {
		switch {
		case s.ID == "":
			errs = append(errs, "a surface has no id")
			continue
		case s.Title == "":
			errs = append(errs, fmt.Sprintf("surface %q has no title", s.ID))
		case len(s.Paths) == 0:
			errs = append(errs, fmt.Sprintf("surface %q lists no paths", s.ID))
		}
		if _, dup := m.bySurface[s.ID]; dup {
			errs = append(errs, fmt.Sprintf("surface %q is declared twice", s.ID))
			continue
		}
		m.bySurface[s.ID] = s
	}
	return errs
}

// checkGates reports the gates that cannot be interpreted, including a
// drives entry naming no declared surface — a typo there would silently
// shrink what the map claims to cover.
func (m *Map) checkGates() []string {
	var errs []string
	seen := map[string]bool{}
	for _, g := range m.Gates {
		switch {
		case g.ID == "":
			errs = append(errs, "a gate has no id")
			continue
		case g.Answers == "":
			errs = append(errs, fmt.Sprintf("gate %q does not say what it answers", g.ID))
		case len(g.Drives) == 0:
			errs = append(errs, fmt.Sprintf("gate %q drives no surface", g.ID))
		}
		if seen[g.ID] {
			errs = append(errs, fmt.Sprintf("gate %q is declared twice", g.ID))
		}
		seen[g.ID] = true
		if _, ok := levelRank[g.Level]; !ok {
			errs = append(errs, fmt.Sprintf("gate %q has unknown level %q", g.ID, g.Level))
		}
		for _, id := range g.Drives {
			if _, ok := m.bySurface[id]; !ok {
				errs = append(errs, fmt.Sprintf("gate %q drives undeclared surface %q", g.ID, id))
			}
		}
	}
	return errs
}

// Coverage is the set of gates that drive one surface, grouped so the
// caller can ask the only question that matters: does anything actually
// run this?
type Coverage struct {
	Surface *Surface
	Gates   []*Gate
}

// Deepest reports the strongest level any gate reaches this surface at,
// or the empty string when no gate drives it at all.
func (c Coverage) Deepest() Level {
	var best Level
	for _, g := range c.Gates {
		if levelRank[g.Level] > levelRank[best] {
			best = g.Level
		}
	}
	return best
}

// Coverage returns per-surface coverage in declaration order.
func (m *Map) Coverage() []Coverage {
	byID := map[string][]*Gate{}
	for _, g := range m.Gates {
		for _, id := range g.Drives {
			byID[id] = append(byID[id], g)
		}
	}
	out := make([]Coverage, 0, len(m.Surfaces))
	for _, s := range m.Surfaces {
		out = append(out, Coverage{Surface: s, Gates: byID[s.ID]})
	}
	return out
}

// resolvePaths reports which of a surface's declared paths do not exist
// under root. A path may be a file, a directory, or a glob.
func resolvePaths(root string, paths []string) []string {
	var missing []string
	for _, p := range paths {
		full := filepath.Join(root, filepath.FromSlash(p))
		if strings.ContainsAny(p, "*?[") {
			matches, err := filepath.Glob(full)
			if err != nil || len(matches) == 0 {
				missing = append(missing, p)
			}
			continue
		}
		if _, err := os.Stat(full); err != nil {
			missing = append(missing, p)
		}
	}
	return missing
}
