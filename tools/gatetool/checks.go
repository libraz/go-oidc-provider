package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Finding is one way the declared map and the tree disagree.
type Finding struct {
	Check   string
	Message string
}

func (f Finding) String() string { return fmt.Sprintf("[%s] %s", f.Check, f.Message) }

// Check runs every drift check against the tree rooted at root and
// returns the findings in a stable order.
func Check(root string, m *Map) []Finding {
	out := make([]Finding, 0, len(m.Surfaces))
	out = append(out, checkSurfacePaths(root, m)...)
	out = append(out, checkMakefileTargets(root, m)...)
	out = append(out, checkExercised(m)...)
	return out
}

// checkSurfacePaths fails a surface whose declared paths no longer
// resolve. Without it the map degrades into prose about a tree that has
// moved on, which is the drift class the project already decided to
// solve by generating indexes rather than maintaining them.
func checkSurfacePaths(root string, m *Map) []Finding {
	var out []Finding
	for _, s := range m.Surfaces {
		for _, p := range resolvePaths(root, s.Paths) {
			out = append(out, Finding{
				Check:   "surface-paths",
				Message: fmt.Sprintf("surface %q declares path %q, which does not exist", s.ID, p),
			})
		}
	}
	return out
}

// targetLine matches a Makefile target definition. Pattern rules and
// variable assignments are excluded by requiring a plain name.
var targetLine = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9._-]*):(?:[^=]|$)`)

// parseMakefile returns every plain target in the Makefile, and the
// subset whose recipe invokes something under scripts/. The subset is
// what the map must account for: those are the commands that can report
// "the tree is broken". The full set is what a declared target is
// checked against, because a gate may run a bare command (`go vet`)
// rather than a script.
func parseMakefile(makefile string) (all, scripted map[string]bool, err error) {
	f, err := os.Open(makefile) //nolint:gosec // path is the repository Makefile, supplied by the gate wrapper.
	if err != nil {
		return nil, nil, fmt.Errorf("gatetool: open Makefile: %w", err)
	}
	defer func() { _ = f.Close() }()

	all = map[string]bool{}
	scripted = map[string]bool{}
	var current string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "\t") {
			if current != "" && strings.Contains(line, "scripts/") {
				scripted[current] = true
			}
			continue
		}
		if m := targetLine.FindStringSubmatch(line); m != nil {
			current = m[1]
			all[current] = true
			continue
		}
		if strings.TrimSpace(line) == "" {
			current = ""
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("gatetool: read Makefile: %w", err)
	}
	return all, scripted, nil
}

// checkMakefileTargets reconciles the map against the Makefile in both
// directions: a script-running target the map never mentions is an
// undeclared gate, and a declared target that no longer exists is a
// stale claim.
func checkMakefileTargets(root string, m *Map) []Finding {
	all, scripted, err := parseMakefile(filepath.Join(root, "Makefile"))
	if err != nil {
		return []Finding{{Check: "makefile", Message: err.Error()}}
	}

	declared := map[string]string{}
	for _, g := range m.Gates {
		if g.Target != "" {
			declared[g.Target] = "gate " + g.ID
		}
	}
	for _, n := range m.NonGates {
		declared[n.Target] = "non-gate"
	}

	var out []Finding
	for target := range scripted {
		if _, ok := declared[target]; !ok {
			out = append(out, Finding{
				Check: "makefile",
				Message: fmt.Sprintf("Makefile target %q runs a script but the map neither claims it as a gate "+
					"nor excuses it in non_gates — declare what it drives and what it is blind to", target),
			})
		}
	}
	for target, who := range declared {
		if !all[target] {
			out = append(out, Finding{
				Check:   "makefile",
				Message: fmt.Sprintf("%s names Makefile target %q, which the Makefile no longer defines", who, target),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Message < out[j].Message })
	return out
}

// checkExercised is the check this map exists for. A surface every gate
// reaches only statically is compiled, vetted and linted, and never run:
// a defect in it survives a fully green tree. Declaring
// static_only_reason is allowed, but it has to be written down.
func checkExercised(m *Map) []Finding {
	var out []Finding
	for _, c := range m.Coverage() {
		s := c.Surface
		deepest := c.Deepest()
		switch {
		case deepest == "" && s.StaticOnlyReason == "":
			out = append(out, Finding{
				Check:   "unexercised",
				Message: fmt.Sprintf("surface %q is driven by no gate at all", s.ID),
			})
		case deepest == LevelStatic && s.StaticOnlyReason == "":
			out = append(out, Finding{
				Check: "unexercised",
				Message: fmt.Sprintf("surface %q is only reached by static-level gates, so nothing runs it; "+
					"wire a unit or integration gate, or record static_only_reason", s.ID),
			})
		case deepest != "" && deepest != LevelStatic && s.StaticOnlyReason != "":
			out = append(out, Finding{
				Check: "unexercised",
				Message: fmt.Sprintf("surface %q records static_only_reason but is now driven at %s level; "+
					"drop the exemption", s.ID, deepest),
			})
		}
	}
	return out
}
