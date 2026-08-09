package hygiene_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// markerPatterns match the shapes internal working vocabulary takes
// when it reaches a source file. Each is deliberately narrow: the
// point is to separate process labels from ordinary English, so that
// a comment explaining an operator's remediation steps or citing an
// architecture decision in prose is left alone while a bare
// cross-reference to a working document is not.
//
// Anchoring on shape rather than on a word list is what makes the
// check survive. The labels themselves are invented per review round
// and cannot be enumerated in advance; their form is stable.
// checkerFile is this file, which is skipped: it states the patterns
// literally and would otherwise report itself.
const checkerFile = "internal_markers_test.go"

// processOnlyDirs hold material whose entire subject IS the
// development process — how work is split, reviewed and sequenced.
// A reference to a working document is meaningful there, and the rule
// this check enforces exempts internal-only artifacts for exactly that
// reason. The exemption is by directory rather than by file so it
// cannot creep: nothing under these paths is read by a consumer of the
// library, and nothing outside them gets the same latitude.
var processOnlyDirs = map[string]bool{
	".claude": true,
}

// scannedExtensions are the file kinds a marker can reach a reader
// through. Go source is the obvious one, but the rule is about what
// ships rather than about what compiles: a lint message naming a
// document the reader does not have is worse than a comment doing so,
// because the developer meets it as an instruction with no way to
// follow it.
var scannedExtensions = map[string]bool{
	".go":   true,
	".yml":  true,
	".yaml": true,
	".sh":   true,
	".md":   true,
}

// scannedFile reports whether path is a shipped text file the check
// reads. Makefiles carry no extension and are matched by name.
func scannedFile(path string) bool {
	base := filepath.Base(path)
	if base == "Makefile" || strings.HasSuffix(base, ".mk") {
		return true
	}
	return scannedExtensions[filepath.Ext(path)]
}

var markerPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{
		// Finding and work-item labels: two or more uppercase runs
		// joined by hyphens behind a single-letter class prefix, e.g.
		// a severity band followed by an area code.
		//
		// Only the hyphenated form is matched, which means comments
		// and not identifiers — a hyphen cannot appear in a Go name.
		// The underscore spelling an identifier would have to use is
		// deliberately NOT matched: it collides with TLS cipher-suite
		// constants, environment variable names, and wire tokens, at
		// roughly eighty sites in this repository, so a pattern
		// covering it would be turned off within a week. A label
		// reaching an identifier is caught only if it carries a
		// document number, by the pattern below.
		name: "finding label",
		re:   regexp.MustCompile(`\b[A-Z]-[A-Z]{2,}-[A-Z]{2,}\b`),
	},
	{
		// Numbered references to design documents that live outside
		// the repository, so the citation resolves to nothing for any
		// reader of a clone.
		//
		// No leading word boundary: the form that matters most is a
		// label welded into a camelCase identifier, where the letter
		// before it is a word character and a boundary would never
		// fire. The uppercase-plus-digits shape is specific enough to
		// carry the looser anchor.
		name: "numbered design-document reference",
		re:   regexp.MustCompile(`ADR[- ]?\d{3,}`),
	},
	{
		// Direct appeals to a review or audit as the authority for a
		// piece of code, rather than to the constraint itself.
		// Bounded to phrases that name a review as the authority.
		// A bare "review" is ordinary English and is not matched.
		name: "review-process reference",
		re:   regexp.MustCompile(`(?i)\b(audit finding|review finding|finding #\d|TODO from review)\b`),
	},
	{
		// Work-scheduling vocabulary. Bounded to a following number so
		// "the second phase of the handshake" and similar domain uses
		// do not trip it.
		name: "work-scheduling reference",
		re:   regexp.MustCompile(`(?i)\b(phase|wave|milestone|sprint|batch)[- ]\d+\b`),
	},
}

// TestNoInternalProcessMarkers fails when a shipped source file cites
// the process that produced it rather than the constraint it is
// meeting.
//
// The rule is not stylistic. A label like a finding id or a document
// number is meaningful only to whoever held the working notes, and
// those notes are not in the repository — so to every later reader the
// citation is an unresolvable pointer standing exactly where the
// reason should have been. The failure mode is quiet: the comment
// looks authoritative, nobody can check it, and the actual constraint
// goes unrecorded.
//
// Identifiers matter more than comments here. A comment can be read
// past; a test function or symbol carrying a document number puts the
// label into every failure message the suite ever prints.
//
// The fix is always the same shape: say what the code guarantees and
// why, and cite a specification by section where one applies. If a
// design document is the only source, name the constraint it states
// rather than the document.
func TestNoInternalProcessMarkers(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)

	var findings []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] || processOnlyDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !scannedFile(path) {
			return nil
		}
		// The file holding the patterns necessarily contains every
		// shape it looks for. Excluding it by name keeps the exclusion
		// one file wide, where a broader rule — skipping this package,
		// or ignoring lines that mention a pattern — would quietly
		// stop covering real code.
		if filepath.Base(path) == checkerFile {
			return nil
		}
		hits, ferr := internalMarkers(path)
		if ferr != nil {
			return ferr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		for _, h := range hits {
			findings = append(findings, fmt.Sprintf("%s:%d: %s %q", rel, h.line, h.kind, h.text))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	if len(findings) > 0 {
		t.Errorf("%d internal process marker(s) in shipped source.\n"+
			"These name the work that produced the code instead of the constraint it meets, "+
			"and they point at documents no reader of a clone has.\n"+
			"Rewrite each to state the guarantee and its reason; cite a specification section where one applies.\n\t%s",
			len(findings), strings.Join(findings, "\n\t"))
	}
}

// TestInternalMarkerPatternsDetect pins what the check can see.
//
// [TestNoInternalProcessMarkers] passes when the tree is clean, which
// is indistinguishable from passing because the patterns match
// nothing. This test removes that ambiguity: every pattern is
// exercised against a line it must catch, and against a line of
// ordinary prose it must not. Without it, a regexp broken by a later
// edit would leave a permanently green check that inspects nothing.
func TestInternalMarkerPatternsDetect(t *testing.T) {
	t.Parallel()

	caught := []struct {
		name string
		line string
	}{
		{"finding label", "// closes S-JOSE-CACHE for the encryption set"},
		{"document reference in an identifier", "func TestThing_PreservesADR0013(t *testing.T) {"},
		{"document reference", "// see ADR0013 for the rationale"},
		{"spaced document reference", "// ADR 0025 forbids coalescing"},
		{"audit reference", "// pins audit finding S-10's gate"},
		{"scheduling reference", "// deferred to phase 3"},
	}
	for _, tc := range caught {
		t.Run("catches "+tc.name, func(t *testing.T) {
			t.Parallel()
			if !matchesAnyPattern(tc.line) {
				t.Errorf("no pattern matched %q", tc.line)
			}
		})
	}

	ignored := []struct {
		name string
		line string
	}{
		{"operator remediation", "// the caller has no remediation other than rejecting"},
		{"design decisions in prose", "// this follows the architecture decision recorded for the store"},
		{"protocol phases", "// the second phase of the handshake carries the nonce"},
		{"a review mentioned in passing", "// worth a review if the cap ever changes"},
		{"batch as a domain noun", "// a recovery batch holds up to maxBatchSize slots"},
	}
	for _, tc := range ignored {
		t.Run("ignores "+tc.name, func(t *testing.T) {
			t.Parallel()
			if matchesAnyPattern(tc.line) {
				t.Errorf("a pattern matched ordinary prose: %q", tc.line)
			}
		})
	}
}

func matchesAnyPattern(line string) bool {
	for _, p := range markerPatterns {
		if p.re.MatchString(line) {
			return true
		}
	}
	return false
}

// marker is one match and where it was written.
type marker struct {
	kind string
	line int
	text string
}

// internalMarkers reports every process label in a Go file. The file
// is scanned as text rather than parsed, because the labels appear in
// comments and in identifiers alike and both have to be caught.
func internalMarkers(path string) ([]marker, error) {
	body, err := os.ReadFile(path) //nolint:gosec // walking the repository's own sources.
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var out []marker
	for i, line := range strings.Split(string(body), "\n") {
		for _, p := range markerPatterns {
			if m := p.re.FindString(line); m != "" {
				out = append(out, marker{kind: p.name, line: i + 1, text: m})
			}
		}
	}
	return out, nil
}
