package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Catalog is the union of every feature file in a catalog directory.
type Catalog struct {
	Files []*FeatureFile
	byID  map[string]*Row
}

// FeatureFile mirrors the on-disk YAML shape of one
// test/scenarios/catalog/<feature>.yaml file.
type FeatureFile struct {
	Path        string   `yaml:"-"`
	Feature     string   `yaml:"feature"`
	Prefix      string   `yaml:"prefix"`
	Title       string   `yaml:"title"`
	Specs       []string `yaml:"specs"`
	Description string   `yaml:"description,omitempty"`

	// ShapeExemptReason records why this file is right to demand only
	// that things appear. It is the escape hatch for the shape gate, and
	// it is deliberately a sentence rather than a boolean: a file whose
	// rows can never pin a value should be able to say so, and a reader
	// should be able to disagree.
	ShapeExemptReason string `yaml:"shape_exempt_reason,omitempty"`

	Rows []*Row `yaml:"rows"`
}

// Row mirrors one entry under FeatureFile.Rows.
type Row struct {
	ID        string `yaml:"id"`
	Severity  string `yaml:"severity"`
	Spec      string `yaml:"spec"`
	Behaviour string `yaml:"behaviour"`
	Status    string `yaml:"status,omitempty"`
	// CoveredBy names the test that asserts this row when the assertion
	// cannot live in the scenario suite — a construction-time rejection
	// the black-box harness never observes, a clock the flow harness
	// does not seat. Format: "<package path>.<TestFunc>", e.g.
	// "internal/authorizeendpoint.TestAuthorize_MaxAgeViolation". The
	// coverage gate resolves it against `go test -list`, so a rename or
	// deletion on the other side fails the build instead of quietly
	// leaving the row asserted by nothing.
	CoveredBy        string   `yaml:"covered_by,omitempty"`
	CrossRefs        []string `yaml:"cross_refs,omitempty"`
	Notes            string   `yaml:"notes,omitempty"`
	OutOfScopeReason string   `yaml:"out_of_scope_reason,omitempty"`

	// Shape declares what the row demands — presence, value, order or
	// identity. It is optional: the shape gate infers a shape from the
	// behaviour text and only ever infers *upward*, out of presence, so
	// leaving it empty is safe. Set it when the prose does not read the
	// way the inference expects, or when the row's shape is the point
	// being made. See shape.go.
	Shape string `yaml:"shape,omitempty"`

	// File is the parent feature file; populated post-parse for
	// reverse-lookup convenience.
	File *FeatureFile `yaml:"-"`
}

// EffectiveStatus returns the row's declared status, defaulting to
// "pending" when the field is empty.
func (r *Row) EffectiveStatus() string {
	if r.Status == "" {
		return "pending"
	}
	return r.Status
}

// loadCatalog reads every <feature>.yaml file under dir and returns a
// fully populated Catalog. Per-file structural problems (unparseable
// YAML, missing required keys) surface as errors here; cross-file
// constraints are checked by Catalog.Validate.
func loadCatalog(dir string) (*Catalog, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read catalog dir %q: %w", dir, err)
	}
	cat := &Catalog{byID: make(map[string]*Row)}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		// Files starting with `_` are reserved for catalog-adjacent
		// inventories that share the directory but not the FeatureFile
		// shape (e.g. `_advisories.yaml`). They are loaded by their
		// owning subcommand directly.
		if strings.HasPrefix(e.Name(), "_") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		ff, err := loadFeatureFile(path)
		if err != nil {
			return nil, err
		}
		cat.Files = append(cat.Files, ff)
		for _, r := range ff.Rows {
			r.File = ff
			cat.byID[r.ID] = r
		}
	}
	sort.Slice(cat.Files, func(i, j int) bool { return cat.Files[i].Feature < cat.Files[j].Feature })
	return cat, nil
}

// loadFeatureFile parses one catalog file into a FeatureFile.
func loadFeatureFile(path string) (*FeatureFile, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is supplied by the operator inside the catalog tree.
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var ff FeatureFile
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // typo guard
	if err := dec.Decode(&ff); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	ff.Path = path
	return &ff, nil
}

// AllRows returns every row across every file in stable order.
func (c *Catalog) AllRows() []*Row {
	out := make([]*Row, 0, len(c.byID))
	for _, ff := range c.Files {
		out = append(out, ff.Rows...)
	}
	return out
}

// Lookup returns the row with the given ID or nil.
func (c *Catalog) Lookup(id string) *Row {
	return c.byID[id]
}

// rowIDPattern is the regex the schema imposes on row.id.
var rowIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]+(-[A-Z][A-Z0-9]+)*-[0-9]+$`)

// crossRefPattern matches "<feature>#<ID>".
var crossRefPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*#[A-Z][A-Z0-9]+(-[A-Z][A-Z0-9]+)*-[0-9]+$`)

// coveredByPattern matches "<package path>.<TestFunc>". The package is
// written relative to the module root, exactly as it would be passed to
// `go test`; the function must be a Test or Fuzz entry point, because
// those are the only names `go test -list` can resolve.
var coveredByPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:/[a-z0-9_]+)*\.(?:Test|Fuzz)[A-Za-z0-9_]*$`)

// featurePattern guards file-level feature slugs.
var featurePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// prefixPattern guards file-level prefixes.
var prefixPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]+$`)

// validSeverities enumerates the allowed `severity` values.
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var validSeverities = map[string]bool{"P0": true, "P1": true, "P2": true}

// validStatuses enumerates the allowed `status` values.
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var validStatuses = map[string]bool{"active": true, "pending": true, "out-of-scope": true}

// ValidationOptions tunes Catalog.Validate.
type ValidationOptions struct {
	// LenientCrossRefs downgrades unresolved cross_refs from errors to
	// warnings printed on stderr. Used during partial migration when
	// not every feature file is in place yet.
	LenientCrossRefs bool

	// SourceRoot is the repository root scanned for Go declarations so
	// prose citations of the form `package.Symbol` can be resolved.
	// Callers that have a tree to check against pass its root; the ones
	// that do not set SkipSymbolCitations instead.
	SourceRoot string

	// SkipSymbolCitations turns the citation check off for a caller with
	// no tree to resolve against — `flip`, which re-reads what it just
	// wrote, and the structural tests.
	//
	// It exists so that decision has to be spelled. An empty SourceRoot
	// alone used to mean the same thing, which made "this caller has no
	// tree" and "this caller lost its root" the same input: the second
	// silently disabled the check and left the validator reporting a
	// catalog it had not resolved a single citation in.
	SkipSymbolCitations bool
}

// Validate runs structural + cross-file checks. The returned error
// aggregates every failure so the operator sees them all at once.
//
// The invariants are grouped one helper per rule family; each helper
// returns the problems it found rather than failing fast, because a
// catalog with five mistakes has to be fixable in one pass.
func (c *Catalog) Validate(opts ValidationOptions) error {
	problems := c.validateFiles()

	dangling := c.unresolvedCrossRefs()
	if opts.LenientCrossRefs {
		warnDanglingCrossRefs(dangling)
	} else {
		problems = append(problems, dangling...)
	}

	// Prose citations are checked the same way covered_by is: by
	// resolving them against the other side rather than trusting the
	// sentence. A citation that no longer names anything is how an
	// out-of-scope claim stops being auditable.
	citations, err := c.symbolCitationProblems(opts)
	if err != nil {
		return err
	}
	problems = append(problems, citations...)

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("catalog validation failed (%d issue(s)):\n  %s",
		len(problems), strings.Join(problems, "\n  "))
}

// symbolCitationProblems resolves the catalog's prose citations against
// the tree named by opts, or reports why it cannot.
//
// The two ways the check can end up resolving nothing are refused
// rather than skipped, because both read out as a clean catalog: a
// caller that supplied no root without saying it meant to, and a root
// whose scan found no declarations at all. Skipping is available, but
// only to a caller that asks for it in as many words.
func (c *Catalog) symbolCitationProblems(opts ValidationOptions) ([]string, error) {
	switch {
	case opts.SkipSymbolCitations && opts.SourceRoot != "":
		return nil, errors.New("SkipSymbolCitations and SourceRoot are mutually exclusive: " +
			"a caller either has a tree to resolve citations against or it does not")
	case opts.SkipSymbolCitations:
		return nil, nil
	case opts.SourceRoot == "":
		return nil, errors.New("no SourceRoot: the citation check has no tree to resolve against, " +
			"so every row would be reported clean unresolved (set SkipSymbolCitations to disable it deliberately)")
	}
	ix, err := buildSymbolIndex(opts.SourceRoot)
	if err != nil {
		return nil, err
	}
	if err := checkSymbolIndexReachedSources(opts.SourceRoot, ix); err != nil {
		return nil, err
	}
	return c.unresolvedSymbolCitations(ix), nil
}

// validateFiles walks every feature file and every row in it, carrying
// the two catalog-wide indexes (prefix and row ID) that make uniqueness
// checkable across files rather than only within one.
func (c *Catalog) validateFiles() []string {
	var problems []string
	seenPrefix := map[string]string{} // prefix -> first-seen path
	seenID := map[string]string{}     // id -> first-seen path

	for _, ff := range c.Files {
		problems = append(problems, validateFeature(ff)...)
		problems = append(problems, validatePrefix(ff, seenPrefix)...)
		problems = append(problems, validateFileMetadata(ff)...)
		for i, r := range ff.Rows {
			where := fmt.Sprintf("%s rows[%d] (%s)", ff.Path, i, r.ID)
			problems = append(problems, validateRow(where, ff, r, seenID)...)
		}
	}
	return problems
}

// validateFeature enforces the feature-identity invariant: every file
// declares a slug, the slug is a lowercase identifier, and it equals the
// filename. Feature slugs address files from cross_refs and from the
// `list` / `next` subcommands, so a slug that disagrees with its
// filename makes a file reachable under a name it does not have.
func validateFeature(ff *FeatureFile) []string {
	base := strings.TrimSuffix(filepath.Base(ff.Path), ".yaml")
	switch {
	case ff.Feature == "":
		return []string{ff.Path + ": missing required field 'feature'"}
	case !featurePattern.MatchString(ff.Feature):
		return []string{fmt.Sprintf("%s: feature %q must match %s", ff.Path, ff.Feature, featurePattern)}
	case ff.Feature != base:
		return []string{fmt.Sprintf("%s: feature %q must equal filename %q", ff.Path, ff.Feature, base)}
	}
	return nil
}

// validatePrefix enforces the prefix invariant: every file declares an
// uppercase prefix and no two files share one. The prefix is what makes
// row IDs unique by construction, so a collision would let two features
// mint the same ID and silently overwrite each other in the index.
// seenPrefix accumulates the first file to claim each prefix.
func validatePrefix(ff *FeatureFile, seenPrefix map[string]string) []string {
	switch {
	case ff.Prefix == "":
		return []string{ff.Path + ": missing required field 'prefix'"}
	case !prefixPattern.MatchString(ff.Prefix):
		return []string{fmt.Sprintf("%s: prefix %q must match %s", ff.Path, ff.Prefix, prefixPattern)}
	}
	if prev, dup := seenPrefix[ff.Prefix]; dup {
		return []string{fmt.Sprintf("%s: prefix %q already used by %s", ff.Path, ff.Prefix, prev)}
	}
	seenPrefix[ff.Prefix] = ff.Path
	return nil
}

// validateFileMetadata enforces that a feature file carries the context
// a reader needs to act on its rows: a human title, at least one spec it
// derives from, and at least one row. An empty file is indistinguishable
// from a forgotten one once the counts are summed.
func validateFileMetadata(ff *FeatureFile) []string {
	var problems []string
	if ff.Title == "" {
		problems = append(problems, ff.Path+": missing required field 'title'")
	}
	if len(ff.Specs) == 0 {
		problems = append(problems, ff.Path+": 'specs' MUST have at least one entry")
	}
	if len(ff.Rows) == 0 {
		problems = append(problems, ff.Path+": 'rows' MUST have at least one entry")
	}
	return problems
}

// validateRow runs every row-scoped rule family. where is the
// "<path> rows[<i>] (<id>)" location prefix shared by all of them.
func validateRow(where string, ff *FeatureFile, r *Row, seenID map[string]string) []string {
	problems := validateRowID(where, ff, r, seenID)
	problems = append(problems, validateRowContent(where, r)...)
	problems = append(problems, validateRowStatus(where, r)...)
	problems = append(problems, validateRowCoveredBy(where, r)...)
	problems = append(problems, validateRowCrossRefSyntax(where, r)...)
	return problems
}

// validateRowID enforces the row-identity invariant: the ID exists,
// matches the schema shape, carries its file's prefix, and is unique
// across the whole catalog. Everything downstream — cross_refs, the
// Test_<PREFIX>_<NNN>_ binding, the flip subcommand — addresses a row by
// this ID, so a duplicate makes one of the two rows unaddressable.
// seenID accumulates the first file to declare each ID.
func validateRowID(where string, ff *FeatureFile, r *Row, seenID map[string]string) []string {
	switch {
	case r.ID == "":
		return []string{where + ": missing 'id'"}
	case !rowIDPattern.MatchString(r.ID):
		return []string{fmt.Sprintf("%s: id %q must match %s", where, r.ID, rowIDPattern)}
	case ff.Prefix != "" && !strings.HasPrefix(r.ID, ff.Prefix+"-"):
		return []string{fmt.Sprintf("%s: id %q must start with file prefix %q", where, r.ID, ff.Prefix+"-")}
	}
	if prev, dup := seenID[r.ID]; dup {
		return []string{fmt.Sprintf("%s: id %q already declared in %s", where, r.ID, prev)}
	}
	seenID[r.ID] = ff.Path
	return nil
}

// validateRowContent enforces that a row says what it is about: a
// severity the dashboards can bucket, the spec clause it derives from,
// and the behaviour a test is supposed to assert. A row missing any of
// the three cannot be turned into a test by anyone but its author.
func validateRowContent(where string, r *Row) []string {
	var problems []string
	if !validSeverities[r.Severity] {
		problems = append(problems, fmt.Sprintf("%s: severity %q must be one of P0|P1|P2", where, r.Severity))
	}
	if strings.TrimSpace(r.Spec) == "" {
		problems = append(problems, where+": 'spec' MUST be non-empty")
	}
	if strings.TrimSpace(r.Behaviour) == "" {
		problems = append(problems, where+": 'behaviour' MUST be non-empty")
	}
	// The field is optional — the shape gate infers one when it is
	// absent — but a misspelled value would be read as its own shape
	// and quietly change what the file's profile says.
	if r.Shape != "" && !validShapes[Shape(r.Shape)] {
		problems = append(problems, fmt.Sprintf(
			"%s: shape %q must be one of presence|value|order|identity", where, r.Shape,
		))
	}
	return problems
}

// validateRowStatus enforces the status enum and its coupling with
// out_of_scope_reason. Declaring a behaviour unreachable is the one way
// to remove it from the coverage denominator, so it always has to carry
// the reason that justifies the exclusion — and a reason left behind on
// a row that came back in scope would document an exclusion that no
// longer applies.
func validateRowStatus(where string, r *Row) []string {
	var problems []string
	status := r.EffectiveStatus()
	if !validStatuses[status] {
		problems = append(problems, fmt.Sprintf("%s: status %q must be active|pending|out-of-scope", where, r.Status))
	}
	if status == "out-of-scope" && strings.TrimSpace(r.OutOfScopeReason) == "" {
		problems = append(problems, where+": status=out-of-scope requires 'out_of_scope_reason'")
	}
	if status != "out-of-scope" && r.OutOfScopeReason != "" {
		problems = append(problems, where+": 'out_of_scope_reason' is only valid when status=out-of-scope")
	}
	return problems
}

// validateRowCoveredBy enforces the delegation invariant. covered_by
// names the test that asserts a row from outside the scenario suite, and
// the coverage gate resolves it with `go test -list`; a value that is
// not "<package path>.<TestFunc>" cannot be resolved at all, so the row
// would be counted as covered by a claim nothing checks.
func validateRowCoveredBy(where string, r *Row) []string {
	if r.CoveredBy == "" {
		return nil
	}
	var problems []string
	if !coveredByPattern.MatchString(r.CoveredBy) {
		problems = append(problems, fmt.Sprintf(
			"%s: covered_by %q must be <package path>.<TestFunc>, e.g. internal/authorizeendpoint.TestAuthorize_MaxAge",
			where, r.CoveredBy,
		))
	}
	// A row is either covered or it is not. Naming the test that covers
	// a pending row, or one declared unreachable, states two
	// incompatible things at once.
	if status := r.EffectiveStatus(); status != "active" {
		problems = append(problems, fmt.Sprintf("%s: covered_by is only valid when status=active (row is %s)", where, status))
	}
	return problems
}

// validateRowCrossRefSyntax enforces the "<feature>#<ID>" shape of every
// cross_ref. Only the shape is checked here; whether the target exists
// needs the whole ID index and is settled by unresolvedCrossRefs.
func validateRowCrossRefSyntax(where string, r *Row) []string {
	var problems []string
	for j, ref := range r.CrossRefs {
		if !crossRefPattern.MatchString(ref) {
			problems = append(problems, fmt.Sprintf("%s: cross_refs[%d]=%q must match <feature>#<ID>", where, j, ref))
		}
	}
	return problems
}

// unresolvedCrossRefs enforces cross-reference existence, the one
// invariant that needs the fully populated ID index and so runs as a
// second pass. A cross_ref pointing at an ID nobody declares is a link
// into a row that was renamed or never written; left unchecked it reads
// like a real relationship. Syntactically malformed refs are skipped
// because validateRowCrossRefSyntax already reported them.
func (c *Catalog) unresolvedCrossRefs() []string {
	var dangling []string
	for _, r := range c.AllRows() {
		for _, ref := range r.CrossRefs {
			parts := strings.SplitN(ref, "#", 2)
			if len(parts) != 2 {
				continue
			}
			if c.Lookup(parts[1]) != nil {
				continue
			}
			dangling = append(dangling, fmt.Sprintf("%s rows (%s): cross_ref %q points at unknown ID",
				r.File.Path, r.ID, ref))
		}
	}
	return dangling
}

// warnDanglingCrossRefs prints the tolerated dangling references to
// stderr so a lenient run still shows what it let through.
func warnDanglingCrossRefs(dangling []string) {
	if len(dangling) == 0 {
		return
	}
	sort.Strings(dangling)
	fmt.Fprintf(os.Stderr, "scenariotool: %d dangling cross_ref(s) tolerated under --lenient:\n  %s\n",
		len(dangling), strings.Join(dangling, "\n  "))
}
