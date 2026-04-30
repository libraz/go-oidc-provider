package main

import (
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
	Rows        []*Row   `yaml:"rows"`
}

// Row mirrors one entry under FeatureFile.Rows.
type Row struct {
	ID               string   `yaml:"id"`
	Severity         string   `yaml:"severity"`
	Spec             string   `yaml:"spec"`
	Behaviour        string   `yaml:"behaviour"`
	Status           string   `yaml:"status,omitempty"`
	CrossRefs        []string `yaml:"cross_refs,omitempty"`
	Notes            string   `yaml:"notes,omitempty"`
	OutOfScopeReason string   `yaml:"out_of_scope_reason,omitempty"`

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

// featurePattern guards file-level feature slugs.
var featurePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// prefixPattern guards file-level prefixes.
var prefixPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]+$`)

// validSeverities enumerates the allowed `severity` values.
var validSeverities = map[string]bool{"P0": true, "P1": true, "P2": true}

// validStatuses enumerates the allowed `status` values.
var validStatuses = map[string]bool{"active": true, "pending": true, "out-of-scope": true}

// ValidationOptions tunes Catalog.Validate.
type ValidationOptions struct {
	// LenientCrossRefs downgrades unresolved cross_refs from errors to
	// warnings printed on stderr. Used during partial migration when
	// not every feature file is in place yet.
	LenientCrossRefs bool
}

// Validate runs structural + cross-file checks. The returned error
// aggregates every failure so the operator sees them all at once.
func (c *Catalog) Validate(opts ValidationOptions) error {
	var problems []string
	report := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	seenPrefix := map[string]string{} // prefix -> first-seen path
	seenID := map[string]string{}     // id -> first-seen path

	for _, ff := range c.Files {
		base := strings.TrimSuffix(filepath.Base(ff.Path), ".yaml")

		switch {
		case ff.Feature == "":
			report("%s: missing required field 'feature'", ff.Path)
		case !featurePattern.MatchString(ff.Feature):
			report("%s: feature %q must match %s", ff.Path, ff.Feature, featurePattern)
		case ff.Feature != base:
			report("%s: feature %q must equal filename %q", ff.Path, ff.Feature, base)
		}

		switch {
		case ff.Prefix == "":
			report("%s: missing required field 'prefix'", ff.Path)
		case !prefixPattern.MatchString(ff.Prefix):
			report("%s: prefix %q must match %s", ff.Path, ff.Prefix, prefixPattern)
		default:
			if prev, dup := seenPrefix[ff.Prefix]; dup {
				report("%s: prefix %q already used by %s", ff.Path, ff.Prefix, prev)
			} else {
				seenPrefix[ff.Prefix] = ff.Path
			}
		}

		if ff.Title == "" {
			report("%s: missing required field 'title'", ff.Path)
		}
		if len(ff.Specs) == 0 {
			report("%s: 'specs' MUST have at least one entry", ff.Path)
		}
		if len(ff.Rows) == 0 {
			report("%s: 'rows' MUST have at least one entry", ff.Path)
		}

		for i, r := range ff.Rows {
			where := fmt.Sprintf("%s rows[%d] (%s)", ff.Path, i, r.ID)

			switch {
			case r.ID == "":
				report("%s: missing 'id'", where)
			case !rowIDPattern.MatchString(r.ID):
				report("%s: id %q must match %s", where, r.ID, rowIDPattern)
			case ff.Prefix != "" && !strings.HasPrefix(r.ID, ff.Prefix+"-"):
				report("%s: id %q must start with file prefix %q", where, r.ID, ff.Prefix+"-")
			default:
				if prev, dup := seenID[r.ID]; dup {
					report("%s: id %q already declared in %s", where, r.ID, prev)
				} else {
					seenID[r.ID] = ff.Path
				}
			}

			if !validSeverities[r.Severity] {
				report("%s: severity %q must be one of P0|P1|P2", where, r.Severity)
			}
			if strings.TrimSpace(r.Spec) == "" {
				report("%s: 'spec' MUST be non-empty", where)
			}
			if strings.TrimSpace(r.Behaviour) == "" {
				report("%s: 'behaviour' MUST be non-empty", where)
			}
			status := r.EffectiveStatus()
			if !validStatuses[status] {
				report("%s: status %q must be active|pending|out-of-scope", where, r.Status)
			}
			if status == "out-of-scope" && strings.TrimSpace(r.OutOfScopeReason) == "" {
				report("%s: status=out-of-scope requires 'out_of_scope_reason'", where)
			}
			if status != "out-of-scope" && r.OutOfScopeReason != "" {
				report("%s: 'out_of_scope_reason' is only valid when status=out-of-scope", where)
			}
			for j, ref := range r.CrossRefs {
				if !crossRefPattern.MatchString(ref) {
					report("%s: cross_refs[%d]=%q must match <feature>#<ID>", where, j, ref)
				}
			}
		}
	}

	// Cross-ref existence check (second pass — needs full ID index).
	var dangling []string
	for _, r := range c.AllRows() {
		for _, ref := range r.CrossRefs {
			parts := strings.SplitN(ref, "#", 2)
			if len(parts) != 2 {
				continue // already reported by syntactic pass
			}
			if c.Lookup(parts[1]) != nil {
				continue
			}
			msg := fmt.Sprintf("%s rows (%s): cross_ref %q points at unknown ID",
				r.File.Path, r.ID, ref)
			if opts.LenientCrossRefs {
				dangling = append(dangling, msg)
			} else {
				problems = append(problems, msg)
			}
		}
	}

	if opts.LenientCrossRefs && len(dangling) > 0 {
		sort.Strings(dangling)
		fmt.Fprintf(os.Stderr, "scenariotool: %d dangling cross_ref(s) tolerated under --lenient:\n  %s\n",
			len(dangling), strings.Join(dangling, "\n  "))
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("catalog validation failed (%d issue(s)):\n  %s",
		len(problems), strings.Join(problems, "\n  "))
}
