package inmem

import (
	"context"
	"go/parser"
	"go/token"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// The package doc's Reclamation section is the only statement of which
// substores give their rows back and by what route. Nothing in the
// implementation points at it, so it can go stale the moment a substore
// is added, loses its sweep, or grows a second map. The tests in this
// file are that pointer: they enumerate the maps whose contents expire
// straight out of the type declarations and hold the section to them.
//
// gc_bounds_internal_test.go asserts that an individual substore stops
// retaining dead records. It cannot notice a substore nobody wrote a
// bound test for, which is exactly the drift this file catches.

// reclamationClass is the treatment the Reclamation section files a
// substore map under.
type reclamationClass int

const (
	// classSwept is a map the substore sweeps itself on an amortised
	// interval, because an unauthenticated request can grow it.
	classSwept reclamationClass = iota

	// classOperatorGC is a map reclaimed on a cutoff the embedder passes
	// to the substore's GC method rather than by a sweep of its own.
	classOperatorGC

	// classKeyBounded is a map that carries an expiry and is reclaimed by
	// neither route, because its key space is what bounds it.
	classKeyBounded

	// classRetained is a map whose rows outlive their own expiry on
	// purpose.
	classRetained
)

// reclamationEntry is one map's filing: the class it belongs to and the
// wording the Reclamation section uses for it.
type reclamationEntry struct {
	class  reclamationClass
	phrase string
}

// reclamationDoc mirrors the Reclamation section, keyed by
// "<Store field>.<map field>". [TestReclamationDocCoversEveryExpiringMap]
// pins the key set against the declarations, so an entry cannot be
// quietly dropped and a new expiring map cannot be quietly added.
var reclamationDoc = map[string]reclamationEntry{
	"authCodes.m":                 {classSwept, "authorization codes"},
	"sessions.m":                  {classSwept, "sessions"},
	"interactions.m":              {classSwept, "interactions"},
	"pars.m":                      {classSwept, "PAR records"},
	"jtis.m":                      {classSwept, "consumed JTIs"},
	"deviceCodes.m":               {classSwept, "device codes"},
	"cibaRequests.m":              {classSwept, "CIBA requests"},
	"refreshes.retries":           {classSwept, "sealed retry responses"},
	"refreshes.m":                 {classRetained, "Refresh tokens are deliberately not on that list"},
	"accessTokens.m":              {classOperatorGC, "access-token registry"},
	"opaqueAccessTokens.m":        {classOperatorGC, "opaque access tokens"},
	"grantRevocations.tombstones": {classOperatorGC, "grant tombstones"},
	"grantRevocations.denylist":   {classOperatorGC, "JTI denylist"},
	"emailotps.m":                 {classKeyBounded, "email-OTP challenges"},
	"iats.m":                      {classKeyBounded, "initial access tokens"},
	"iats.byHash":                 {classKeyBounded, "initial access tokens"},
}

// statedCounts are the numerals the prose puts in front of a list. The
// doc counts substores rather than maps, so a substore holding a primary
// map and a secondary index still counts once.
var statedCounts = map[reclamationClass]string{
	classOperatorGC: "Three substores",
	classKeyBounded: "Two substores",
}

// expiryFieldNames are the record fields that make a map's contents
// reclaimable. The unexported spellings are here because the sealed
// retry responses carry their bound on an unexported field.
var expiryFieldNames = []string{"ExpiresAt", "RetainUntil", "expiresAt", "retainUntil"}

// TestReclamationDocCoversEveryExpiringMap holds the registry above --
// and through it the Reclamation section -- to the substore maps the
// package actually declares. A map whose values expire but which the
// section never mentions is a substore nobody decided a reclamation
// policy for.
func TestReclamationDocCoversEveryExpiringMap(t *testing.T) {
	t.Parallel()

	declared := expiringSubstoreMaps(t)
	filed := make([]string, 0, len(reclamationDoc))
	for path := range reclamationDoc {
		filed = append(filed, path)
	}
	slices.Sort(filed)

	for _, path := range declared {
		if !slices.Contains(filed, path) {
			t.Errorf("substore map %s holds records that expire but the Reclamation section files it nowhere: "+
				"whether it is swept, collected on a GC cutoff, or bounded by its key space is undecided", path)
		}
	}
	for _, path := range filed {
		if !slices.Contains(declared, path) {
			t.Errorf("the Reclamation section files %s, which is no longer a substore map whose records expire", path)
		}
	}
}

// TestReclamationDocNamesEveryFiledMap pins the section's prose against
// the registry: every filed map has to be findable in the text, and the
// numerals the text puts in front of its lists have to match how many
// substores are actually on them.
func TestReclamationDocNamesEveryFiledMap(t *testing.T) {
	t.Parallel()

	section := reclamationSection(t)
	for path, entry := range reclamationDoc {
		if !strings.Contains(section, entry.phrase) {
			t.Errorf("the Reclamation section does not contain %q, the wording it files %s under",
				entry.phrase, path)
		}
	}

	for class, stated := range statedCounts {
		substores := make([]string, 0, len(reclamationDoc))
		for path, entry := range reclamationDoc {
			if entry.class != class {
				continue
			}
			owner, _, _ := strings.Cut(path, ".")
			if !slices.Contains(substores, owner) {
				substores = append(substores, owner)
			}
		}
		if !strings.Contains(section, stated) {
			slices.Sort(substores)
			t.Errorf("the Reclamation section does not say %q, but %d substores are filed there: %v",
				stated, len(substores), substores)
		}
		if want := numeral(t, len(substores)) + " substores"; want != stated {
			t.Errorf("the Reclamation section says %q where the registry holds %d: %v",
				stated, len(substores), substores)
		}
	}
}

// TestReclamationClassMatchesTheReclamationMechanism cross-checks the
// filing against the implementation, so a substore cannot be described
// as collected on a cutoff without exposing one, or as bounded by its
// key space while quietly reclaiming rows.
func TestReclamationClassMatchesTheReclamationMechanism(t *testing.T) {
	t.Parallel()

	for path, entry := range reclamationDoc {
		owner, _, _ := strings.Cut(path, ".")
		sub := substoreType(t, owner)
		gc := reflect.PointerTo(sub).Implements(reflect.TypeOf((*cutoffCollector)(nil)).Elem())

		if want := entry.class == classOperatorGC; gc != want {
			if want {
				t.Errorf("%s is filed as reclaimed on a GC cutoff but %s exposes no GC(ctx, cutoff) method",
					path, sub)
			} else {
				t.Errorf("%s is not filed as reclaimed on a GC cutoff but %s exposes GC(ctx, cutoff): "+
					"the section describes a reclamation route the substore does not take", path, sub)
			}
		}
		if entry.class == classKeyBounded && hasSweepCounter(sub) {
			t.Errorf("%s is filed as bounded by its key space but %s carries a sweep counter", path, sub)
		}
	}
}

// cutoffCollector is the shape of the GC method the access-token,
// opaque-access-token and grant-revocation interfaces declare. It is
// restated here rather than imported because the check is about the
// method being present on the concrete substore, not about the substore
// satisfying any particular store interface.
type cutoffCollector interface {
	GC(context.Context, time.Time) (int, error)
}

// expiringSubstoreMaps reports every "<Store field>.<map field>" whose
// values carry an expiry, read out of the type declarations.
func expiringSubstoreMaps(t *testing.T) []string {
	t.Helper()

	storeType := reflect.TypeOf(Store{})
	var paths []string
	for i := range storeType.NumField() {
		field := storeType.Field(i)
		sub := deref(field.Type)
		if sub.Kind() != reflect.Struct {
			continue
		}
		for j := range sub.NumField() {
			mapField := sub.Field(j)
			if mapField.Type.Kind() != reflect.Map || !carriesExpiry(mapField.Type.Elem()) {
				continue
			}
			paths = append(paths, field.Name+"."+mapField.Name)
		}
	}
	if len(paths) == 0 {
		t.Fatal("the walk over Store found no substore map whose records expire: there is nothing to compare against")
	}
	slices.Sort(paths)
	return paths
}

// carriesExpiry reports whether a map's element type states when its
// record stops being readable. A bare time.Time value counts: the
// consumed-JTI substore stores the expiry as the value itself.
func carriesExpiry(elem reflect.Type) bool {
	elem = deref(elem)
	if elem == reflect.TypeOf(time.Time{}) {
		return true
	}
	if elem.Kind() != reflect.Struct {
		return false
	}
	for _, name := range expiryFieldNames {
		if _, ok := elem.FieldByName(name); ok {
			return true
		}
	}
	return false
}

// substoreType resolves a [Store] field name to the struct type behind
// it.
func substoreType(t *testing.T, field string) reflect.Type {
	t.Helper()
	f, ok := reflect.TypeOf(Store{}).FieldByName(field)
	if !ok {
		t.Fatalf("Store declares no field %s", field)
	}
	return deref(f.Type)
}

// hasSweepCounter reports whether a substore keeps the write counter an
// amortised sweep is driven off.
func hasSweepCounter(sub reflect.Type) bool {
	for i := range sub.NumField() {
		if strings.HasSuffix(sub.Field(i).Name, "SinceGC") {
			return true
		}
	}
	return false
}

func deref(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ
}

// reclamationHeading is the godoc heading the section opens with.
const reclamationHeading = "# Reclamation"

// reclamationSection returns the Reclamation section of the package doc
// with its whitespace collapsed, so a phrase that the comment wraps
// across two lines still matches.
func reclamationSection(t *testing.T) string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "inmem.go", nil, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse inmem.go: %v", err)
	}
	if file.Doc == nil {
		t.Fatal("inmem.go carries no package doc comment")
	}
	doc := file.Doc.Text()
	start := strings.Index(doc, reclamationHeading)
	if start < 0 {
		t.Fatalf("the package doc has no %q section", reclamationHeading)
	}
	section := doc[start+len(reclamationHeading):]
	if end := strings.Index(section, "\n# "); end >= 0 {
		section = section[:end]
	}
	return strings.Join(strings.Fields(section), " ")
}

// numeral spells a list size the way the prose does.
func numeral(t *testing.T, n int) string {
	t.Helper()
	words := []string{"Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"}
	if n < 0 || n >= len(words) {
		t.Fatalf("no spelling for a list of %d substores", n)
	}
	return words[n]
}
