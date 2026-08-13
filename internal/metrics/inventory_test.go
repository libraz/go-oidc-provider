package metrics_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/metrics"
)

// metricsExamplePath is the operator-facing inventory of the OP's
// counters: the only place a reader who never opens the library source
// learns which series exist. It is checked against the catalog rather
// than kept in step by hand.
const metricsExamplePath = "examples/52-prometheus-metrics/main.go"

// exampleInventoryEntry matches one counter row of that inventory. The
// pattern is anchored on the bullet and the type column so prose that
// merely mentions a metric name (including the embedder-owned HTTP
// metrics the example tells readers to install themselves) is not read
// as an entry.
var exampleInventoryEntry = regexp.MustCompile(`^//\s+-\s+(oidc_[a-z0-9_]+)\s+counter\s*$`)

// TestCollector_RegisteredFamiliesMatchCatalog holds the constructor to
// the catalog's projection in both directions: a collector the catalog
// does not name is a series no event can move, and a catalog projection
// with no collector is an event whose metric silently disappears.
//
// Every registered family is given a sample first, because a vec metric
// is invisible to Gather until it has one — which is exactly why a
// missing collector is easy to ship unnoticed.
func TestCollector_RegisteredFamiliesMatchCatalog(t *testing.T) {
	t.Parallel()

	missing, unexpected := diffNames(auditevent.MetricNames(), gatheredFamilyNames(t))
	if len(missing) > 0 {
		t.Errorf("catalog metrics with no collector registered (or no event reaching one): %v", missing)
	}
	if len(unexpected) > 0 {
		t.Errorf("registered metrics absent from the catalog: %v", unexpected)
	}
}

// TestMetricsExample_InventoryMatchesCatalog keeps the counter list an
// operator reads in step with the counters the OP registers. A series
// absent from the inventory is a series nobody writes an alert for, and
// a series listed but never registered is an alert rule that can only
// ever evaluate against no data.
func TestMetricsExample_InventoryMatchesCatalog(t *testing.T) {
	t.Parallel()

	missing, unexpected := diffNames(auditevent.MetricNames(), exampleInventoryNames(t))
	if len(missing) > 0 {
		t.Errorf("%s does not list registered metrics %v, so nobody alerts on them", metricsExamplePath, missing)
	}
	if len(unexpected) > 0 {
		t.Errorf("%s lists %v, which the OP does not register", metricsExamplePath, unexpected)
	}
}

// diffNames reports the want entries absent from got and the got
// entries absent from want.
func diffNames(want, got []string) (missing, unexpected []string) {
	for _, name := range want {
		if !slices.Contains(got, name) {
			missing = append(missing, name)
		}
	}
	for _, name := range got {
		if !slices.Contains(want, name) {
			unexpected = append(unexpected, name)
		}
	}
	return missing, unexpected
}

// gatheredFamilyNames returns the sorted metric families a freshly
// constructed collector surfaces once one event per catalog projection
// has been emitted through the bridge.
func gatheredFamilyNames(t *testing.T) []string {
	t.Helper()

	c, reg := newTestCollector(t, metrics.Options{})
	bridge := metrics.NewBridge(c, nil)
	seen := make(map[auditevent.Metric]struct{})
	for _, definition := range auditevent.Catalog() {
		if definition.Metric == auditevent.MetricNone {
			continue
		}
		if _, done := seen[definition.Metric]; done {
			continue
		}
		seen[definition.Metric] = struct{}{}
		bridge.Emit(context.Background(), audit.Event{Name: string(definition.Name)})
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	names := make([]string, 0, len(families))
	for _, family := range families {
		names = append(names, family.GetName())
	}
	slices.Sort(names)
	return names
}

// exampleInventoryNames returns the sorted counter names the example's
// package documentation publishes.
func exampleInventoryNames(t *testing.T) []string {
	t.Helper()

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	//nolint:gosec // path is a package constant resolved against this file's own directory.
	source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(metricsExamplePath)))
	if err != nil {
		t.Fatalf("read %s: %v", metricsExamplePath, err)
	}
	var names []string
	for line := range strings.Lines(string(source)) {
		match := exampleInventoryEntry.FindStringSubmatch(strings.TrimRight(line, "\n"))
		if match == nil {
			continue
		}
		names = append(names, match[1])
	}
	slices.Sort(names)
	return names
}
