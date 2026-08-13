package hygiene_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The dependency license gate lives in scripts/licenses.sh. Collecting the
// report it decides on requires the whole module graph and a module
// download; the decision itself requires only the report, and the script
// exposes that half as `--check <report>` so it can be driven from a
// fixture. These tests are the only thing that ever feeds it a report it
// must reject — a real run lists only dependencies the project already
// ships, so it cannot distinguish a working gate from one that inspects
// nothing.

// checkReport runs the gate over a report written from rows and returns its
// combined output and whether it exited zero.
func checkReport(tb testing.TB, rows string) (string, bool) {
	tb.Helper()

	script := filepath.Join(repoRoot(tb), "scripts", "licenses.sh")
	report := filepath.Join(tb.TempDir(), "go-licenses.csv")
	if err := os.WriteFile(report, []byte(rows), 0o600); err != nil {
		tb.Fatalf("write report: %v", err)
	}

	out, err := exec.CommandContext(tb.Context(), script, "--check", report).CombinedOutput() //nolint:gosec // fixed path under the repository.
	if err == nil {
		return string(out), true
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		tb.Fatalf("run %s: %v\n%s", script, err, out)
	}
	return string(out), false
}

// TestLicenseGateRejectsUnallowedLicense pins the gate's decision rule: a
// dependency passes only when its license is positively identified as one
// the project accepts.
//
// Each row here is a way the opposite rule — reject what matches a list of
// forbidden families — lets a dependency through. An unclassified module has
// no license text the scanner could read, so it matches no family and ships
// unexamined. A copyleft license written without a version number misses a
// pattern spelled with one. An empty classification matches nothing at all.
// All three have to fail, and the message has to name the module, because
// the operator's next step is to go read that module's license file.
func TestLicenseGateRejectsUnallowedLicense(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		row  string
		want string
	}{
		{
			name: "unclassified",
			row:  "example.com/unreadable,Unknown,Unknown",
			want: "example.com/unreadable is classified as Unknown",
		},
		{
			name: "copyleft without a version suffix",
			row:  "example.com/ancient,https://example.com/ancient/LICENSE,GPL-1.0",
			want: "example.com/ancient is classified as GPL-1.0",
		},
		{
			name: "empty classification",
			row:  "example.com/blank,https://example.com/blank/LICENSE,",
			want: "example.com/blank is classified as",
		},
		{
			name: "license named in the module path only",
			row:  "example.com/mit-tools/parser,https://example.com/mit-tools/LICENSE,Unknown",
			want: "example.com/mit-tools/parser is classified as Unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, ok := checkReport(t, "example.com/allowed,https://example.com/allowed/LICENSE,MIT\n"+tc.row+"\n")
			if ok {
				t.Fatalf("gate accepted %q:\n%s", tc.row, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("gate output does not name the rejected module and its classification\nwant substring: %s\ngot:\n%s", tc.want, out)
			}
		})
	}
}

// TestLicenseGateAcceptsAllowlistedLicenses guards the other side: the gate
// has to pass the licenses the project actually depends on, or the first
// green run would be the one where somebody removes it.
func TestLicenseGateAcceptsAllowlistedLicenses(t *testing.T) {
	t.Parallel()

	rows := strings.Join([]string{
		"example.com/apache,https://example.com/apache/LICENSE,Apache-2.0",
		"example.com/bsd2,https://example.com/bsd2/LICENSE,BSD-2-Clause",
		"example.com/bsd3,https://example.com/bsd3/LICENSE,BSD-3-Clause",
		"example.com/isc,https://example.com/isc/LICENSE,ISC",
		"example.com/mit,https://example.com/mit/LICENSE,MIT",
		"example.com/mpl,https://example.com/mpl/LICENSE,MPL-2.0",
		"",
	}, "\n")

	if out, ok := checkReport(t, rows); !ok {
		t.Errorf("gate rejected an allowlisted license:\n%s", out)
	}
}

// TestLicenseGateResolvesPinnedClassification covers the escape hatch for a
// module the scanner cannot classify. Pinning the license by hand is the
// only way such a module can pass, and the pin has to be visible here:
// otherwise the row that fails the gate above and the row that ships in the
// index are the same row, and nothing says which one the project meant.
func TestLicenseGateResolvesPinnedClassification(t *testing.T) {
	t.Parallel()

	if out, ok := checkReport(t, "modernc.org/mathutil,Unknown,Unknown\n"); !ok {
		t.Errorf("gate rejected a module whose license is pinned in the script:\n%s", out)
	}
}

// TestThirdPartyIndexIsFullyClassified checks the published artifact rather
// than the gate. THIRD_PARTY.md is the notice file an embedder reads to
// discharge their own attribution duty, and a row saying the license is
// unknown discharges nothing — it hands the reader the same question they
// came with.
func TestThirdPartyIndexIsFullyClassified(t *testing.T) {
	t.Parallel()

	path := filepath.Join(repoRoot(t), "THIRD_PARTY.md")
	body, err := os.ReadFile(path) //nolint:gosec // fixed path under the repository.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var unclassified []string
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 4 {
			continue
		}
		license := strings.TrimSpace(fields[2])
		if license == "" || license == "Unknown" {
			unclassified = append(unclassified, strings.TrimSpace(fields[1]))
		}
	}

	if len(unclassified) > 0 {
		t.Errorf("%d dependency row(s) in THIRD_PARTY.md carry no license.\n"+
			"Read the module's own license file and pin the identifier in scripts/licenses.sh, then regenerate.\n\t%s",
			len(unclassified), strings.Join(unclassified, "\n\t"))
	}
}
