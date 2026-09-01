package hygiene_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A container build stage and the go.mod it compiles are two halves of
// a version contract nothing in the tree checks. The go directive and
// the toolchain line move with the language; the base image is a string
// in a file no Go tool reads. When the image falls behind, the module
// builds everywhere except inside the container, and the failure
// surfaces only to whoever runs `docker compose up --build` — which is
// the reader following the example, not the maintainer. The propagation
// is by hand and has already been missed once, so the check re-derives
// each stage's requirement from the module it builds.

// goBaseImage matches a builder stage's base image and captures its Go
// version. The tag is the major.minor stream (golang:1.27-alpine); a
// fully qualified patch tag parses the same way.
var goBaseImage = regexp.MustCompile(`^FROM\s+golang:(\d+)\.(\d+)`)

// dockerWorkdir matches the WORKDIR that selects which module the stage
// compiles.
var dockerWorkdir = regexp.MustCompile(`^WORKDIR\s+(\S+)`)

// goBuildCommand matches the RUN line that invokes the Go toolchain.
// It is what makes a stage subject to the check: a stage that runs no
// Go command has no toolchain requirement to satisfy.
var goBuildCommand = regexp.MustCompile(`^RUN\s+.*\bgo\s+(build|install|test|run)\b`)

// goModVersion matches the go / toolchain directives, whose versions
// carry an optional patch component (go 1.25.0, toolchain go1.26.5).
var goModVersion = regexp.MustCompile(`^(go|toolchain go)\s*(\d+)\.(\d+)`)

// goVersion is a major.minor pair. Patch releases are deliberately not
// compared: the published base images are major.minor streams, so a
// patch-level comparison would demand a tag that does not exist.
type goVersion struct {
	major int
	minor int
}

func (v goVersion) String() string { return strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) }

// olderThan reports whether v is behind other.
func (v goVersion) olderThan(other goVersion) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	return v.minor < other.minor
}

// goBuildStage is one builder stage: the image it runs on and the
// directory it compiles from, both relative to the repository root.
type goBuildStage struct {
	dockerfile string
	line       int
	image      goVersion
	moduleDir  string
}

// TestDockerfileGoImagesMeetModuleToolchains fails when a builder stage
// runs on an image older than the go.mod it compiles asks for.
//
// The requirement is read off the module rather than from a list kept
// here, so raising a module's toolchain is enough to make this check
// name the images that have to follow. That direction matters: the
// version that ages is the one in the Dockerfile, and a list would age
// with it.
func TestDockerfileGoImagesMeetModuleToolchains(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	stages := goBuildStages(t, root)
	if len(stages) == 0 {
		t.Fatal("no Dockerfile builder stage runs a Go command; the scan found nothing to check")
	}

	for _, stage := range stages {
		want := moduleToolchain(t, root, stage.moduleDir)
		if stage.image.olderThan(want) {
			t.Errorf("%s:%d builds %s on golang:%s, but %s/go.mod requires Go %s.\n"+
				"The image has to be raised to at least golang:%s, or `docker compose up --build` fails on a module the host builds fine.",
				stage.dockerfile, stage.line, stage.moduleDir, stage.image,
				stage.moduleDir, want, want)
		}
	}
}

// goBuildStages returns every builder stage in the tree that runs a Go
// command, paired with the module directory it runs in. A Dockerfile
// that declares a Go base image but reaches no Go command is reported:
// the scan would otherwise stay silent about a stage whose shape it
// failed to read.
func goBuildStages(tb testing.TB, root string) []goBuildStage {
	tb.Helper()

	var stages []goBuildStage
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "Dockerfile" {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		found := scanDockerfile(tb, root, path, rel)
		if len(found) == 0 {
			tb.Errorf("%s declares no Go builder stage this check can read; "+
				"either it stopped building Go, or the FROM / WORKDIR / RUN shape changed and the check is now blind to it", rel)
		}
		stages = append(stages, found...)
		return nil
	})
	if err != nil {
		tb.Fatalf("walk %s: %v", root, err)
	}
	return stages
}

// scanDockerfile reads one Dockerfile and returns its Go builder
// stages. The module directory is the working directory in force when
// the Go command runs, mapped back out of the image by stripping the
// stage's context root — the stages copy the repository in whole, so
// the path below that root is the repository-relative one.
func scanDockerfile(tb testing.TB, root, path, rel string) []goBuildStage {
	tb.Helper()

	body, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		tb.Fatalf("read %s: %v", rel, err)
	}

	var (
		stages    []goBuildStage
		image     goVersion
		inGoStage bool
		contextIn string
		workdir   string
	)
	for i, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "FROM "):
			m := goBaseImage.FindStringSubmatch(trimmed)
			inGoStage = m != nil
			contextIn, workdir = "", ""
			if inGoStage {
				image = goVersion{major: atoi(tb, m[1]), minor: atoi(tb, m[2])}
			}
		case dockerWorkdir.MatchString(trimmed):
			workdir = dockerWorkdir.FindStringSubmatch(trimmed)[1]
			if contextIn == "" {
				// The first WORKDIR of a stage is where the repository
				// is copied to; every later one is a directory inside
				// that copy.
				contextIn = workdir
			}
		case inGoStage && goBuildCommand.MatchString(trimmed):
			dir := strings.TrimPrefix(strings.TrimPrefix(workdir, contextIn), "/")
			if dir == "" {
				dir = "."
			}
			// Resolved through the repository's own file system so a
			// path read out of a Dockerfile cannot reach above it.
			if _, serr := fs.Stat(os.DirFS(root), dir); serr != nil {
				tb.Errorf("%s:%d runs a Go build in %q, which is no directory of this repository; "+
					"the check cannot tell which module the stage compiles", rel, i+1, dir)
				continue
			}
			stages = append(stages, goBuildStage{dockerfile: rel, line: i + 1, image: image, moduleDir: dir})
		}
	}
	return stages
}

// moduleToolchain returns the Go version the module enclosing dir
// requires: its toolchain directive when it pins one, otherwise its go
// directive. Both are floors — the toolchain line is the higher of the
// two whenever both are present.
func moduleToolchain(tb testing.TB, root, dir string) goVersion {
	tb.Helper()

	modDir := dir
	for {
		path := filepath.Join(root, modDir, "go.mod")
		body, err := os.ReadFile(filepath.Clean(path))
		if err == nil {
			return parseModuleToolchain(tb, filepath.Join(modDir, "go.mod"), string(body))
		}
		parent := filepath.Dir(modDir)
		if parent == modDir || modDir == "." {
			tb.Fatalf("no go.mod at or above %s", dir)
			return goVersion{}
		}
		modDir = parent
	}
}

// parseModuleToolchain reads the highest version floor a go.mod
// declares.
func parseModuleToolchain(tb testing.TB, name, body string) goVersion {
	tb.Helper()

	var want goVersion
	for _, line := range strings.Split(body, "\n") {
		m := goModVersion.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		found := goVersion{major: atoi(tb, m[2]), minor: atoi(tb, m[3])}
		if want.olderThan(found) {
			want = found
		}
	}
	if (want == goVersion{}) {
		tb.Fatalf("%s declares no go or toolchain version", name)
	}
	return want
}

// atoi converts a version component the regexp already constrained to
// digits.
func atoi(tb testing.TB, s string) int {
	tb.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		tb.Fatalf("parse version component %q: %v", s, err)
	}
	return n
}
