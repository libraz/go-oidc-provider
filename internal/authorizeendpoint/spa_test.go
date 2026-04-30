//nolint:testpackage // exercises unexported looksLikeUID / validAssetPath / safeFS
package authorizeendpoint

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestLooksLikeUID pins the byte-class definition the SPA shell
// handler enforces before any IO. The shape — base64-url-no-pad of
// 16 random bytes — is the only token format the OP mints for
// /authorize redirects, so any deviation MUST resolve to false to
// keep the shell from doubling as a static-file probe oracle.
func TestLooksLikeUID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"too_short", "AAAAAAAAAAAAAAAAAAAAA", false},  // 21 chars
		{"too_long", "AAAAAAAAAAAAAAAAAAAAAAA", false}, // 23 chars
		{"all_lowercase", "abcdefghijklmnopqrstuv", true},
		{"all_uppercase", "ABCDEFGHIJKLMNOPQRSTUV", true},
		{"with_digits_dash_underscore", "ABCdef012345-_xyzABCDEF", false}, // 23 chars
		{"valid_22_mixed", "AbCdEf012345_-XyZ12345", true},
		{"contains_dot", "AAAAAAAAAAAAAAAAAAA.AB", false},
		{"contains_slash", "AAAAAAAAAAAAAAAA/AAAAA", false},
		{"contains_plus", "AAAAAAAAAAAAAAAAAAA+AB", false},
		{"contains_equals", "AAAAAAAAAAAAAAAAAAA=AB", false},
		{"contains_space", "AAAAAAAAAAAAAAAAAAA AB", false},
		{"contains_null_byte", "AAAAAAAAAAAAAAAAAAA\x00B", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := looksLikeUID(tc.in); got != tc.want {
				t.Errorf("looksLikeUID(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestValidAssetPath pins the dotfile-segment rejection rule the
// asset handler relies on. The check is segment-wise so a leading
// "/" never bypasses it; the helper is the only sentinel the
// handler exposes against committed secrets and metadata files.
func TestValidAssetPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"plain_filename", "main.js", true},
		{"nested_normal", "vendor/react.js", true},
		{"absolute_normal", "/assets/main.js", true},
		{"dotfile_root", ".env", false},
		{"dotfile_basename", "config/.env", false},
		{"dotfile_dirname", ".git/config", false},
		{"hidden_macos", ".DS_Store", false},
		{"double_slash", "/foo//bar.js", true},
		{"trailing_slash", "/foo/", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := validAssetPath(tc.in); got != tc.want {
				t.Errorf("validAssetPath(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestSafeFS_OpenServesPlainFile confirms a plain file under the
// configured root opens successfully and returns the expected
// content. The test pins the happy path so a future regression in
// the dotfile / directory / symlink guard does not silently break
// every asset request.
func TestSafeFS_OpenServesPlainFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "assets", "main.js"), "console.log('ok')")

	f, err := safeFS{root: root}.Open("/assets/main.js")
	if err != nil {
		t.Fatalf("Open(/assets/main.js): %v", err)
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != "console.log('ok')" {
		t.Errorf("body = %q, want \"console.log('ok')\"", body)
	}
}

// TestSafeFS_OpenRejectsDotfile pins the segment-wise dotfile rule.
// Both the basename and an interior dot-segment MUST resolve to
// fs.ErrNotExist so the handler returns 404 without surfacing the
// existence of the file.
func TestSafeFS_OpenRejectsDotfile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".env"), "SECRET=42")
	mustWrite(t, filepath.Join(root, ".git", "config"), "[user]")

	cases := []string{"/.env", "/.git/config"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := safeFS{root: root}.Open(name)
			if !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Open(%q) err = %v, want fs.ErrNotExist", name, err)
			}
		})
	}
}

// TestSafeFS_OpenRejectsDirectory confirms directory targets do
// not surface through the asset handler. The shell handler is the
// only surface that serves index.html; the asset path MUST refuse
// directory targets so a misconfigured StaticDir cannot leak
// directory enumeration through Readdir.
func TestSafeFS_OpenRejectsDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	_, err := safeFS{root: root}.Open("/assets")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open(/assets) err = %v, want fs.ErrNotExist", err)
	}
}

// TestSafeFS_OpenRejectsSymlinkOutsideRoot guards the
// symlink-containment rule. A symlink whose target sits outside
// the configured root MUST resolve to fs.ErrNotExist so a
// misconfigured workspace symlink (npm/pnpm dependency link,
// monorepo build aliases) cannot bridge to the host filesystem.
func TestSafeFS_OpenRejectsSymlinkOutsideRoot(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows; covered by Linux/macOS CI")
	}

	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "secret.txt")
	mustWrite(t, target, "leaked")

	link := filepath.Join(root, "evil")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := safeFS{root: root}.Open("/evil")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open(/evil) err = %v, want fs.ErrNotExist", err)
	}
}

// TestSafeFS_OpenAcceptsSymlinkInsideRoot confirms a symlink
// whose target is within the same root passes the containment
// check. SPA build pipelines occasionally emit such links (e.g.,
// vendored dependency mirrors); rejecting them would force the
// embedder to flatten the build output.
func TestSafeFS_OpenAcceptsSymlinkInsideRoot(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows; covered by Linux/macOS CI")
	}

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "assets", "main.js"), "ok")

	link := filepath.Join(root, "alias.js")
	if err := os.Symlink(filepath.Join(root, "assets", "main.js"), link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	f, err := safeFS{root: root}.Open("/alias.js")
	if err != nil {
		t.Fatalf("Open(/alias.js): %v", err)
	}
	defer f.Close()
}

// mustWrite writes content to path, creating parent directories
// as needed. Test helpers only; no error wrapping or partial
// recovery — failure aborts the test.
func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
