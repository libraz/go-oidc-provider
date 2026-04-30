//nolint:testpackage // exercises unexported looksLikeUID / validAssetPath / safeFS / spaTerminalWriter
package authorizeendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
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

// TestSPATerminalWriter_RewritesFoundToJSONEnvelope pins the contract
// the SPA route relies on: a 302 carrying a Location header is
// converted to a 200 application/json envelope of the form
// {"type":"redirect","location":"<target>"} so the SPA's submit
// handler can navigate at document level. The orchestrator's
// http.Redirect call also writes a small HTML body; the wrapper
// MUST suppress it so the JSON envelope is the only response body.
func TestSPATerminalWriter_RewritesFoundToJSONEnvelope(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	tw := newSPATerminalWriter(rec)
	target := "http://rp.example/callback?code=abc&state=xyz"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/login/state/u", nil)
	http.Redirect(tw, req, target, http.StatusFound)
	tw.flush()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want application/json; charset=utf-8", got)
	}
	if got := rec.Header().Get("Location"); got != "" {
		t.Fatalf("Location header leaked: %q", got)
	}
	var body struct {
		Type     string `json:"type"`
		Location string `json:"location"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v (raw=%q)", err, rec.Body.String())
	}
	if body.Type != "redirect" {
		t.Errorf("type = %q, want \"redirect\"", body.Type)
	}
	if body.Location != target {
		t.Errorf("location = %q, want %q", body.Location, target)
	}
}

// TestSPATerminalWriter_PassthroughOK confirms the wrapper does not
// rewrite a normal JSON next-prompt response. The JSONDriver writes a
// 200 with an application/json body; the wrapper must forward both
// the status and the body byte-for-byte so the SPA can parse and
// render the next prompt.
func TestSPATerminalWriter_PassthroughOK(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	tw := newSPATerminalWriter(rec)
	tw.Header().Set("Content-Type", "application/json")
	tw.WriteHeader(http.StatusOK)
	if _, err := tw.Write([]byte(`{"type":"auth.password"}`)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	tw.flush()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if rec.Body.String() != `{"type":"auth.password"}` {
		t.Fatalf("body = %q, want JSON next-prompt envelope", rec.Body.String())
	}
}

// TestSPATerminalWriter_PassthroughClientError confirms the wrapper
// forwards 4xx error envelopes unchanged. The JSONDriver writes a JSON
// error body when the orchestrator rejects the submission; the SPA
// reads it to surface a localized error to the user, so the wrapper
// must not rewrite it.
func TestSPATerminalWriter_PassthroughClientError(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	tw := newSPATerminalWriter(rec)
	tw.Header().Set("Content-Type", "application/json")
	tw.WriteHeader(http.StatusForbidden)
	if _, err := tw.Write([]byte(`{"error":"invalid_request"}`)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	tw.flush()

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if rec.Body.String() != `{"error":"invalid_request"}` {
		t.Fatalf("body = %q, want JSON error envelope", rec.Body.String())
	}
}

// TestSPATerminalWriter_PassthroughNoContent confirms a 204 cancel
// (the DELETE-without-redirect path in serveInteractionDelete)
// reaches the inner writer with status and empty body intact.
func TestSPATerminalWriter_PassthroughNoContent(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	tw := newSPATerminalWriter(rec)
	tw.WriteHeader(http.StatusNoContent)
	tw.flush()

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body unexpectedly non-empty: %q", rec.Body.String())
	}
}

// TestSPATerminalWriter_PassthroughFoundWithoutLocation defends against
// a 302 that somehow lacks a Location header. The wrapper's
// rewrite branch is gated on Location being non-empty; without it the
// response forwards as-is so the SPA receives the original (degraded)
// signal rather than a synthetic envelope claiming an empty target.
func TestSPATerminalWriter_PassthroughFoundWithoutLocation(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	tw := newSPATerminalWriter(rec)
	tw.WriteHeader(http.StatusFound)
	tw.flush()

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 passthrough when Location is absent", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got == "application/json; charset=utf-8" {
		t.Fatal("wrapper rewrote a Location-less 302; that path is reserved for true terminal redirects")
	}
}

// TestSPATerminalWriter_ImplicitOK confirms a Write without a prior
// WriteHeader is treated as 200, matching net/http's standard
// convention. The handler-side helpers occasionally rely on this so
// the wrapper must not desynchronize with that contract.
func TestSPATerminalWriter_ImplicitOK(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	tw := newSPATerminalWriter(rec)
	if _, err := tw.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	tw.flush()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (implicit)", rec.Code)
	}
	if rec.Body.String() != "hello" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "hello")
	}
}

// TestSPATerminalWriter_FlushIdempotent confirms a second flush call
// is a no-op so accidental double-flush in a route helper does not
// panic on a closed-channel-style write or duplicate the body.
func TestSPATerminalWriter_FlushIdempotent(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	tw := newSPATerminalWriter(rec)
	tw.WriteHeader(http.StatusOK)
	if _, err := tw.Write([]byte("once")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	tw.flush()
	tw.flush()

	if rec.Body.String() != "once" {
		t.Fatalf("body = %q, want %q (flush should be idempotent)", rec.Body.String(), "once")
	}
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
