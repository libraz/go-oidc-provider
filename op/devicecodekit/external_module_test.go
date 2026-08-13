package devicecodekit_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Every module in this repository — the examples, the store adapters,
// the harnesses — has an import path under the library's own, so Go's
// internal-package rule lets all of them reach internal/. A test in any
// of them can therefore build a device-code audit sink no real embedder
// can write, which is exactly the gap these cases exist to close. The
// probe below is compiled as a module whose path is unrelated to the
// library's, so it is held to the same rule as a third-party embedder:
// it can name only exported types.

// embedderMain drives the four device-code audit events through the
// public dependency bundle and prints what the configured sink
// received. It imports the public packages only; a device-code audit
// event that has no exported route into a sink cannot appear here.
const embedderMain = `package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/libraz/go-oidc-provider/op/devicecodekit"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "embedder:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	st := inmem.New()
	codes := st.DeviceCodes()
	now := time.Now().UTC()
	for id, userCode := range map[string]string{
		"dev-strike":  "ABCDEFGH",
		"dev-approve": "BCDEFGHJ",
		"dev-deny":    "CDEFGHJK",
		"dev-revoke":  "DEFGHJKM",
	} {
		if err := codes.Save(ctx, &store.DeviceCode{
			ID:        id,
			UserCode:  userCode,
			ClientID:  "cli-tool",
			Status:    store.DeviceCodeStatusPending,
			IssuedAt:  now,
			ExpiresAt: now.Add(10 * time.Minute),
		}); err != nil {
			return fmt.Errorf("seed %s: %w", id, err)
		}
	}

	// The whole point of the probe: an embedder outside the library's
	// import path assigns its own audit sink and gets the device-code
	// events on it.
	var sink bytes.Buffer
	deps := &devicecodekit.Deps{
		DeviceCodes:      codes,
		GrantRevocations: st.GrantRevocations(),
		AuditLogger:      slog.New(slog.NewJSONHandler(&sink, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}

	if _, err := devicecodekit.VerifyUserCode(ctx, deps, "dev-strike", "WR0NGCDE"); err != nil {
		return fmt.Errorf("verify user_code: %w", err)
	}
	if err := devicecodekit.ApproveUserCode(ctx, deps, "BCDEFGHJ", "user-1", now); err != nil {
		return fmt.Errorf("approve user_code: %w", err)
	}
	if err := devicecodekit.DenyUserCode(ctx, deps, "CDEFGHJK", devicecodekit.DenyReasonUserDenied); err != nil {
		return fmt.Errorf("deny user_code: %w", err)
	}
	if err := devicecodekit.Revoke(ctx, deps, "dev-revoke", devicecodekit.DenyReasonUserRevokedDevice); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	fmt.Print(sink.String())
	return nil
}
`

// embedderInternalProbe asserts the counter-property: the probe module
// really is outside the library's import path, so a case that passes
// above cannot have passed by reaching into internal/.
const embedderInternalProbe = `package main

import _ "github.com/libraz/go-oidc-provider/internal/audit"
`

// TestDeps_AuditLoggerReachesASinkFromAnotherModule compiles and runs a
// module whose import path is unrelated to the library's, and asserts
// each device-code audit event arrived at the sink that module
// configured with exported API alone.
func TestDeps_AuditLoggerReachesASinkFromAnotherModule(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH: %v", err)
	}
	dir := writeEmbedderModule(t, map[string]string{"main.go": embedderMain})

	cmd := exec.CommandContext(t.Context(), "go", "run", ".")
	cmd.Dir = dir
	cmd.Env = embedderEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("an embedder outside this module could not build or run against the public API: %v\n%s", err, out)
	}
	for _, want := range []string{
		`"audit":"true"`,
		"device_code.verification.user_code_brute_force",
		"device_code.verification.approved",
		"device_code.verification.denied",
		"device_code.revoked",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("%s never reached the embedder's sink; it received:\n%s", want, out)
		}
	}
}

// TestEmbedderModule_CannotReachInternalPackages keeps the case above
// honest. If this probe ever compiles, the module shares the library's
// import path prefix and proves nothing an in-module test does not.
func TestEmbedderModule_CannotReachInternalPackages(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH: %v", err)
	}
	dir := writeEmbedderModule(t, map[string]string{"main.go": embedderInternalProbe})

	cmd := exec.CommandContext(t.Context(), "go", "build", "./...")
	cmd.Dir = dir
	cmd.Env = embedderEnv()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the probe module imported internal/audit, so it is not held to the embedder's import rules:\n%s", out)
	}
	if !strings.Contains(string(out), "use of internal package") {
		t.Fatalf("probe module failed for an unrelated reason: %v\n%s", err, out)
	}
}

// writeEmbedderModule materialises a module rooted outside the
// library's import path, wired to this working tree through a replace
// so the probe compiles against the source under test rather than a
// published version.
func writeEmbedderModule(tb testing.TB, files map[string]string) string {
	tb.Helper()

	root, err := filepath.Abs("../..")
	if err != nil {
		tb.Fatalf("resolve module root: %v", err)
	}
	dir := tb.TempDir()
	gomod := fmt.Sprintf(`module example.com/oidc-embedder

%s

require github.com/libraz/go-oidc-provider v0.0.0

replace github.com/libraz/go-oidc-provider => %s
`, goDirective(tb, root), root)
	files["go.mod"] = gomod
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			tb.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// goDirective returns the library's own "go" line so the probe module
// never declares a language version older than the module it replaces.
func goDirective(tb testing.TB, root string) string {
	tb.Helper()

	//nolint:gosec // the path is this package's own location plus a fixed name, never caller input.
	content, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		tb.Fatalf("read library go.mod: %v", err)
	}
	for _, raw := range strings.Split(string(content), "\n") {
		if line := strings.TrimSpace(raw); strings.HasPrefix(line, "go ") {
			return line
		}
	}
	tb.Fatal("library go.mod declares no go directive")
	return ""
}

// embedderEnv keeps the probe off the workspace (which lists neither
// module) and off the network: every module it needs is either this
// working tree or already in the local cache from building the library
// itself.
func embedderEnv() []string {
	return append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "GOPROXY=off")
}
