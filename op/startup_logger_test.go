package op_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

const (
	startupPKCEMsg        = "no security profile requires PKCE"
	startupClaimSourceMsg = "resolved the source of ID Token and /userinfo claims"
)

// swapDefaultLogger points [slog.Default] at a JSON handler over the
// returned buffer for the duration of the test. Callers must not run in
// parallel: the default logger is process-global.
func swapDefaultLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestNew_StartupDiagnosticsGoToDefaultLogger pins that, without
// [op.WithLogger], the construction-time lines reach [slog.Default].
func TestNew_StartupDiagnosticsGoToDefaultLogger(t *testing.T) { //nolint:paralleltest // swaps the process-wide slog default.
	buf := swapDefaultLogger(t)

	if _, err := op.New(validBaseOptsWithInmem(t)...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
	out := buf.String()
	for _, want := range []string{startupPKCEMsg, startupClaimSourceMsg} {
		if !strings.Contains(out, want) {
			t.Errorf("default logger output missing %q; got:\n%s", want, out)
		}
	}
}

// TestNew_WithLoggerKeepsStartupDiagnosticsOffDefault pins that a supplied
// logger receives the construction-time lines and [slog.Default] none.
func TestNew_WithLoggerKeepsStartupDiagnosticsOffDefault(t *testing.T) { //nolint:paralleltest // swaps the process-wide slog default.
	defBuf := swapDefaultLogger(t)

	var own bytes.Buffer
	opts := append(validBaseOptsWithInmem(t), op.WithLogger(slog.New(slog.NewJSONHandler(&own, nil))))
	if _, err := op.New(opts...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if defBuf.Len() != 0 {
		t.Errorf("default logger received output despite WithLogger:\n%s", defBuf.String())
	}
	for _, want := range []string{startupPKCEMsg, startupClaimSourceMsg} {
		if !strings.Contains(own.String(), want) {
			t.Errorf("supplied logger output missing %q; got:\n%s", want, own.String())
		}
	}
}
