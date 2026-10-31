package audit_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
)

// TestSlog_ExtrasEmittedInKeyOrder pins a deterministic attribute order so
// two emissions of the same event render byte-identically.
func TestSlog_ExtrasEmittedInKeyOrder(t *testing.T) {
	t.Parallel()

	extras := map[string]any{"delta": 4, "alpha": 1, "echo": 5, "charlie": 3, "bravo": 2}
	want := "extras.alpha=1 extras.bravo=2 extras.charlie=3 extras.delta=4 extras.echo=5"
	for range 20 {
		var buf bytes.Buffer
		opts := &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}}
		audit.Slog(slog.New(slog.NewTextHandler(&buf, opts))).Emit(context.Background(),
			audit.Event{Name: "order.check", Extras: extras})
		line := buf.String()
		start := strings.Index(line, "extras.alpha=")
		if start < 0 || !strings.Contains(line[start:], want) {
			t.Fatalf("extras not in key order:\n%s", line)
		}
	}
}
