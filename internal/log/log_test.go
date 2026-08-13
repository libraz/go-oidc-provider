package log_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/log"
)

func TestDiscardHandlerIsNoOpAndKeepsIdentity(t *testing.T) {
	t.Parallel()

	handler := log.DiscardHandler{}
	ctx := context.Background()

	if handler.Enabled(ctx, slog.LevelError) {
		t.Fatal("DiscardHandler.Enabled returned true; discard handler should stay disabled")
	}
	if err := handler.Handle(ctx, slog.NewRecord(time.Now(), slog.LevelError, "ignored", 0)); err != nil {
		t.Fatalf("DiscardHandler.Handle returned error: %v", err)
	}
	if got := handler.WithAttrs([]slog.Attr{slog.String("k", "v")}); got != handler {
		t.Fatalf("WithAttrs returned %T, want original discard handler", got)
	}
	if got := handler.WithGroup("group"); got != handler {
		t.Fatalf("WithGroup returned %T, want original discard handler", got)
	}
}
