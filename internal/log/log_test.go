package log_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/log"
)

func TestNew_NilLoggerDefaultsToStderrInfo(t *testing.T) {
	t.Parallel()

	got := log.New(nil)
	if got == nil {
		t.Fatal("New(nil) returned nil Logger")
	}
}

func TestLogger_Info_RoutesToHandler(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := log.New(slog.New(handler))

	logger.Info(context.Background(), "hello", slog.String("k", "v"))

	out := buf.String()
	if !strings.Contains(out, "hello") {
		t.Fatalf("expected message in output, got: %s", out)
	}
	if !strings.Contains(out, "k=v") {
		t.Fatalf("expected attribute in output, got: %s", out)
	}
}

func TestLogger_With_AddsAttributes(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, nil)
	base := log.New(slog.New(handler))

	scoped := base.With(slog.String("svc", "op"))
	scoped.Info(context.Background(), "ping")

	out := buf.String()
	if !strings.Contains(out, "svc=op") {
		t.Fatalf("expected scoped attribute in output, got: %s", out)
	}
}

func TestLogger_WithNoAttrsReturnsUsableLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	base := log.New(slog.New(slog.NewTextHandler(&buf, nil)))

	base.With().Info(context.Background(), "ping")

	if out := buf.String(); !strings.Contains(out, "ping") {
		t.Fatalf("expected message from logger returned by With(), got: %s", out)
	}
}

func TestDiscard_DoesNotPanic(t *testing.T) {
	t.Parallel()

	logger := log.Discard()
	logger.Debug(context.Background(), "ignored")
	logger.Info(context.Background(), "ignored")
	logger.Warn(context.Background(), "ignored")
	logger.Error(context.Background(), "ignored")
}

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
