package log_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

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

func TestDiscard_DoesNotPanic(t *testing.T) {
	t.Parallel()

	logger := log.Discard()
	logger.Debug(context.Background(), "ignored")
	logger.Info(context.Background(), "ignored")
	logger.Warn(context.Background(), "ignored")
	logger.Error(context.Background(), "ignored")
}
