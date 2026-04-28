// Package log is the library's thin wrapper over [log/slog]. Library code
// MUST go through this package rather than reaching for [slog.Default()] so
// that callers can inject a logger with their own handler, and so that we
// have a single place to enforce redaction of sensitive attributes.
package log

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// Logger is the minimal logging surface used by the library. It is
// intentionally narrower than [*slog.Logger] so that we can swap the
// backend (or enforce redaction in front of it) without leaking the
// abstraction to the call sites.
type Logger interface {
	Debug(ctx context.Context, msg string, attrs ...slog.Attr)
	Info(ctx context.Context, msg string, attrs ...slog.Attr)
	Warn(ctx context.Context, msg string, attrs ...slog.Attr)
	Error(ctx context.Context, msg string, attrs ...slog.Attr)
	With(attrs ...slog.Attr) Logger
}

// New wraps the given [*slog.Logger] in our [Logger] interface. If l is
// nil, a JSON logger writing to [os.Stderr] at info level is used.
func New(l *slog.Logger) Logger {
	if l == nil {
		l = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return slogLogger{l: l}
}

// Discard returns a [Logger] that drops every record. It is the right
// default for tests that do not assert on log output.
func Discard() Logger {
	return slogLogger{l: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

type slogLogger struct {
	l *slog.Logger
}

func (s slogLogger) Debug(ctx context.Context, msg string, attrs ...slog.Attr) {
	s.l.LogAttrs(ctx, slog.LevelDebug, msg, attrs...)
}

func (s slogLogger) Info(ctx context.Context, msg string, attrs ...slog.Attr) {
	s.l.LogAttrs(ctx, slog.LevelInfo, msg, attrs...)
}

func (s slogLogger) Warn(ctx context.Context, msg string, attrs ...slog.Attr) {
	s.l.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
}

func (s slogLogger) Error(ctx context.Context, msg string, attrs ...slog.Attr) {
	s.l.LogAttrs(ctx, slog.LevelError, msg, attrs...)
}

func (s slogLogger) With(attrs ...slog.Attr) Logger {
	if len(attrs) == 0 {
		return s
	}
	args := make([]any, 0, len(attrs))
	for _, a := range attrs {
		args = append(args, a)
	}
	return slogLogger{l: s.l.With(args...)}
}
