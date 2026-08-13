// Package log holds the library's silent [slog.Handler].
//
// The library logs through [*slog.Logger] directly rather than through a
// wrapper interface: the handler, not the logger, is the composition point
// slog is designed around. Redaction of sensitive attributes is enforced at
// exactly one place — the redact package's handler wrapper,
// which op.WithLogger and op.WithAuditLogger apply to the embedder-supplied
// handler as it enters the library. Everything downstream of that boundary
// is already wrapped, so no call site has to remember to redact.
package log

import (
	"context"
	"log/slog"
)

// DiscardHandler is a [slog.Handler] that drops every record. It is
// the canonical fall-back the library uses when no logger is configured
// so a nil handler never causes a runtime panic. The type is exported
// so the small handful of internal call sites that need a stable
// "silent handler" reference (op's default logger, the redactor's nil
// guard, the orchestrator's default) share a single implementation.
type DiscardHandler struct{}

// Enabled always returns false so the wrapped handler short-circuits
// before ever building a record.
func (DiscardHandler) Enabled(_ context.Context, _ slog.Level) bool { return false }

// Handle ignores every record.
func (DiscardHandler) Handle(_ context.Context, _ slog.Record) error { return nil }

// WithAttrs returns the same handler; the discard handler has no
// attribute state to track.
func (h DiscardHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }

// WithGroup returns the same handler; the discard handler has no
// group state to track.
func (h DiscardHandler) WithGroup(_ string) slog.Handler { return h }
