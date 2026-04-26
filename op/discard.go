package op

import (
	"context"
	"log/slog"
)

// discardHandler is the default [slog.Handler] used when the caller did not
// supply a logger via [WithLogger]. It is a private type because the public
// API surface for "no logging" is "do not call [WithLogger]" — exposing the
// handler would imply users build their own discarding pipeline.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (discardHandler) WithAttrs(_ []slog.Attr) slog.Handler      { return discardHandler{} }
func (discardHandler) WithGroup(_ string) slog.Handler           { return discardHandler{} }
