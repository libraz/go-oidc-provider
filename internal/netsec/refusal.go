package netsec

import (
	"context"
	"errors"
	"log/slog"
)

// IsDenyListed reports whether err is a deny-list rejection: the target
// resolves to a loopback, private or link-local range, or to a
// cloud-metadata address.
func IsDenyListed(err error) bool {
	return errors.Is(err, ErrPrivateNetworkBlocked) || errors.Is(err, ErrCloudMetadataBlocked)
}

// IsRequestRefusal reports whether err is one of the rejections the
// request-build gate raises before any network I/O: a deny-listed target
// ([IsDenyListed]), a disallowed scheme or a missing host.
func IsRequestRefusal(err error) bool {
	return IsDenyListed(err) ||
		errors.Is(err, ErrSchemeNotAllowed) ||
		errors.Is(err, ErrMissingHost)
}

// LogDenyListed records one WARN on logger when err is a deny-list rejection
// ([IsDenyListed]), so an operator sees which fetch was refused and, through
// err's text, the option that lifts the refusal. fetch names the outbound
// fetch kind; clientID is omitted from the record when empty. A nil logger
// or any other error is a no-op.
func LogDenyListed(ctx context.Context, logger *slog.Logger, fetch, clientID string, err error) {
	if logger == nil || !IsDenyListed(err) {
		return
	}
	attrs := []slog.Attr{slog.String("fetch", fetch)}
	if clientID != "" {
		attrs = append(attrs, slog.String("client_id", clientID))
	}
	attrs = append(attrs, slog.Any("err", err))
	logger.LogAttrs(ctx, slog.LevelWarn, "outbound fetch refused by the private-network deny-list", attrs...)
}
