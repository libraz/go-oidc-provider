package devicecodekit

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/internal/redact"
)

// TestDepsAuditEmitter_RedactsBeforeTheEmbedderHandler pins the
// redaction hook onto the embedder-facing seam. Routing alone is not
// enough: the OP's own audit stream reaches the embedder through a
// redact-wrapped handler, and a device-code record that skipped the
// wrapper would hold a deployment's audit log to a weaker posture than
// every other record in it.
//
// The probe carries a credential-named attribute nested inside an
// extras value, because that is the shape the emitter's own key-name
// masking does not see — it matches the top-level extras key and does
// not descend. Only the handler wrapper does, so the sentinel in the
// output is evidence of the wrapper rather than of the emitter.
func TestDepsAuditEmitter_RedactsBeforeTheEmbedderHandler(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	deps := &Deps{AuditLogger: slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	deps.auditEmitter().Emit(context.Background(), audit.Event{
		Name:    devicecode.AuditRevoked,
		Level:   audit.LevelInfo,
		Message: "device_code revoked",
		Extras: map[string]any{
			"cascade": slog.GroupValue(slog.String("refresh_token", "s3cr3t-value")),
		},
	})

	if bytes.Contains(buf.Bytes(), []byte("s3cr3t-value")) {
		t.Errorf("credential reached the embedder's handler unmasked:\n%s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte(redact.Sentinel)) {
		t.Errorf("record carries no redaction sentinel:\n%s", buf.String())
	}
}
