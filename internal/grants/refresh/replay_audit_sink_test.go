package refresh_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/redact"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// Refresh-token replay is the most security-relevant event the OP
// raises, and its one correlation field is what tells an operator
// which rotation chain was replayed. Every other test in this package
// asserts on an in-process Emitter that receives Extras verbatim, so
// none of them observes the key-name redaction that sits between the
// emitter and a real sink. This test drives the production pair
// (audit.Slog over a redact-wrapped handler, the shape op.New builds)
// end to end, which is the only place the collision between a field
// name and the redactor's substring rules is observable.
func TestExchange_Replay_FingerprintSurvivesToSlogSink(t *testing.T) {
	t.Parallel()

	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	cur := t0
	clk := func() time.Time { return cur }
	st := inmem.New(inmem.WithClock(movingClock{cur: &cur})).RefreshTokens()

	var buf bytes.Buffer
	logger := slog.New(redact.WrapHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	iss, err := refresh.NewIssuer(refresh.IssuerConfig{Store: st, Clock: clk, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	exc, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store: st,
		Clock: clk,
		Audit: audit.Slog(logger),
	})
	if err != nil {
		t.Fatalf("NewExchanger: %v", err)
	}

	ctx := context.Background()
	root, err := iss.Issue(ctx, goodIssue())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); err != nil {
		t.Fatalf("first Exchange: %v", err)
	}
	cur = cur.Add(refresh.GraceTTLDefault + time.Second)
	if _, err := exc.Exchange(ctx, refresh.ExchangeInput{Token: root, ClientID: "client-1"}); !errors.Is(err, refresh.ErrTokenReplayed) {
		t.Fatalf("replay err=%v want ErrTokenReplayed", err)
	}

	rec := findLoggedEvent(t, buf.Bytes(), "refresh.replay_detected")
	extras, ok := rec["extras"].(map[string]any)
	if !ok {
		t.Fatalf("record carries no extras group: %v", rec)
	}
	got, _ := extras["refresh_chain_fingerprint"].(string)
	if want := audit.Fingerprint(root); got != want {
		t.Fatalf("the replay correlation field reached the sink as %q, want the fingerprint %q; "+
			"an operator cannot tell which chain was replayed", got, want)
	}
	if strings.Contains(buf.String(), root) {
		t.Fatalf("the raw refresh token reached the sink: %s", buf.String())
	}
}

// findLoggedEvent returns the decoded JSON record whose "event"
// attribute equals name, failing the test when no such record was
// written.
func findLoggedEvent(tb testing.TB, out []byte, name string) map[string]any {
	tb.Helper()
	for _, line := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			tb.Fatalf("decode log line %q: %v", line, err)
		}
		if rec["event"] == name {
			return rec
		}
	}
	tb.Fatalf("no %q record was written; log was:\n%s", name, out)
	return nil
}
