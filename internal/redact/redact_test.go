package redact_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/redact"
)

func TestIsSensitive(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key  string
		want bool
	}{
		{"access_token", true},
		{"Access_Token", true},
		{"ACCESS-TOKEN", true},
		{"set-cookie", true},
		{"Set-Cookie", true},
		{"refresh_token", true},
		{"id_token", true},
		{"code", true},
		{"code_verifier", true},
		{"client_secret", true},
		{"password", true},
		{"state", true},
		{"nonce", true},
		{"dpop", true},
		{"DPoP", true},
		{"Authorization", true},
		{"request", true},
		{"request_uri", true},
		{"Request-URI", true},
		{"client_id", false},
		{"sub", false},
		{"iss", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			t.Parallel()
			if got := redact.IsSensitive(tc.key); got != tc.want {
				t.Fatalf("IsSensitive(%q) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}

func TestWrapHandler_RedactsTopLevelAttr(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(redact.WrapHandler(slog.NewJSONHandler(&buf, nil)))

	logger.Info("token issued",
		slog.String("client_id", "cid-123"),
		slog.String("access_token", "shh-its-a-secret"),
	)

	rec := decodeJSON(t, buf.Bytes())
	if got := rec["client_id"]; got != "cid-123" {
		t.Fatalf("client_id should be unredacted, got %v", got)
	}
	if got := rec["access_token"]; got != redact.Sentinel {
		t.Fatalf("access_token should be redacted, got %v", got)
	}
}

func TestWrapHandler_RedactsInsideGroup(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(redact.WrapHandler(slog.NewJSONHandler(&buf, nil)))

	logger.Info("nested",
		slog.Group("body",
			slog.String("client_id", "cid-456"),
			slog.String("refresh_token", "shh-its-a-secret"),
		),
	)

	rec := decodeJSON(t, buf.Bytes())
	body, ok := rec["body"].(map[string]any)
	if !ok {
		t.Fatalf("expected body group, got %T", rec["body"])
	}
	if got := body["client_id"]; got != "cid-456" {
		t.Fatalf("nested client_id should be unredacted, got %v", got)
	}
	if got := body["refresh_token"]; got != redact.Sentinel {
		t.Fatalf("nested refresh_token should be redacted, got %v", got)
	}
}

func TestWrapHandler_RedactsWithAttrs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	base := slog.New(redact.WrapHandler(slog.NewJSONHandler(&buf, nil)))
	scoped := base.With(slog.String("id_token", "shh-its-a-secret"))

	scoped.Info("scoped")

	rec := decodeJSON(t, buf.Bytes())
	if got := rec["id_token"]; got != redact.Sentinel {
		t.Fatalf("scoped id_token should be redacted, got %v", got)
	}
}

func TestWrapHandler_Idempotent(t *testing.T) {
	t.Parallel()

	base := slog.NewJSONHandler(&bytes.Buffer{}, nil)
	once := redact.WrapHandler(base)
	twice := redact.WrapHandler(once)
	if once != twice {
		t.Fatalf("WrapHandler should be idempotent; got distinct handlers")
	}
}

func TestWrapHandler_NilFallsBackToDiscard(t *testing.T) {
	t.Parallel()

	h := redact.WrapHandler(nil)
	if h == nil {
		t.Fatalf("WrapHandler(nil) returned nil")
	}
	logger := slog.New(h)
	logger.Info("ignored", slog.String("access_token", "shh-its-a-secret"))
}

func TestReplaceAttr_RedactsSensitive(t *testing.T) {
	t.Parallel()

	got := redact.ReplaceAttr(nil, slog.String("password", "shh-its-a-secret"))
	if got.Key != "password" || got.Value.String() != redact.Sentinel {
		t.Fatalf("expected redacted, got key=%q value=%q", got.Key, got.Value.String())
	}
}

func TestReplaceAttr_PassesThroughBenign(t *testing.T) {
	t.Parallel()

	in := slog.String("client_id", "cid-789")
	got := redact.ReplaceAttr(nil, in)
	if got.Value.String() != "cid-789" {
		t.Fatalf("expected pass-through, got %q", got.Value.String())
	}
}

func TestMask(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty",
			in:   "",
			want: "",
		},
		{
			name: "no_pairs",
			in:   "hello world",
			want: "hello world",
		},
		{
			name: "single_sensitive",
			in:   "code=shh-its-a-secret",
			want: "code=" + redact.Sentinel,
		},
		{
			name: "mixed_pairs",
			in:   "client_id=cid&code=shh-its-a-secret&state=opaque",
			want: "client_id=cid&code=" + redact.Sentinel + "&state=" + redact.Sentinel,
		},
		{
			name: "preserves_separator",
			in:   "code=secret;state=opaque",
			want: "code=" + redact.Sentinel + ";state=" + redact.Sentinel,
		},
		{
			name: "leaves_non_kv",
			in:   "verb=GET path=/oidc/token",
			want: "verb=GET path=/oidc/token",
		},
		{
			name: "url_query",
			in:   "https://op.example.com/cb?code=secret&iss=https://op",
			want: "https://op.example.com/cb?code=" + redact.Sentinel + "&iss=https://op",
		},
		{
			name: "case_insensitive_key",
			in:   "Access_Token=shh-its-a-secret",
			want: "Access_Token=" + redact.Sentinel,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := redact.Mask(tc.in); got != tc.want {
				t.Fatalf("Mask(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestWrapHandler_RespectsLevel(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	opts := &slog.HandlerOptions{Level: slog.LevelWarn}
	logger := slog.New(redact.WrapHandler(slog.NewJSONHandler(&buf, opts)))

	logger.Info("dropped", slog.String("access_token", "shh-its-a-secret"))
	if buf.Len() != 0 {
		t.Fatalf("info-level record should not have been emitted: %s", buf.String())
	}

	logger.Warn("kept", slog.String("access_token", "shh-its-a-secret"))
	rec := decodeJSON(t, buf.Bytes())
	if got := rec["access_token"]; got != redact.Sentinel {
		t.Fatalf("expected redacted access_token in warn record, got %v", got)
	}
}

func TestWrapHandler_WithGroup(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	base := slog.New(redact.WrapHandler(slog.NewJSONHandler(&buf, nil)))

	base.WithGroup("req").Info("hit",
		slog.String("client_id", "cid"),
		slog.String("code", "shh-its-a-secret"),
	)

	out := buf.String()
	if !strings.Contains(out, `"client_id":"cid"`) {
		t.Fatalf("expected client_id under group, got %s", out)
	}
	if !strings.Contains(out, `"code":"`+redact.Sentinel+`"`) {
		t.Fatalf("expected redacted code under group, got %s", out)
	}
}

func decodeJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatalf("decode JSON record: %v\nbody: %s", err, string(b))
	}
	return rec
}
