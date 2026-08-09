package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestAllowPlaintextRedis pins where the binary draws the line around an
// unencrypted Redis link: a loopback engine is the development
// arrangement op-demo exists for, a rediss:// DSN needs no escape hatch,
// and a plaintext link to anywhere else is refused rather than admitted
// unconditionally.
func TestAllowPlaintextRedis(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		dsn       string
		wantAllow bool
		wantErr   bool
	}{
		"loopback IPv4":      {dsn: "redis://127.0.0.1:6379/0", wantAllow: true},
		"loopback IPv6":      {dsn: "redis://[::1]:6379/0", wantAllow: true},
		"localhost":          {dsn: "redis://localhost:6379/0", wantAllow: true},
		"TLS needs no hatch": {dsn: "rediss://redis.internal:6380/0"},
		"remote plaintext":   {dsn: "redis://redis.internal:6379/0", wantErr: true},
		"private network":    {dsn: "redis://10.1.2.3:6379/0", wantErr: true},
		// An unsupported scheme is the adapter's error to report, so this
		// helper stays quiet and lets construction fail there.
		"other scheme": {dsn: "http://127.0.0.1:6379/0"},
	}

	for name, tc := range cases {
		allow, err := allowPlaintextRedis(tc.dsn)
		switch {
		case tc.wantErr && err == nil:
			t.Errorf("%s: allowPlaintextRedis(%q) = %v, nil; want an error", name, tc.dsn, allow)
		case !tc.wantErr && err != nil:
			t.Errorf("%s: allowPlaintextRedis(%q): %v", name, tc.dsn, err)
		case allow != tc.wantAllow:
			t.Errorf("%s: allow = %v, want %v", name, allow, tc.wantAllow)
		}
	}
}

// TestAllowPlaintextRedisErrorRedactsCredentials pins that the refusal
// names the engine without republishing the password the DSN carries.
func TestAllowPlaintextRedisErrorRedactsCredentials(t *testing.T) {
	t.Parallel()

	const dsn = "redis://opdemo:opdemo-secret@redis.internal:6379/0" //nolint:gosec // synthetic credential verifies redaction.
	_, err := allowPlaintextRedis(dsn)
	if err == nil {
		t.Fatal("allowPlaintextRedis: got nil error for a remote plaintext DSN")
	}
	if !strings.Contains(err.Error(), "redis.internal:6379") {
		t.Errorf("error = %q, want the endpoint named", err)
	}
	if strings.Contains(err.Error(), "opdemo-secret") {
		t.Errorf("error = %q, must not carry the DSN credentials", err)
	}
}

// TestPlaintextRedisWarningIsLogged pins that the adapter's warning
// reaches the binary's log. The sink is a required argument of the escape
// hatch precisely so an operator learns the link is unencrypted; a no-op
// closure satisfies the compiler and silences the one thing the argument
// exists for.
func TestPlaintextRedisWarningIsLogged(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	const dsn = "redis://opdemo:opdemo-secret@127.0.0.1:6379/0" //nolint:gosec // synthetic credential verifies redaction.

	plaintextRedisWarning(dsn, logger)("oidcredis: TLS is NOT being enforced")

	logged := buf.String()
	if !strings.Contains(logged, "TLS is NOT being enforced") {
		t.Errorf("log = %q, want the adapter's warning", logged)
	}
	if !strings.Contains(logged, "127.0.0.1:6379") {
		t.Errorf("log = %q, want the Redis endpoint named", logged)
	}
	if strings.Contains(logged, "opdemo-secret") {
		t.Errorf("log = %q, must not carry the DSN credentials", logged)
	}
}
