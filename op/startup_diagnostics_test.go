package op_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
)

// startupOutput builds a Provider on the in-memory store with a capturing
// logger at INFO and returns what construction logged.
func startupOutput(t *testing.T, opts ...op.Option) string {
	t.Helper()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	all := append(validBaseOptsWithInmem(t), op.WithLogger(logger))
	if _, err := op.New(append(all, opts...)...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
	return buf.String()
}

// linesContaining returns the log lines of out that contain sub.
func linesContaining(out, sub string) []string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, sub) {
			lines = append(lines, line)
		}
	}
	return lines
}

func seedWithGrants(grants ...string) op.Option {
	return op.WithStaticClients(op.PublicClient{
		ID:           "seed-app",
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid"},
		GrantTypes:   grants,
	})
}

type allowAllTokenExchange struct{}

func (allowAllTokenExchange) Allow(context.Context, op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	return &op.TokenExchangeDecision{}, nil
}

const deviceCodeURN = "urn:ietf:params:oauth:grant-type:device_code"

// TestNew_WarnsOncePerUnenabledSeedGrant pins the startup warning for a
// static client seed naming a grant the OP has not enabled.
func TestNew_WarnsOncePerUnenabledSeedGrant(t *testing.T) {
	t.Parallel()

	const marker = "lists grant_type"
	cases := []struct {
		name       string
		opts       []op.Option
		wantLines  int
		wantInLine []string
	}{
		{
			name:       "device code not enabled, listed twice",
			opts:       []op.Option{seedWithGrants("authorization_code", deviceCodeURN, deviceCodeURN)},
			wantLines:  1,
			wantInLine: []string{"level=WARN", "static client seed-app", deviceCodeURN, "WithDeviceCodeGrant()"},
		},
		{
			name:       "token exchange not registered",
			opts:       []op.Option{seedWithGrants("authorization_code", op.TokenExchangeGrantType)},
			wantLines:  1,
			wantInLine: []string{"level=WARN", "seed-app", op.TokenExchangeGrantType, "RegisterTokenExchange(...)"},
		},
		{
			name: "token exchange registered",
			opts: []op.Option{
				seedWithGrants("authorization_code", op.TokenExchangeGrantType),
				op.RegisterTokenExchange(allowAllTokenExchange{}),
			},
		},
		{
			name: "default grants",
			opts: []op.Option{seedWithGrants("authorization_code", "refresh_token")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lines := linesContaining(startupOutput(t, tc.opts...), marker)
			if len(lines) != tc.wantLines {
				t.Fatalf("lines = %d, want %d:\n%s", len(lines), tc.wantLines, strings.Join(lines, "\n"))
			}
			for _, want := range tc.wantInLine {
				if !strings.Contains(lines[0], want) {
					t.Errorf("line does not contain %q:\n%s", want, lines[0])
				}
			}
		})
	}
}

// TestNew_SeedGrantWarningNamesDefaultedGrants pins that a seed which left
// GrantTypes empty is told its defaults include the unenabled grant, while
// an explicit list keeps the "lists grant_type" wording.
func TestNew_SeedGrantWarningNamesDefaultedGrants(t *testing.T) {
	t.Parallel()

	const marker = "static client seed-app"
	t.Run("defaulted", func(t *testing.T) {
		t.Parallel()

		lines := linesContaining(startupOutput(t, op.WithGrants(grant.AuthorizationCode), seedWithGrants()), marker)
		if len(lines) != 1 {
			t.Fatalf("lines = %d, want 1:\n%s", len(lines), strings.Join(lines, "\n"))
		}
		for _, want := range []string{
			"level=WARN", "left GrantTypes empty", "default grant types include refresh_token",
			"WithGrants(..., grant.RefreshToken)", "set GrantTypes explicitly",
		} {
			if !strings.Contains(lines[0], want) {
				t.Errorf("line does not contain %q:\n%s", want, lines[0])
			}
		}
		if strings.Contains(lines[0], "lists grant_type") {
			t.Errorf("defaulted seed reported as listing the grant:\n%s", lines[0])
		}
	})
	t.Run("explicit", func(t *testing.T) {
		t.Parallel()

		lines := linesContaining(startupOutput(t,
			op.WithGrants(grant.AuthorizationCode), seedWithGrants("authorization_code", "refresh_token")), marker)
		if len(lines) != 1 || !strings.Contains(lines[0], "lists grant_type refresh_token") {
			t.Fatalf("want one \"lists grant_type\" line:\n%s", strings.Join(lines, "\n"))
		}
		if strings.Contains(lines[0], "set GrantTypes explicitly") {
			t.Errorf("explicit seed told to set GrantTypes:\n%s", lines[0])
		}
	})
}

const noLoggerMarker = "request-time operational logs and audit records are discarded"

// TestNew_WarnsWhenNoLoggerConfigured pins the warning that request-time
// logs and audit records are discarded, and its absence once either logger
// option is set.
func TestNew_WarnsWhenNoLoggerConfigured(t *testing.T) { //nolint:paralleltest // swaps the process-wide slog default.
	cases := []struct {
		name string
		opt  func() op.Option
		want bool
	}{
		{name: "no logger", want: true},
		{name: "WithLogger", opt: func() op.Option { return op.WithLogger(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))) }},
		{name: "WithAuditLogger", opt: func() op.Option { return op.WithAuditLogger(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))) }},
	}
	for _, tc := range cases { //nolint:paralleltest // swaps the process-wide slog default.
		t.Run(tc.name, func(t *testing.T) {
			buf := swapDefaultLogger(t)
			opts := validBaseOptsWithInmem(t)
			if tc.opt != nil {
				opts = append(opts, tc.opt())
			}
			if _, err := op.New(opts...); err != nil {
				t.Fatalf("op.New: %v", err)
			}
			lines := linesContaining(buf.String(), noLoggerMarker)
			if got := len(lines) == 1; got != tc.want {
				t.Fatalf("warning present = %v, want %v; default logger:\n%s", got, tc.want, buf.String())
			}
			if tc.want && !strings.Contains(lines[0], `"level":"WARN"`) {
				t.Fatalf("not a WARN: %s", lines[0])
			}
		})
	}
}

// TestNew_LogsPrivateNetworkReach pins the INFO line per enabled
// private-network option and its escalation to WARN when an unauthenticated
// caller can choose the fetched URL.
func TestNew_LogsPrivateNetworkReach(t *testing.T) {
	t.Parallel()

	openDCR := op.WithDynamicRegistration(op.RegistrationOption{Open: true})
	iatDCR := op.WithDynamicRegistration(op.RegistrationOption{})
	cimd := op.WithClientIDMetadataDocuments(op.ClientIDMetadataDocuments{})
	cases := []struct {
		name    string
		option  string
		reach   op.Option
		others  []op.Option
		level   string
		wantMsg string
	}{
		{name: "JWKS alone", option: "WithAllowPrivateNetworkJWKS", reach: op.WithAllowPrivateNetworkJWKS(), level: "INFO"},
		{name: "JAR alone", option: "WithAllowPrivateNetworkJAR", reach: op.WithAllowPrivateNetworkJAR(), level: "INFO"},
		{name: "Sector alone", option: "WithAllowPrivateNetworkSector", reach: op.WithAllowPrivateNetworkSector(), level: "INFO"},
		{
			name: "ClientIDMetadata alone", option: "WithAllowPrivateNetworkClientIDMetadata",
			reach: op.WithAllowPrivateNetworkClientIDMetadata(), level: "INFO",
		},
		{
			name: "Backchannel alone", option: "WithAllowPrivateNetworkBackchannel",
			reach: op.WithAllowPrivateNetworkBackchannel(), level: "INFO",
		},
		{
			name: "SharedSignals alone", option: "WithAllowPrivateNetworkSharedSignals",
			reach: op.WithAllowPrivateNetworkSharedSignals(), level: "INFO",
		},
		{
			name: "JWKS with IAT-gated registration", option: "WithAllowPrivateNetworkJWKS",
			reach: op.WithAllowPrivateNetworkJWKS(), others: []op.Option{iatDCR}, level: "INFO",
		},
		{
			name: "JWKS with open registration", option: "WithAllowPrivateNetworkJWKS",
			reach: op.WithAllowPrivateNetworkJWKS(), others: []op.Option{openDCR}, level: "WARN",
			wantMsg: "open dynamic registration",
		},
		{
			name: "Sector with open registration", option: "WithAllowPrivateNetworkSector",
			reach: op.WithAllowPrivateNetworkSector(), others: []op.Option{openDCR}, level: "WARN",
			wantMsg: "SSRF exposure",
		},
		{
			name: "JAR with client ID metadata documents", option: "WithAllowPrivateNetworkJAR",
			reach: op.WithAllowPrivateNetworkJAR(), others: []op.Option{cimd}, level: "WARN",
			wantMsg: "Client ID Metadata Documents",
		},
		{
			name: "Backchannel with open registration", option: "WithAllowPrivateNetworkBackchannel",
			reach: op.WithAllowPrivateNetworkBackchannel(), others: []op.Option{openDCR}, level: "WARN",
			wantMsg: "open dynamic registration",
		},
		{
			name: "Backchannel with IAT-gated registration", option: "WithAllowPrivateNetworkBackchannel",
			reach: op.WithAllowPrivateNetworkBackchannel(), others: []op.Option{iatDCR}, level: "INFO",
		},
		{
			name: "SharedSignals with open registration", option: "WithAllowPrivateNetworkSharedSignals",
			reach: op.WithAllowPrivateNetworkSharedSignals(), others: []op.Option{openDCR}, level: "INFO",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := startupOutput(t, append([]op.Option{tc.reach}, tc.others...)...)
			lines := linesContaining(out, tc.option+" is enabled")
			if len(lines) != 1 {
				t.Fatalf("lines naming %s = %d, want 1:\n%s", tc.option, len(lines), out)
			}
			if !strings.Contains(lines[0], "level="+tc.level) {
				t.Fatalf("want level %s: %s", tc.level, lines[0])
			}
			if tc.wantMsg != "" && !strings.Contains(lines[0], tc.wantMsg) {
				t.Fatalf("line does not contain %q: %s", tc.wantMsg, lines[0])
			}
		})
	}
}

// TestNew_KeyMaterialMessages pins the remedy and the received length in
// the key-shape errors.
func TestNew_KeyMaterialMessages(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opt  func() op.Option
		want string
	}{
		{
			name: "RSA active key under ES256 suggests RS256",
			opt:  func() op.Option { return op.WithKeyset(op.Keyset{newRSATestKey(t, "rsa", 2048)}) },
			want: "add WithSigningAlgorithm(op.AlgRS256)",
		},
		{
			name: "cookie key length",
			opt:  func() op.Option { return op.WithCookieKeys(make([]byte, 16)) },
			want: "WithCookieKeys: entry 0 is not 32 bytes (got 16)",
		},
		{
			name: "MFA key length",
			opt:  func() op.Option { return op.WithMFAEncryptionKeys(make([]byte, 31)) },
			want: "WithMFAEncryptionKeys: entry 0 is not 32 bytes (got 31)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := op.New(append(validBaseOpts(t), tc.opt())...)
			wantConfigurationError(t, err, tc.want)
		})
	}
}

// TestNew_NoRS256HintForOtherKeyTypes pins that the RS256 remedy is offered
// only for a key RS256 can use.
func TestNew_NoRS256HintForOtherKeyTypes(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithKeyset(op.Keyset{newP384TestKey(t, "p384")}))...)
	if err == nil {
		t.Fatal("op.New accepted a P-384 active key")
	}
	if strings.Contains(err.Error(), "WithSigningAlgorithm") {
		t.Fatalf("unexpected RS256 hint: %v", err)
	}
}
