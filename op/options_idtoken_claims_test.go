package op_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

func TestWithIDTokenScopeClaims_Validation(t *testing.T) {
	t.Parallel()

	tenant := op.Scope{Name: "tenant", Public: true, Claims: []string{"tenant_id"}}
	rows := []struct {
		name    string
		opts    []op.Option
		wantErr string
	}{
		{name: "standard scopes", opts: []op.Option{op.WithIDTokenScopeClaims("profile", "email", "address", "phone")}},
		{name: "duplicates collapse", opts: []op.Option{op.WithIDTokenScopeClaims("email", "email")}},
		{
			name: "registered custom scope",
			opts: []op.Option{op.WithScope(tenant), op.WithIDTokenScopeClaims("tenant")},
		},
		{
			name: "custom scope registered after the option",
			opts: []op.Option{op.WithIDTokenScopeClaims("tenant"), op.WithScope(tenant)},
		},
		{name: "no arguments", opts: []op.Option{op.WithIDTokenScopeClaims()}, wantErr: "at least one scope"},
		{name: "empty name", opts: []op.Option{op.WithIDTokenScopeClaims("email", "")}, wantErr: "must not be empty"},
		{name: "openid", opts: []op.Option{op.WithIDTokenScopeClaims("openid")}, wantErr: "releases no claims"},
		{name: "offline_access", opts: []op.Option{op.WithIDTokenScopeClaims("offline_access")}, wantErr: "releases no claims"},
		{name: "unregistered name", opts: []op.Option{op.WithIDTokenScopeClaims("tenant")}, wantErr: "not a standard claim scope"},
		{
			name: "custom scope without claims",
			opts: []op.Option{
				op.WithScope(op.Scope{Name: "plain", Public: true}),
				op.WithIDTokenScopeClaims("plain"),
			},
			wantErr: "not a standard claim scope",
		},
		{
			name: "custom scope with a reserved claim",
			opts: []op.Option{
				op.WithScope(op.Scope{Name: "tenant", Public: true, Claims: []string{"tenant_id", "sub"}}),
				op.WithIDTokenScopeClaims("tenant"),
			},
			wantErr: "reserved ID Token claim sub",
		},
		{
			name: "standard scope overridden with a reserved claim",
			opts: []op.Option{
				op.WithScope(op.Scope{Name: "email", Public: true, Claims: []string{"email", "nonce"}}),
				op.WithIDTokenScopeClaims("email"),
			},
			wantErr: "reserved ID Token claim nonce",
		},
		{
			name:    "repeated call",
			opts:    []op.Option{op.WithIDTokenScopeClaims("email"), op.WithIDTokenScopeClaims("profile")},
			wantErr: "at most once",
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t), row.opts...)...)
			if row.wantErr == "" {
				if err != nil {
					t.Fatalf("op.New: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("op.New accepted the configuration, want error containing %q", row.wantErr)
			}
			if !strings.Contains(err.Error(), row.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, row.wantErr)
			}
		})
	}
}
