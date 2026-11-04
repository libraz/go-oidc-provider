package op_test

import (
	"context"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

const logoutUIConfirmSrc = `LOGOUT-UI-CONFIRM<form method="{{.SubmitMethod}}" action="{{.SubmitAction}}">` +
	`{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}</form>`

func logoutUITemplate(t *testing.T, name, src string) *template.Template {
	t.Helper()
	return template.Must(template.New(name).Parse(src))
}

func TestWithLogoutUI_Validation(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name    string
		opts    func(t *testing.T) []op.Option
		wantErr string
	}{
		{
			name: "valid with default CSP",
			opts: func(t *testing.T) []op.Option {
				return []op.Option{op.WithLogoutUI(op.LogoutUI{
					ConfirmTemplate:   logoutUITemplate(t, "c", logoutUIConfirmSrc),
					SignedOutTemplate: logoutUITemplate(t, "s", "signed out"),
				})}
			},
		},
		{
			name: "zero value",
			opts: func(*testing.T) []op.Option {
				return []op.Option{op.WithLogoutUI(op.LogoutUI{})}
			},
			wantErr: "ConfirmTemplate must not be nil",
		},
		{
			name: "nil confirm template",
			opts: func(t *testing.T) []op.Option {
				return []op.Option{op.WithLogoutUI(op.LogoutUI{SignedOutTemplate: logoutUITemplate(t, "s", "x")})}
			},
			wantErr: "ConfirmTemplate must not be nil",
		},
		{
			name: "nil signed-out template",
			opts: func(t *testing.T) []op.Option {
				return []op.Option{op.WithLogoutUI(op.LogoutUI{ConfirmTemplate: logoutUITemplate(t, "c", logoutUIConfirmSrc)})}
			},
			wantErr: "SignedOutTemplate must not be nil",
		},
		{
			name: "repeated call",
			opts: func(t *testing.T) []op.Option {
				ui := op.LogoutUI{
					ConfirmTemplate:   logoutUITemplate(t, "c", logoutUIConfirmSrc),
					SignedOutTemplate: logoutUITemplate(t, "s", "x"),
				}
				return []op.Option{op.WithLogoutUI(ui), op.WithLogoutUI(ui)}
			},
			wantErr: "at most once",
		},
		{
			name: "CSP rejected",
			opts: func(t *testing.T) []op.Option {
				return []op.Option{op.WithLogoutUI(op.LogoutUI{
					ConfirmTemplate:       logoutUITemplate(t, "c", logoutUIConfirmSrc),
					SignedOutTemplate:     logoutUITemplate(t, "s", "x"),
					ContentSecurityPolicy: "default-src 'none'; form-action 'self'",
				})}
			},
			wantErr: "ContentSecurityPolicy rejected",
		},
		{
			name: "confirm template omits Fields",
			opts: func(t *testing.T) []op.Option {
				return []op.Option{op.WithLogoutUI(op.LogoutUI{
					ConfirmTemplate:   logoutUITemplate(t, "c", `<form method="{{.SubmitMethod}}" action="{{.SubmitAction}}"></form>`),
					SignedOutTemplate: logoutUITemplate(t, "s", "x"),
				})}
			},
			wantErr: "must render every entry of Fields",
		},
		{
			name: "confirm template renders only some Fields",
			opts: func(t *testing.T) []op.Option {
				return []op.Option{op.WithLogoutUI(op.LogoutUI{
					ConfirmTemplate: logoutUITemplate(t, "c",
						`{{with index .Fields 0}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}`),
					SignedOutTemplate: logoutUITemplate(t, "s", "x"),
				})}
			},
			wantErr: "must render every entry of Fields",
		},
		{
			name: "confirm template fails to execute",
			opts: func(t *testing.T) []op.Option {
				return []op.Option{op.WithLogoutUI(op.LogoutUI{
					ConfirmTemplate:   logoutUITemplate(t, "c", `{{.NoSuchField}}`),
					SignedOutTemplate: logoutUITemplate(t, "s", "x"),
				})}
			},
			wantErr: "failed to execute",
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			_, err := op.New(append(validBaseOpts(t), row.opts(t)...)...)
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

func TestWithLogoutUI_ComposesWithSPAUI(t *testing.T) {
	t.Parallel()

	for name, order := range map[string]func(spa, logout op.Option) []op.Option{
		"SPA first":    func(spa, logout op.Option) []op.Option { return []op.Option{spa, logout} },
		"logout first": func(spa, logout op.Option) []op.Option { return []op.Option{logout, spa} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			spa := op.WithUI(op.SPAUI{LoginMount: "/login"})
			logout := op.WithLogoutUI(op.LogoutUI{
				ConfirmTemplate:   logoutUITemplate(t, "c", logoutUIConfirmSrc),
				SignedOutTemplate: logoutUITemplate(t, "s", "signed out"),
			})
			provider, err := op.New(append(validBaseOpts(t), order(spa, logout)...)...)
			if err != nil {
				t.Fatalf("op.New: %v", err)
			}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				validIssuer+endSessionCeremonyPath, http.NoBody)
			resp := serveCeremony(t, provider, req)
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "LOGOUT-UI-CONFIRM") {
				t.Errorf("status=%d body=%q, want the embedder confirmation template", resp.StatusCode, body)
			}
			if !strings.Contains(string(body), `name="logout_csrf"`) {
				t.Errorf("body lacks the logout_csrf hidden field: %s", body)
			}
		})
	}
}
