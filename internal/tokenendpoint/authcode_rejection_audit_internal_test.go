package tokenendpoint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/grants/authcode"
	"github.com/libraz/go-oidc-provider/internal/pkce"
)

func TestWriteAuthCodeExchangeError_RejectionsReachAudit(t *testing.T) {
	t.Parallel()

	in := authCodeInputs{Code: "code-1", ClientID: "webapp", RedirectURI: "https://rp.example/cb2"}
	cases := []struct {
		name   string
		err    error
		event  string
		reason string
		body   string
	}{
		{"redirect_uri mismatch", authcode.ErrRedirectURIMismatch, string(auditevent.AuditRedirectURIMismatch), "", "authorization code rejected"},
		{"verifier mismatch", pkce.ErrVerifierMismatch, string(auditevent.AuditPKCEViolation), "verifier_mismatch", "PKCE verification failed"},
		{"verifier format", pkce.ErrVerifierFormat, string(auditevent.AuditPKCEViolation), "verifier_format", "PKCE verification failed"},
		{"method unsupported", pkce.ErrChallengeMethodUnsupported, string(auditevent.AuditPKCEViolation), "challenge_method_unsupported", "PKCE verification failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			capture := &captureEmitter{}
			w := httptest.NewRecorder()

			writeAuthCodeExchangeError(context.Background(), w, Deps{Audit: capture}, in, tc.err)

			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.body) {
				t.Fatalf("response = %d %s, want 400 carrying %q", w.Code, w.Body.String(), tc.body)
			}
			if len(capture.events) != 1 {
				t.Fatalf("events = %d, want 1", len(capture.events))
			}
			ev := capture.events[0]
			if ev.Name != tc.event || ev.Level != audit.LevelWarn || ev.ClientID != "webapp" {
				t.Fatalf("event = %q level %v client %q, want %q warn webapp", ev.Name, ev.Level, ev.ClientID, tc.event)
			}
			if ev.Extras["endpoint"] != "token" {
				t.Fatalf("extras.endpoint = %v, want token", ev.Extras["endpoint"])
			}
			if tc.reason == "" {
				if ev.Extras["redirect_uri"] != in.RedirectURI {
					t.Fatalf("extras.redirect_uri = %v, want %s", ev.Extras["redirect_uri"], in.RedirectURI)
				}
			} else if ev.Extras["reason"] != tc.reason {
				t.Fatalf("extras.reason = %v, want %s", ev.Extras["reason"], tc.reason)
			}
			if _, leaked := ev.Extras["code_verifier"]; leaked {
				t.Fatal("the verifier must not reach the audit stream")
			}
		})
	}
}
