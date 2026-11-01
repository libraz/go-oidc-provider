//nolint:testpackage // exercises unexported helpers
package tokenexchange

import (
	"context"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/op/store"
)

func TestTranslateLookupErr_MessageNamesTheRejectedToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		reason    string
		isSubject bool
		wantEvent string
		wantToken string
		banToken  string
	}{
		{"subject registry fault", reasonRegistryError, true, auditSubjectTokenRegistryError, "subject_token", "actor_token"},
		{"actor registry fault", reasonRegistryError, false, auditSubjectTokenRegistryError, "actor_token", "subject_token"},
		{"subject invalid", "expired", true, auditSubjectTokenInvalid, "subject_token", "actor_token"},
		{"actor invalid", "expired", false, auditSubjectTokenInvalid, "actor_token", "subject_token"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			emitter := &recordingEmitter{}
			h := &Handler{audit: emitter}
			err := h.translateLookupErr(context.Background(), &store.Client{ID: "caller"}, errTokenInvalid,
				lookupResult{reason: tc.reason}, tc.isSubject)
			if err == nil {
				t.Fatal("translateLookupErr returned nil")
			}
			if len(emitter.events) != 1 {
				t.Fatalf("events=%v, want one", eventNames(emitter.events))
			}
			ev := emitter.events[0]
			if ev.Name != tc.wantEvent {
				t.Errorf("event=%q, want %q", ev.Name, tc.wantEvent)
			}
			if !strings.Contains(ev.Message, tc.wantToken) || strings.Contains(ev.Message, tc.banToken) {
				t.Errorf("message %q must name %s and not %s", ev.Message, tc.wantToken, tc.banToken)
			}
			if got, _ := ev.Extras["is_subject"].(bool); got != tc.isSubject {
				t.Errorf("extras.is_subject=%v, want %v", got, tc.isSubject)
			}
			if tc.wantEvent == auditSubjectTokenRegistryError && ev.Level != audit.LevelWarn {
				t.Errorf("level=%v, want warn", ev.Level)
			}
		})
	}
}
