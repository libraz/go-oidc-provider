package op_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

func TestValidateInteractionUICapabilities(t *testing.T) {
	t.Parallel()

	overlay := interaction.TemplateOverlayDriver{Inner: interaction.HTMLDriver{}}

	tests := []struct {
		name    string
		extra   []op.Option
		wantErr bool
	}{
		{name: "default HTML driver", wantErr: true},
		{
			name:    "overlay value over HTML driver",
			extra:   []op.Option{op.WithInteractionDriver(overlay)},
			wantErr: true,
		},
		{
			name:    "overlay pointer over HTML driver",
			extra:   []op.Option{op.WithInteractionDriver(&overlay)},
			wantErr: true,
		},
		{
			name:  "embedder driver",
			extra: []op.Option{op.WithInteractionDriver(scriptedDriver{})},
		},
		{
			name:  "SPA UI",
			extra: []op.Option{op.WithSPAUI(op.SPAUI{LoginMount: "/login"})},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := op.New(append(passkeyFlowOpts(t), tc.extra...)...)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("op.New: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("op.New accepted a passkey step on the scriptless HTML driver")
			}
			if !strings.Contains(err.Error(), "WithSPAUI") {
				t.Fatalf("error does not name the remedy: %v", err)
			}
		})
	}
}
