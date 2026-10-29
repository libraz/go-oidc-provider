package op_test

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
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

// TestValidateInteractionUICapabilities_PasskeyInsideOneOf pins that a
// passkey offered only through a StepOneOf is still rejected behind the
// scriptless HTML driver.
func TestValidateInteractionUICapabilities_PasskeyInsideOneOf(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	opts := append(validBaseOptsWithStoreNoAuthn(t, st),
		op.WithLoginFlow(flowWithRule(op.StepOneOf{Steps: []op.Step{
			op.PrimaryPasskey{
				Store:         st.Passkeys(),
				RPID:          "id.example.com",
				RPDisplayName: "Example",
				RPOrigins:     []string{"https://id.example.com"},
			},
			op.ExternalStep{Authenticator: stubExternalAuthenticator{}, KindLabel: op.StepKind("test.second")},
		}})),
	)
	_, err := op.New(opts...)
	if err == nil {
		t.Fatal("op.New accepted a passkey inside a StepOneOf on the scriptless HTML driver")
	}
	if !strings.Contains(err.Error(), "WithSPAUI") {
		t.Fatalf("error does not name the remedy: %v", err)
	}
}
