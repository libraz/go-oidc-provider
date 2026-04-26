package interaction_test

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

func TestNoopDriver_OfferReturnsLoginPromptWithReason(t *testing.T) {
	t.Parallel()

	step, err := interaction.NoopDriver{}.Offer(context.Background(), interaction.Request{UID: "u-1"})
	if err != nil {
		t.Fatalf("Offer returned err=%v", err)
	}
	if step.Hint.Prompt != interaction.PromptLogin {
		t.Errorf("Prompt=%q want %q", step.Hint.Prompt, interaction.PromptLogin)
	}
	if len(step.Hint.Reasons) == 0 || step.Hint.Reasons[0] != "no_driver_configured" {
		t.Errorf("Reasons=%v want [no_driver_configured]", step.Hint.Reasons)
	}
}

func TestNoopDriver_VerifySurfacesError(t *testing.T) {
	t.Parallel()

	dec, err := interaction.NoopDriver{}.Verify(context.Background(), interaction.Request{}, interaction.Result{})
	if err != nil {
		t.Fatalf("Verify returned err=%v", err)
	}
	if dec.Continue {
		t.Error("NoopDriver must never request a follow-up step")
	}
	if dec.Error == "" {
		t.Error("NoopDriver must surface an error string")
	}
}

func TestNoopDriver_CancelIsNoop(t *testing.T) {
	t.Parallel()

	if err := (interaction.NoopDriver{}).Cancel(context.Background(), interaction.Request{}); err != nil {
		t.Errorf("Cancel returned err=%v", err)
	}
}
