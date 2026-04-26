package consent_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/consent"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

func sampleCatalog() []interaction.ConsentScope {
	return []interaction.ConsentScope{
		{Name: "openid", Description: "Sign you in", Required: true},
		{Name: "profile", Description: "Profile info"},
		{Name: "email", Description: "Email address"},
	}
}

func TestInteraction_Metadata(t *testing.T) {
	t.Parallel()

	i := consent.New(sampleCatalog())
	if got := i.Name(); got != consent.Name {
		t.Errorf("Name() = %q, want %q", got, consent.Name)
	}
	if got := i.Trigger(); got != authn.TriggerAfterAuthn {
		t.Errorf("Trigger() = %v, want TriggerAfterAuthn", got)
	}
}

func TestInteraction_BeginEmitsPromptWithCatalogProjection(t *testing.T) {
	t.Parallel()

	i := consent.New(sampleCatalog())
	step, err := i.Begin(context.Background(), authn.BeginInput{
		Subject:         "user-1",
		ClientID:        "rp-1",
		AuthTime:        time.Now(),
		RequestedScopes: []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if step.Prompt == nil {
		t.Fatalf("expected Prompt, got %+v", step)
	}
	if step.Prompt.Type != consent.PromptType {
		t.Errorf("Prompt.Type = %q, want %q", step.Prompt.Type, consent.PromptType)
	}
	data, ok := step.Prompt.Data.(interaction.ConsentScopePromptData)
	if !ok {
		t.Fatalf("Prompt.Data type = %T, want ConsentScopePromptData", step.Prompt.Data)
	}
	if len(data.Scopes) != 3 {
		t.Fatalf("Scopes len = %d, want 3", len(data.Scopes))
	}
	if data.Scopes[0].Name != "openid" || !data.Scopes[0].Required {
		t.Errorf("Scopes[0] = %+v, want openid required", data.Scopes[0])
	}
	if len(step.Prompt.Inputs) != 1 || step.Prompt.Inputs[0].Name != consent.ApprovedScopesField {
		t.Errorf("Inputs = %+v, want one entry named %q", step.Prompt.Inputs, consent.ApprovedScopesField)
	}
}

func TestInteraction_BeginRendersUnknownScopeMinimally(t *testing.T) {
	t.Parallel()

	i := consent.New(sampleCatalog())
	step, err := i.Begin(context.Background(), authn.BeginInput{
		Subject:         "user-1",
		RequestedScopes: []string{"openid", "myorg.custom"},
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	data := step.Prompt.Data.(interaction.ConsentScopePromptData)
	if len(data.Scopes) != 2 {
		t.Fatalf("Scopes len = %d, want 2", len(data.Scopes))
	}
	if data.Scopes[1].Name != "myorg.custom" {
		t.Errorf("unknown scope dropped: %+v", data.Scopes)
	}
	if data.Scopes[1].Description != "" || data.Scopes[1].Required {
		t.Errorf("unknown scope should be minimal: %+v", data.Scopes[1])
	}
}

func TestInteraction_BeginRequiresSubject(t *testing.T) {
	t.Parallel()

	i := consent.New(sampleCatalog())
	_, err := i.Begin(context.Background(), authn.BeginInput{
		RequestedScopes: []string{"openid"},
	})
	if !errors.Is(err, consent.ErrSubjectRequired) {
		t.Fatalf("err = %v, want ErrSubjectRequired", err)
	}
}

func TestInteraction_ContinueReturnsApprovedScopes(t *testing.T) {
	t.Parallel()

	i := consent.New(sampleCatalog())
	step, err := i.Continue(context.Background(), authn.ContinueInput{
		Subject:         "user-1",
		RequestedScopes: []string{"openid", "profile", "email"},
		Submission: interaction.FormSubmission{
			Values: map[string]string{consent.ApprovedScopesField: "openid profile"},
		},
	})
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected Result, got %+v", step)
	}
	if len(step.Result.Scope) != 2 {
		t.Fatalf("Scope len = %d, want 2", len(step.Result.Scope))
	}
	if step.Result.Scope[0] != "openid" || step.Result.Scope[1] != "profile" {
		t.Errorf("Scope = %v, want [openid profile]", step.Result.Scope)
	}
}

func TestInteraction_ContinuePreservesRequestOrder(t *testing.T) {
	t.Parallel()

	i := consent.New(sampleCatalog())
	step, err := i.Continue(context.Background(), authn.ContinueInput{
		Subject:         "user-1",
		RequestedScopes: []string{"openid", "profile", "email"},
		Submission: interaction.FormSubmission{
			Values: map[string]string{consent.ApprovedScopesField: "email openid profile"},
		},
	})
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected Result")
	}
	want := []string{"openid", "profile", "email"}
	for i, name := range want {
		if step.Result.Scope[i] != name {
			t.Errorf("Scope[%d] = %q, want %q (request order must win)", i, step.Result.Scope[i], name)
		}
	}
}

func TestInteraction_ContinueRejectsScopeNotInRequest(t *testing.T) {
	t.Parallel()

	i := consent.New(sampleCatalog())
	_, err := i.Continue(context.Background(), authn.ContinueInput{
		Subject:         "user-1",
		RequestedScopes: []string{"openid"},
		Submission: interaction.FormSubmission{
			Values: map[string]string{consent.ApprovedScopesField: "openid email"},
		},
	})
	if !errors.Is(err, consent.ErrApprovedScopeNotRequested) {
		t.Fatalf("err = %v, want ErrApprovedScopeNotRequested", err)
	}
}

func TestInteraction_ContinueRejectsRequiredScopeDecline(t *testing.T) {
	t.Parallel()

	i := consent.New(sampleCatalog())
	_, err := i.Continue(context.Background(), authn.ContinueInput{
		Subject:         "user-1",
		RequestedScopes: []string{"openid", "profile"},
		Submission: interaction.FormSubmission{
			Values: map[string]string{consent.ApprovedScopesField: "profile"},
		},
	})
	if !errors.Is(err, consent.ErrRequiredScopeDeclined) {
		t.Fatalf("err = %v, want ErrRequiredScopeDeclined", err)
	}
}

func TestInteraction_ContinueRequiresSubject(t *testing.T) {
	t.Parallel()

	i := consent.New(sampleCatalog())
	_, err := i.Continue(context.Background(), authn.ContinueInput{
		RequestedScopes: []string{"openid"},
		Submission: interaction.FormSubmission{
			Values: map[string]string{consent.ApprovedScopesField: "openid"},
		},
	})
	if !errors.Is(err, consent.ErrSubjectRequired) {
		t.Fatalf("err = %v, want ErrSubjectRequired", err)
	}
}

func TestInteraction_ContinueRequiresApprovedScopesField(t *testing.T) {
	t.Parallel()

	i := consent.New(sampleCatalog())
	_, err := i.Continue(context.Background(), authn.ContinueInput{
		Subject:         "user-1",
		RequestedScopes: []string{"openid"},
		Submission:      interaction.FormSubmission{Values: map[string]string{}},
	})
	if !errors.Is(err, consent.ErrApprovedScopesMissing) {
		t.Fatalf("err = %v, want ErrApprovedScopesMissing", err)
	}
}
