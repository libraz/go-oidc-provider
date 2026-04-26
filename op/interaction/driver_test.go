package interaction_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

func TestJSONDriver_RenderEmitsJSONEnvelope(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	prompt := interaction.Prompt{
		Type:     "auth.password",
		Data:     interaction.PasswordPromptData{UsernameHint: "alice"},
		Inputs:   []interaction.FieldSpec{{Name: "password", Kind: interaction.FieldPassword, Required: true}},
		StateRef: "ref-1",
	}
	if err := (interaction.JSONDriver{}).Render(rec, httptest.NewRequestWithContext(context.Background(), "GET", "/interaction/u-1", nil), prompt); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var got struct {
		Type     string `json:"type"`
		StateRef string `json:"state_ref"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Type != prompt.Type || got.StateRef != prompt.StateRef {
		t.Errorf("envelope = %+v, want type=%s state_ref=%s", got, prompt.Type, prompt.StateRef)
	}
}

func TestJSONDriver_ParseSubmissionDecodesEnvelope(t *testing.T) {
	t.Parallel()

	body := `{"state_ref":"ref-1","values":{"password":"hunter2"}}`
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", strings.NewReader(body))
	sub, err := (interaction.JSONDriver{}).ParseSubmission(r)
	if err != nil {
		t.Fatalf("ParseSubmission: %v", err)
	}
	if sub.StateRef != "ref-1" {
		t.Errorf("StateRef = %q, want ref-1", sub.StateRef)
	}
	if sub.Values["password"] != "hunter2" {
		t.Errorf("Values[password] = %q, want hunter2", sub.Values["password"])
	}
}

func TestJSONDriver_ParseSubmissionRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	body := `{"state_ref":"ref-1","values":{},"extra":"reject"}`
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", strings.NewReader(body))
	_, err := (interaction.JSONDriver{}).ParseSubmission(r)
	if !errors.Is(err, interaction.ErrSubmissionMalformed) {
		t.Fatalf("err = %v, want ErrSubmissionMalformed", err)
	}
}

func TestJSONDriver_ParseSubmissionRejectsEmptyBody(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", bytes.NewReader(nil))
	_, err := (interaction.JSONDriver{}).ParseSubmission(r)
	if !errors.Is(err, interaction.ErrSubmissionMalformed) {
		t.Fatalf("err = %v, want ErrSubmissionMalformed", err)
	}
}
