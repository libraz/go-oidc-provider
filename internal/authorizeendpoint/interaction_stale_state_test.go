package authorizeendpoint_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestStaleActiveInputsRestart covers an interaction persisted by a build
// that wrote the field kind as a number. The chain state no longer
// decodes, and the ceremony restarts the way an expired one does (404)
// instead of failing with a server error.
func TestStaleActiveInputsRestart(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		inputs string
	}{
		{name: "numeric kind", inputs: `[{"name":"subject","kind":1}]`},
		{name: "go-named shape", inputs: `[{"Name":"subject","Kind":1}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t)
			start := startInteractionFlow(t, h)
			getResp := doInteractionGet(t, h, start)
			_, csrfCookie := readPromptStateRef(t, getResp)
			getResp.Body.Close()

			persistStaleActiveInputs(t, h, start.uid, tc.inputs)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				h.interactionPth+"/"+start.uid, http.NoBody)
			req.AddCookie(start.interactionCk)
			rr := httptest.NewRecorder()
			h.handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusNotFound {
				t.Fatalf("GET status=%d body=%s, want 404 (restart)", rr.Code, rr.Body.String())
			}

			post := postSubmission(t, h, start, csrfCookie, interaction.FormSubmission{
				Values: map[string]string{"subject": "user-1"},
			})
			if post.Code != http.StatusNotFound {
				t.Fatalf("POST status=%d body=%s, want 404 (restart)", post.Code, post.Body.String())
			}
		})
	}
}

// persistStaleActiveInputs rewrites the stored chain state's active_inputs
// to inputs, leaving the rest of the record as the endpoint wrote it.
func persistStaleActiveInputs(t *testing.T, h *testHarness, uid, inputs string) {
	t.Helper()
	ctx := context.Background()
	rec, err := h.store.Interactions().Find(ctx, uid)
	if err != nil {
		t.Fatalf("Find interaction: %v", err)
	}
	state, err := authorize.UnmarshalState(rec.RawState)
	if err != nil {
		t.Fatalf("UnmarshalState: %v", err)
	}
	chain := map[string]json.RawMessage{}
	if len(state.Authn) > 0 {
		if err := json.Unmarshal(state.Authn, &chain); err != nil {
			t.Fatalf("decode chain state: %v", err)
		}
	}
	chain["active_inputs"] = json.RawMessage(inputs)
	state.Authn, err = json.Marshal(chain)
	if err != nil {
		t.Fatalf("encode chain state: %v", err)
	}
	rec.RawState, err = authorize.MarshalState(state)
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	if err := h.store.Interactions().Save(ctx, rec); err != nil {
		t.Fatalf("Save interaction: %v", err)
	}
}
