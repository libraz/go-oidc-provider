package testkit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// ApproveAllScopes is the empty approved-scopes payload.
//
// Deprecated: an empty submission records an approval of nothing, not
// an approval of everything — a consent screen the user answered by
// clearing every box is a decision the OP honours. Use
// [ApprovedScopesFrom] to build the payload that approves what the
// screen actually presented.
const ApproveAllScopes = ""

// ApprovedScopesFrom returns the approved-scopes payload that approves
// every scope the consent prompt presented, read out of the envelope
// [IsConsentPrompt] returned.
//
// Building the payload from the envelope rather than from the
// authorization request is what makes it an approval: the OP decides
// which scopes reach the screen, and a test that submits the request's
// scope list instead would approve entries the user was never shown.
// The member names are the json tags of
// [interaction.ConsentScopePromptData] and [interaction.ConsentScope].
func ApprovedScopesFrom(tb testing.TB, envelope map[string]any) string {
	tb.Helper()
	data, _ := envelope["data"].(map[string]any)
	raw, _ := data["scopes"].([]any)
	if len(raw) == 0 {
		tb.Fatalf("testkit: consent envelope presented no scopes: %v", envelope)
	}
	names := make([]string, 0, len(raw))
	for _, entry := range raw {
		switch v := entry.(type) {
		case string:
			names = append(names, v)
		case map[string]any:
			if name, ok := v["name"].(string); ok && name != "" {
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		tb.Fatalf("testkit: consent envelope carried %d scope rows but no names: %v", len(raw), envelope)
	}
	return strings.Join(names, " ")
}

// IsConsentPrompt reports whether resp is a JSON envelope from the
// built-in consent screen. The test-side dispatcher
// branches on the result to decide whether the chain is complete or a
// consent submission is still pending.
//
// The function consumes resp.Body. Callers MUST treat the response as
// drained after the call; the function returns the parsed envelope so
// tests can read state_ref and the requested scope list without a
// second decode.
func IsConsentPrompt(resp *http.Response) (consent bool, envelope map[string]any, err error) {
	if resp == nil || resp.StatusCode != http.StatusOK {
		return false, nil, nil
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		return false, nil, nil
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil, fmt.Errorf("testkit: read consent response: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, nil, fmt.Errorf("testkit: decode consent response: %w", err)
	}
	if t, _ := out["type"].(string); t != interaction.PromptTypeConsentScope {
		return false, out, nil
	}
	return true, out, nil
}

// PostConsentApproval submits the built-in consent screen's
// approved_scopes form. csrfToken is the value of the __Host-oidc_csrf
// cookie attached to the prior /interaction response; stateRef is the
// state_ref the consent prompt embedded; origin is the Origin header
// the OP's CSRF middleware expects (typically the issuer URL).
//
// approved is the space-delimited approved-scope string. An empty
// string approves no scope (the chain rejects the submission unless
// no required scope was requested); pass [ApproveAllScopes] for the
// canonical "approve everything in the request" wire payload.
func PostConsentApproval(
	tb testing.TB,
	client *http.Client,
	interactionURL, origin, csrfToken, stateRef, approved string,
) *http.Response {
	tb.Helper()
	body := map[string]any{
		interaction.StateRefField: stateRef,
		"values":                  map[string]string{interaction.ConsentApprovedScopesField: approved},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		tb.Fatalf("testkit: marshal consent submission: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, interactionURL, bytes.NewReader(raw))
	if err != nil {
		tb.Fatalf("testkit: build consent request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	req.Header.Set(csrf.HeaderName, csrfToken)
	//nolint:gosec // G124: AddCookie serialises name=value only; Set-Cookie attributes never travel on a request.
	req.AddCookie(&http.Cookie{Name: cookie.CSRFProfile.Name, Value: csrfToken})
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("testkit: POST consent: %v", err)
	}
	return resp
}
