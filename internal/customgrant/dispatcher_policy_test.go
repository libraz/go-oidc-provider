//nolint:testpackage // exercises unexported dispatcher state
package customgrant

import (
	"context"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// policyCountingHandler counts ParamPolicy invocations.
type policyCountingHandler struct {
	name  string
	calls *atomic.Int64
}

func (h policyCountingHandler) Name() string { return h.name }
func (h policyCountingHandler) ParamPolicy() ParamPolicy {
	h.calls.Add(1)
	return ParamPolicy{Allowed: []string{"resource"}, DupesAllowed: []string{"resource"}}
}

func (h policyCountingHandler) Handle(context.Context, Request) (Response, error) {
	return Response{AccessToken: "at", AccessTokenTTL: time.Minute}, nil
}

func TestDispatcher_ReadsParamPolicyOnceAtRegistration(t *testing.T) {
	t.Parallel()

	const grant = "urn:example:grant-type:counted"
	var calls atomic.Int64
	disp := New([]Handler{policyCountingHandler{name: grant, calls: &calls}})
	for range 3 {
		_, err := disp.Dispatch(context.Background(), DispatchInput{
			GrantType: grant,
			Client:    newClient(grant),
			Form:      url.Values{"resource": []string{"https://api.example.com"}},
		})
		if err != nil {
			t.Fatalf("Dispatch returned %v, want nil", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("ParamPolicy called %d times, want 1", got)
	}
}
