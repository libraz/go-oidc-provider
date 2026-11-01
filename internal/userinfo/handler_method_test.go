package userinfo_test

import (
	"context"
	"net/http"
	"testing"
)

func TestHandler_MethodNotAllowed_IsUncacheable(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, f.endpoint, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp := f.doRequest(t, req)
	defer resp.Body.Close()

	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", got)
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma=%q want no-cache", got)
	}
}
