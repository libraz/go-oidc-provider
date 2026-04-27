package op_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

func TestWithBackchannelLogoutHTTPClient_AcceptsCustomClient(t *testing.T) {
	t.Parallel()

	client := &http.Client{Timeout: 750 * time.Millisecond}
	provider, err := op.New(append(validBaseOpts(t), op.WithBackchannelLogoutHTTPClient(client))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}

func TestWithBackchannelLogoutHTTPClient_AcceptsNil(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t), op.WithBackchannelLogoutHTTPClient(nil))...)
	if err != nil {
		t.Fatalf("op.New with nil HTTP client: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}

func TestWithBackchannelLogoutTimeout_AcceptsPositive(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t), op.WithBackchannelLogoutTimeout(2*time.Second))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}

func TestWithBackchannelLogoutTimeout_ZeroFallsBack(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t), op.WithBackchannelLogoutTimeout(0))...)
	if err != nil {
		t.Fatalf("op.New with zero timeout: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}
