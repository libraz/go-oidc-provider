package op_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

func TestWithBackchannelLogout_AcceptsCustomTransport(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t), op.WithBackchannelLogout(op.BackchannelLogout{
		Transport: http.DefaultTransport,
	}))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}

func TestWithBackchannelLogout_AcceptsPositive(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t), op.WithBackchannelLogout(op.BackchannelLogout{
		Timeout:      2 * time.Second,
		FanOutBudget: time.Minute,
	}))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}

func TestWithBackchannelLogout_ZeroFallsBack(t *testing.T) {
	t.Parallel()

	provider, err := op.New(append(validBaseOpts(t), op.WithBackchannelLogout(op.BackchannelLogout{}))...)
	if err != nil {
		t.Fatalf("op.New with zero BackchannelLogout: %v", err)
	}
	if provider == nil {
		t.Fatalf("provider is nil")
	}
}
