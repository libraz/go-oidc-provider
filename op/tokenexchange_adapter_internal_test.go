package op

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

type denyAllExchange struct{}

func (denyAllExchange) Allow(context.Context, TokenExchangeRequest) (*TokenExchangeDecision, error) {
	return nil, nil
}

func TestBuildExtensionDispatcherSurfacesHandlerConstructionError(t *testing.T) {
	cfg := &config{issuer: "https://op.example.com", store: inmem.New(), tokenExchangePolicy: denyAllExchange{}}
	d, err := buildExtensionDispatcher(cfg, nil, cfg.effectiveAuditEmitter())
	if err == nil {
		t.Fatalf("expected a construction error, got dispatcher %v", d)
	}
	var opErr *Error
	if !errors.As(err, &opErr) || opErr.Code != codeConfiguration {
		t.Fatalf("error = %v, want a configuration *Error", err)
	}
}
