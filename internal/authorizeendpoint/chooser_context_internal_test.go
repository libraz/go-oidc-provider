package authorizeendpoint

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

type authContextFaultStore struct {
	err error
}

func (s authContextFaultStore) Save(context.Context, *store.Session) error { return s.err }

func (s authContextFaultStore) Find(context.Context, string) (*store.Session, error) {
	return nil, s.err
}

func (s authContextFaultStore) Touch(context.Context, string, time.Time, time.Time) error {
	return s.err
}

func (s authContextFaultStore) Delete(context.Context, string) error { return s.err }

func (s authContextFaultStore) ListByChooserGroup(
	context.Context,
	string,
) ([]*store.Session, error) {
	return nil, s.err
}

func TestResolveGrantACRAMR_ChooserStoreFaultFailsClosed(t *testing.T) {
	t.Parallel()

	injected := errors.New("injected chooser session lookup failure")
	cookieCodec, err := cookie.NewCodec(bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatalf("cookie.NewCodec: %v", err)
	}
	sessionCodec, err := sessions.NewCodec(cookieCodec)
	if err != nil {
		t.Fatalf("sessions.NewCodec: %v", err)
	}
	manager, err := sessions.NewManager(sessions.Config{
		Codec: sessionCodec,
		Store: authContextFaultStore{err: injected},
		Clock: func() time.Time {
			return time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatalf("sessions.NewManager: %v", err)
	}
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://op.example.com/interaction/id",
		http.NoBody,
	)
	_, _, _, err = resolveGrantACRAMR(
		request,
		resolved{Deps: Deps{Sessions: manager}},
		&store.Interaction{ClientID: "client-1"},
		&authorize.Request{ClientID: "client-1"},
		authn.State{
			ChooserBoundSubject:      true,
			ChooserGroupID:           "group-1",
			ChooserSelectedSessionID: "session-1",
		},
		"user-1",
		time.Time{},
	)
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("resolveGrantACRAMR error=%v want injected backend fault", err)
	}
}
