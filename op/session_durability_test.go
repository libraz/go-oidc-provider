//nolint:testpackage // exercises the unexported posture resolver and warning emitter.
package op

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// durabilityReportingStore wraps an in-memory store so its SessionStore
// answers the durability capability with a fixed value.
type durabilityReportingStore struct {
	store.Store
	durable bool
}

func (s durabilityReportingStore) Sessions() store.SessionStore {
	return reportingSessions{SessionStore: s.Store.Sessions(), durable: s.durable}
}

type reportingSessions struct {
	store.SessionStore
	durable bool
}

func (r reportingSessions) Durable() bool { return r.durable }

// postureConfig applies opts to a config backed by st and a capturing logger.
func postureConfig(t *testing.T, st store.Store, opts ...Option) (*config, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	c := &config{
		store:  st,
		logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}
	for _, o := range opts {
		if err := o.apply(c); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}
	return c, &buf
}

func TestSessionDurabilityPosture_ExplicitDurable(t *testing.T) {
	t.Parallel()

	c, _ := postureConfig(t, inmem.New(), WithSessionDurabilityPosture(SessionDurabilityDurable))
	if got := c.effectiveSessionDurabilityPosture(); got != SessionDurabilityDurable {
		t.Fatalf("posture=%v want durable", got)
	}
}

func TestSessionDurabilityPosture_ExplicitVolatileOverridesDurableStore(t *testing.T) {
	t.Parallel()

	st := durabilityReportingStore{Store: inmem.New(), durable: true}
	c, buf := postureConfig(t, st, WithSessionDurabilityPosture(SessionDurabilityVolatile))
	if got := c.effectiveSessionDurabilityPosture(); got == SessionDurabilityDurable {
		t.Fatalf("posture=%v want volatile", got)
	}
	c.emitPartialWiringWarnings()
	if buf.Len() != 0 {
		t.Fatalf("unexpected log output:\n%s", buf.String())
	}
}

func TestSessionDurabilityPosture_InferredDurable(t *testing.T) {
	t.Parallel()

	st := durabilityReportingStore{Store: inmem.New(), durable: true}
	c, buf := postureConfig(t, st)
	if got := c.effectiveSessionDurabilityPosture(); got != SessionDurabilityDurable {
		t.Fatalf("posture=%v want durable", got)
	}
	c.emitPartialWiringWarnings()
	if buf.Len() != 0 {
		t.Fatalf("unexpected log output:\n%s", buf.String())
	}
}

func TestSessionDurabilityPosture_NoReporterIsVolatile(t *testing.T) {
	t.Parallel()

	// inmem's own session store reports false; the wrapper below hides it.
	c, _ := postureConfig(t, inmem.New())
	if got := c.effectiveSessionDurabilityPosture(); got == SessionDurabilityDurable {
		t.Fatalf("posture=%v want volatile", got)
	}

	c, buf := postureConfig(t, noReporterStore{Store: inmem.New()})
	if got := c.effectiveSessionDurabilityPosture(); got == SessionDurabilityDurable {
		t.Fatalf("posture=%v want volatile", got)
	}
	c.sessionDurabilityPosture = SessionDurabilityDurable
	c.sessionDurabilityPostureSet = true
	c.emitPartialWiringWarnings()
	if buf.Len() != 0 {
		t.Fatalf("a store with no report must not warn:\n%s", buf.String())
	}
}

// noReporterStore hides the capability of the wrapped session store.
type noReporterStore struct{ store.Store }

func (s noReporterStore) Sessions() store.SessionStore {
	return struct{ store.SessionStore }{s.Store.Sessions()}
}

func TestSessionDurabilityPosture_WarnsWhenDurableDeclaredOnVolatileStore(t *testing.T) {
	t.Parallel()

	st := durabilityReportingStore{Store: inmem.New(), durable: false}
	c, buf := postureConfig(t, st, WithSessionDurabilityPosture(SessionDurabilityDurable))
	if got := c.effectiveSessionDurabilityPosture(); got != SessionDurabilityDurable {
		t.Fatalf("posture=%v want the explicit durable", got)
	}
	c.emitPartialWiringWarnings()
	out := buf.String()
	if n := strings.Count(out, "level=WARN"); n != 1 {
		t.Fatalf("warnings=%d want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "SessionDurabilityDurable") || !strings.Contains(out, "volatile backend") {
		t.Fatalf("warning does not name the posture and the backend:\n%s", out)
	}
}
