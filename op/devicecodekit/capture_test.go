package devicecodekit_test

import (
	"context"
	"sync"

	"github.com/libraz/go-oidc-provider/internal/audit"
)

// captureEmitter is a thread-safe slice-backed audit sink the helper
// tests use to assert that the expected events landed. The emitter
// stays in a _test.go file so the production package surface does not
// pick up an audit-recording shape.
type captureEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

// Emit implements [audit.Emitter] by appending a deep-enough copy of
// ev to the captured slice. The Extras map is reused as-is because
// the helpers never mutate it after the emit call.
func (c *captureEmitter) Emit(_ context.Context, ev audit.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

// names returns the captured event names in emission order. Used by
// tests that only need to confirm a particular event landed without
// asserting on the extras.
func (c *captureEmitter) names() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.events))
	for i, ev := range c.events {
		out[i] = ev.Name
	}
	return out
}

// containsName reports whether any captured event has the supplied
// name.
func (c *captureEmitter) containsName(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ev := range c.events {
		if ev.Name == name {
			return true
		}
	}
	return false
}
