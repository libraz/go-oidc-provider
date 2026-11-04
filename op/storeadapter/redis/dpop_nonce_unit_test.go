//nolint:testpackage // tests exercise the unexported Lua script.
package oidcredis

import (
	"strings"
	"testing"
	"time"
)

func TestDPoPNonceSource_RejectsNonPositiveRotation(t *testing.T) {
	t.Parallel()
	s := &Store{}
	for _, rotate := range []time.Duration{-time.Minute, 0, time.Microsecond} {
		if _, err := s.DPoPNonceSource(rotate); err == nil {
			t.Errorf("DPoPNonceSource(%v) succeeded", rotate)
		}
	}
	if _, err := s.DPoPNonceSource(time.Minute); err != nil {
		t.Errorf("DPoPNonceSource(1m): %v", err)
	}
}

// The script keys its state on the fields the Go side documents.
func TestSyncDPoPNonceLuaFields(t *testing.T) {
	t.Parallel()
	for _, f := range []string{`"cur"`, `"prev"`, `"at"`} {
		if !strings.Contains(syncDPoPNonceLua, f) {
			t.Errorf("script does not use field %s", f)
		}
	}
}
