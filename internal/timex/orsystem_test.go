package timex_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

func TestOrSystem(t *testing.T) {
	t.Parallel()
	if got := timex.OrSystem(nil); got != timex.SystemClock {
		t.Fatalf("OrSystem(nil) = %v, want SystemClock", got)
	}
	fixed := time.Unix(1_700_000_000, 0)
	c := timex.ClockFunc(func() time.Time { return fixed })
	if got := timex.OrSystem(c).Now(); !got.Equal(fixed) {
		t.Fatalf("OrSystem(c).Now() = %v, want %v", got, fixed)
	}
}
