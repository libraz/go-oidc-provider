package keys

import (
	"testing"
	"time"
)

func TestRetiredBy(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"zero never retires", time.Time{}, false},
		{"future", at.Add(time.Second), false},
		{"exactly now retires", at, true},
		{"past", at.Add(-time.Second), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := retiredBy(at, tc.notAfter); got != tc.want {
				t.Errorf("retiredBy = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClockReadingNilFallsBackToSystem(t *testing.T) {
	t.Parallel()
	if got := clockReading(nil); time.Since(got) > time.Minute || time.Until(got) > time.Minute {
		t.Errorf("clockReading(nil) = %v, want a system clock reading", got)
	}
}
