package oidcsql

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

func TestSaveSweeper_DueOnFirstAndEveryInterval(t *testing.T) {
	t.Parallel()

	var w saveSweeper
	for i := range 3 * expiredSweepSaveInterval {
		want := i%expiredSweepSaveInterval == 0
		if got := w.due(); got != want {
			t.Fatalf("save %d: due = %v, want %v", i, got, want)
		}
	}
}

func TestInsertReclaimingExpired_RetriesOnlyOnDuplicate(t *testing.T) {
	t.Parallel()

	dup := errors.New("UNIQUE constraint failed: oidc_device_codes.user_code")
	other := errors.New("disk I/O error")

	cases := []struct {
		name       string
		inserts    []error
		wantErr    error
		wantSweeps int
		wantTries  int
	}{
		// The first Save of a sweeper always runs the pacing sweep.
		{"success", []error{nil}, nil, 1, 1},
		{"duplicate reclaimed", []error{dup, nil}, nil, 2, 2},
		{"duplicate survives sweep", []error{dup, dup}, dup, 2, 2},
		{"non-duplicate error is not retried", []error{other}, other, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var (
				w      saveSweeper
				sweeps int
				tries  int
			)
			err := insertReclaimingExpired(context.Background(), &w,
				func(context.Context) error { sweeps++; return nil },
				func() error { e := tc.inserts[tries]; tries++; return e })
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if sweeps != tc.wantSweeps || tries != tc.wantTries {
				t.Fatalf("sweeps/tries = %d/%d, want %d/%d", sweeps, tries, tc.wantSweeps, tc.wantTries)
			}
		})
	}
}

func TestAnchorVersion(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		v    uint64
		want bool
	}{{0, false}, {1, true}, {1<<63 - 2, true}, {1<<63 - 1, false}, {1 << 63, false}} {
		got, ok := anchorVersion(tc.v)
		if ok != tc.want || (ok && got != int64(tc.v)) { //nolint:gosec // tc.v < MaxInt64 whenever ok.
			t.Errorf("anchorVersion(%d) = %d, %v, want ok=%v", tc.v, got, ok, tc.want)
		}
	}
	if err := versionedSwap(context.Background(), nil, "", "x", "s", 0, 0, nil, nil); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("unusable version: %v, want ErrAlreadyConsumed", err)
	}
}
