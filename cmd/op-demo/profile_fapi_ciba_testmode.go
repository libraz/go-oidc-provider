// OFCS conformance-harness scaffolding for the FAPI-CIBA profile.
//
// This file is dev-only and exists solely so the OpenID Foundation
// Conformance Suite (OFCS) runner can drive per-module device-side
// outcomes that op-demo cannot derive from the request itself —
// specifically the user-rejects-authentication and
// multiple-call-to-token-endpoint modules, which need a Deny and a
// longer Approve delay respectively.
//
// Production embedders MUST NOT mount this handler or install
// [scheduleHarness] as their post-save scheduler: it lets any caller
// flip a CIBA request from approved to denied without authentication.
// The clean reference an embedder would copy is in
// profile_fapi_ciba.go (autoApprovingCIBA + scheduleApprove), which
// only ever schedules a plain Approve.

package main

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// cibaTestMode is the next-action override the OFCS conformance runner
// POSTs to /_test/ciba-mode before driving fapi-ciba modules that
// require a non-default device-side outcome. The atomic carries a
// string ("approve" | "reject" | "slow") because the value is written
// from one goroutine (the test handler) and read from many (each Save
// spawns a scheduler goroutine).
//
//nolint:gochecknoglobals // dev-only test-control switch; no per-instance tuning.
var cibaTestMode atomic.Value

// cibaTestModeApprove / cibaTestModeReject / cibaTestModeSlow are the
// values [cibaTestMode] accepts. The constants are package-private so
// the harness POST handler validates the wire string against the same
// vocabulary [scheduleHarness] consumes.
const (
	cibaTestModeApprove = "approve"
	cibaTestModeReject  = "reject"
	cibaTestModeSlow    = "slow"
)

// cibaTestSlowDelay is the Approve delay [scheduleHarness] applies when
// [cibaTestMode] holds [cibaTestModeSlow]. The value is sized so the
// 240 s wall-clock cap in tools/conformance/runner.py allows the OP to
// land 30+ authorization_pending polls under the 1 s plan interval
// before the timer fires — the shape OFCS' multiple-call-to-token
// module asserts on.
const cibaTestSlowDelay = 60 * time.Second

// loadCIBATestMode returns the current override or [cibaTestModeApprove]
// when none has been posted. The helper centralises the type assertion
// so callers do not have to handle the atomic.Value-reads-untyped-nil
// edge case.
func loadCIBATestMode() string {
	v, _ := cibaTestMode.Load().(string)
	if v == "" {
		return cibaTestModeApprove
	}
	return v
}

// CIBATestModeHandler returns an [http.Handler] that lets the OFCS
// runner.py harness pre-load a per-test override of the auto-approve
// shape. POST body "approve" / "reject" / "slow" flips [cibaTestMode];
// GET returns the current value. The handler is mounted in [main.run]
// only when -profile=fapi-ciba is active so non-CIBA profiles do not
// expose the test surface.
func CIBATestModeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, loadCIBATestMode()+"\n")
		case http.MethodPost:
			body, err := io.ReadAll(io.LimitReader(r.Body, 64))
			if err != nil {
				http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
				return
			}
			mode := strings.TrimSpace(string(body))
			switch mode {
			case cibaTestModeApprove, cibaTestModeReject, cibaTestModeSlow:
				cibaTestMode.Store(mode)
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = io.WriteString(w, mode+"\n")
			default:
				http.Error(w, "mode must be approve|reject|slow", http.StatusBadRequest)
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// scheduleHarness is the post-save scheduler [wrapStoreForCIBA]
// installs in place of [scheduleApprove] so the OFCS runner can flip
// per-module outcomes via /_test/ciba-mode. With no override posted the
// behaviour matches [scheduleApprove] (Approve after a.delay) so the
// happy-flow modules see the same shape as a production embedder; the
// "reject" mode schedules a Deny, and "slow" lengthens the delay so
// multi-poll modules observe enough authorization_pending responses
// before approval lands.
func scheduleHarness(a *autoApprovingCIBA, authReqID, subject string) {
	delay := a.delay
	mode := loadCIBATestMode()
	if mode == cibaTestModeSlow {
		delay = cibaTestSlowDelay
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-a.ctx.Done():
		return
	}
	if mode == cibaTestModeReject {
		a.runDeny(authReqID)
		return
	}
	a.runApprove(authReqID, subject)
}

// runDeny calls Deny with the fixed reason "user-rejected-test"; the
// CIBA token endpoint maps Denied → access_denied so the wire shape
// matches what the OFCS user-rejects-authentication module expects.
// Lives in the test-mode file because the only path that invokes it is
// the harness reject mode — production embedders trigger Deny from the
// user's actual device callback.
func (a *autoApprovingCIBA) runDeny(authReqID string) {
	err := a.inner.Deny(a.ctx, authReqID, "user-rejected-test")
	switch {
	case err == nil:
		a.log.Info("ciba auto-denied",
			slog.String("auth_req_id_prefix", safeAuthReqIDPrefix(authReqID)))
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
	default:
		a.log.Warn("ciba auto-deny failed",
			slog.String("auth_req_id_prefix", safeAuthReqIDPrefix(authReqID)),
			slog.String("err", err.Error()))
	}
}
