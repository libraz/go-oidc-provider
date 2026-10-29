package op

import (
	"log/slog"
	"sync"
)

// opaqueOriginWarning is logged once per Provider when a same-origin form
// POST is rejected because the browser sent Origin: null.
const opaqueOriginWarning = "request rejected: the browser sent Origin: null on a same-origin form POST; " +
	"a Referrer-Policy of no-referrer on the OP's pages (from a proxy, a security-header middleware, " +
	"or a <meta name=referrer> in an embedder template) causes this — " +
	"the OP's login and logout pages need same-origin"

// newOpaqueOriginWarner returns a function that logs
// [opaqueOriginWarning] on its first call and does nothing afterwards.
// Each call to the constructor owns its own once, so the warning is per
// Provider. A nil logger disables it.
func newOpaqueOriginWarner(logger *slog.Logger) func() {
	var once sync.Once
	return func() {
		if logger == nil {
			return
		}
		once.Do(func() {
			logger.Warn(opaqueOriginWarning)
		})
	}
}
