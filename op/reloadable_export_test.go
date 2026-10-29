package op

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/backchannel"
)

// NotifyBackchannelLogoutForTest starts the detached back-channel logout
// fan-out for subject on p — the call /end_session makes once the OP-side
// session is gone — and reports whether p has a coordinator to run it.
func NotifyBackchannelLogoutForTest(p *Provider, subject string) bool {
	if p == nil || p.cfg == nil || p.cfg.backchannelCoordinator == nil {
		return false
	}
	p.cfg.backchannelCoordinator.NotifyDetached(context.Background(), backchannel.Notice{Subject: subject})
	return true
}
