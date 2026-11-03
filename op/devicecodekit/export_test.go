package devicecodekit

import "github.com/libraz/go-oidc-provider/internal/audit"

// SetAuditEmitter installs an in-process audit sink for external tests.
func (d *Deps) SetAuditEmitter(e audit.Emitter) { d.audit = e }
