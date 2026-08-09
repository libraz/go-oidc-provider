//go:build example

// Package opkit hosts thin op.LoginFlow construction helpers shared
// across the example/* main.go files. It exists for the same reason
// devkeys / serve / seedkit / rpkit do: keep each example focused on
// the op.Option surface it is meant to demonstrate, and keep the
// boilerplate that every example would otherwise duplicate in exactly
// one place.
//
// This package is an examples-only convenience layer; do NOT depend
// on it from production code. Real deployments compose op.LoginFlow
// directly so the orchestration is auditable in one file. The package
// is gated behind the "example" build tag so it cannot be imported
// into production binaries by accident.
//
// The helpers here cover only the shapes that recur across multiple
// examples and that save at least a handful of lines per call site.
// Anything more elaborate (custom Decider, multi-Primary composition,
// rule predicates that read fields beyond LoginContext.RiskScore)
// belongs in the example main.go directly so the surface stays
// auditable.
//
// The introductory examples (00, 01, 04) do not use this package even
// where it would fit. They are the ones read first, and a reader
// cannot import an examples-internal helper into their own code — so
// they write op.LoginFlow out in full, which is what an embedder
// actually types.
package opkit

import (
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

// DefaultLoginFlow returns an op.LoginFlow whose only step is
// op.PrimaryPassword backed by passwords. The shape matches the
// minimal / single-factor examples that do not register any rules.
//
// The caller still wires the resulting flow with op.WithLoginFlow.
func DefaultLoginFlow(passwords store.UserPasswordStore) op.LoginFlow {
	return op.LoginFlow{
		Primary: op.PrimaryPassword{Store: passwords},
	}
}

// WithTOTP composes a LoginFlow that requires op.PrimaryPassword
// followed by op.StepTOTP. The TOTP step is scheduled with
// op.RuleAlways so the second factor fires on every login attempt;
// risk-driven step-up belongs in WithMFARules instead.
//
// totps is the TOTP secret store (typically st.TOTPs() on the
// embedder's storage backend). encryptionKey is the AES-256-GCM key
// used to seal the shared secret at rest; an empty value falls back
// to the key configured on the Provider through
// op.WithMFAEncryptionKeys.
//
// The function preserves loginFlow.Primary, loginFlow.Decider, and
// loginFlow.Risk; the new RuleAlways(StepTOTP{...}) entry is appended
// after any rules already present on the input.
func WithTOTP(loginFlow op.LoginFlow, totps store.TOTPStore, encryptionKey []byte) op.LoginFlow {
	loginFlow.Rules = append(loginFlow.Rules, op.RuleAlways(op.StepTOTP{
		Store:         totps,
		EncryptionKey: encryptionKey,
	}))
	return loginFlow
}

// WithMFARules attaches additional Risk-driven (or otherwise
// conditional) op.Rule entries on top of an existing LoginFlow. Use
// it to compose risk-based MFA escalation on a flow already populated
// with a Primary step.
//
// The function preserves loginFlow.Primary, loginFlow.Decider, and
// loginFlow.Risk; rules are appended in the order supplied so the
// orchestrator's declaration-order semantics are preserved.
func WithMFARules(loginFlow op.LoginFlow, rules ...op.Rule) op.LoginFlow {
	loginFlow.Rules = append(loginFlow.Rules, rules...)
	return loginFlow
}
