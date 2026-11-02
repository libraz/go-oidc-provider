package op

import (
	"context"
	"strconv"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/nilcheck"
)

// compileLoginFlow projects the public [LoginFlow] onto the internal
// [authn.LoginFlowSpec] shape and hands it to the authn-package
// compiler. The projection lives in op/ (not internal/authn/) because
// the rule "internal MUST NOT import op" forbids the inverse path.
//
// Built-in Steps (PrimaryPassword / PrimaryPasskey / StepTOTP /
// StepEmailOTP / StepRecoveryCode / StepCaptcha) are wired to their
// internal Authenticator primitives through the matching builders in
// loginflow_compile.go. ExternalStep continues to forward an
// already-constructed [Authenticator] verbatim for embedders with
// proprietary factors.
//
// cfg supplies the Provider-level fallbacks the per-step builders
// consult when the Step omits its own field (e.g. StepTOTP defers to
// [WithMFAEncryptionKeys] when [StepTOTP.EncryptionKey] is empty).
func compileLoginFlow(flow LoginFlow, cfg *config) (*authn.CompiledLoginFlow, error) {
	primary, err := projectStepAt("Primary", flow.Primary, cfg, true)
	if err != nil {
		return nil, err
	}
	rules := make([]authn.LoginFlowRule, 0, len(flow.Rules))
	for i, r := range flow.Rules {
		then, perr := projectStepToFlow("Rules["+strconv.Itoa(i)+"].Then", r.Then, cfg)
		if perr != nil {
			return nil, perr
		}
		// Capture the public predicate inside a closure that adapts
		// the LoginFlowContext shape to the public LoginContext one.
		// A nil When is the constant-true predicate per the [Rule]
		// contract, substituted here rather than left nil: the compiled
		// flow reads an unset predicate as "never fires", which would
		// turn a declared second factor into a step no LoginContext can
		// reach and silently authenticate every user on the primary
		// factor alone.
		pred := r.When
		when := func(authn.LoginFlowContext) bool { return true }
		if pred != nil {
			when = func(lc authn.LoginFlowContext) bool {
				return pred(toPublicLoginContext(lc))
			}
		}
		rules = append(rules, authn.LoginFlowRule{When: when, Then: then})
	}
	spec := authn.LoginFlowSpec{
		Primary: primary,
		Rules:   rules,
	}
	if flow.Registration != nil {
		registration, rerr := projectStepAt("Registration", flow.Registration, cfg, true)
		if rerr != nil {
			return nil, rerr
		}
		spec.Registration = registration
	}
	if !nilcheck.IsNil(flow.Risk) {
		spec.Risk = flow.Risk
	}
	if !nilcheck.IsNil(flow.Decider) {
		spec.Decider = &deciderAdapter{inner: flow.Decider}
	}
	// Checked after projection so a step's own configuration error wins
	// over the missing-store error.
	if err := cfg.validateLockoutStore(); err != nil {
		return nil, err
	}
	return authn.CompileLoginFlow(spec)
}

// projectStepToFlow projects a single public [Step] onto the
// internal [authn.LoginFlowStep] shape. The dispatch handles every
// shape the public surface exposes today:
//
//   - [ExternalStep] (embedder-wrapped Authenticator): forwarded
//     verbatim, the orchestrator drives the wrapped authenticator
//     directly.
//   - [StepOneOf]: each step projected at the one-of step's position.
//   - Built-in Steps with construction-time wiring (PrimaryPassword,
//     PrimaryPasskey, StepTOTP, StepEmailOTP, StepRecoveryCode,
//     StepCaptcha): the matching builder synthesises the internal
//     authenticator from the Step's public fields. Validation errors
//     surface as a typed *Error pointing at the offending Step.
//   - Unrecognised Step values: surface a configuration_error pointing
//     at the offending Step so the upgrade path is obvious; embedders
//     use [ExternalStep] until a missing built-in lands.
//
// cfg threads the Provider-level fallbacks (e.g. MFA encryption keys)
// through to the built-in builders. The step is projected for a rule
// position; [compileLoginFlow] projects Primary through [projectStepAt].
func projectStepToFlow(where string, s Step, cfg *config) (authn.LoginFlowStep, error) {
	return projectStepAt(where, s, cfg, false)
}

// projectStepAt is [projectStepToFlow] with the position made explicit:
// primary is true for [LoginFlow.Primary] and the steps of a [StepOneOf]
// placed there, where no subject is bound yet. A [PrimaryPasskey] in that
// position runs the discoverable ceremony.
func projectStepAt(where string, s Step, cfg *config, primary bool) (authn.LoginFlowStep, error) {
	if nilcheck.IsNil(s) {
		return authn.LoginFlowStep{}, newConfigurationError("WithLoginFlow: "+where+" must not be nil", nil)
	}
	switch v := s.(type) {
	case ExternalStep:
		return projectExternalStep(where, v, cfg)
	case StepOneOf:
		return projectOneOfStep(where, v, cfg, primary)
	case PrimaryPasskey:
		if primary {
			return projectPasskeyStep(where, v, cfg, true)
		}
	}
	return projectBuiltinStep(where, s, cfg)
}

// projectOneOfStep projects a [StepOneOf] and each of its steps at the
// same position. OneOf is non-nil even when Steps is empty, so the
// compiler reads the step as a one-of step and reports the empty list.
func projectOneOfStep(where string, s StepOneOf, cfg *config, primary bool) (authn.LoginFlowStep, error) {
	inner := make([]authn.LoginFlowStep, 0, len(s.Steps))
	for i, step := range s.Steps {
		projected, err := projectStepAt(where+".StepOneOf.Steps["+strconv.Itoa(i)+"]", step, cfg, primary)
		if err != nil {
			return authn.LoginFlowStep{}, err
		}
		inner = append(inner, projected)
	}
	return authn.LoginFlowStep{
		Kind:           string(s.Kind()),
		OneOf:          inner,
		IfNoneEnrolled: s.IfNoneEnrolled,
	}, nil
}

// projectExternalStep is the [projectStepToFlow] arm for an
// [ExternalStep]: validate the wrapped authenticator and forward it,
// gated by the cross-factor lockout counter when CountFailures is set.
func projectExternalStep(where string, ext ExternalStep, cfg *config) (authn.LoginFlowStep, error) {
	if nilcheck.IsNil(ext.Authenticator) {
		return authn.LoginFlowStep{}, newConfigurationError("WithLoginFlow: "+where+" ExternalStep.Authenticator must not be nil", nil)
	}
	auth := ext.Authenticator
	if ext.CountFailures {
		auth = authn.WithLockoutCounter(auth, newLockoutCounter(cfg))
	}
	return authn.LoginFlowStep{
		Kind:          string(ext.KindLabel),
		Authenticator: auth,
	}, nil
}

// projectPasskeyStep builds a [PrimaryPasskey]; discoverable is true at
// the Primary position.
func projectPasskeyStep(where string, s PrimaryPasskey, cfg *config, discoverable bool) (authn.LoginFlowStep, error) {
	auth, err := buildPrimaryPasskey(s, cfg.clock, discoverable)
	if err != nil {
		return authn.LoginFlowStep{}, projectStepError(where, err)
	}
	return authn.LoginFlowStep{
		Kind:                    string(StepKindPasskey),
		Authenticator:           auth,
		RequireUserVerification: s.RequireUserVerification,
	}, nil
}

// projectBuiltinStep dispatches a built-in [Step] (PrimaryPassword,
// PrimaryPasskey, StepTOTP, StepEmailOTP, StepRecoveryCode,
// StepCaptcha) to the matching builder in loginflow_compile.go and
// wraps the constructed authenticator in a [authn.LoginFlowStep]. An
// unrecognised Step value surfaces a configuration_error pointing the
// embedder at [ExternalStep].
//
// cfg supplies the Provider-level fallbacks the per-step builders
// consult when the Step omits its own field.
func projectBuiltinStep(where string, s Step, cfg *config) (authn.LoginFlowStep, error) {
	switch v := s.(type) {
	case PrimaryPasskey:
		return projectPasskeyStep(where, v, cfg, false)
	case StepTOTP:
		fallbackCurrent, fallbackPrev := totpFallbackKeys(cfg)
		auth, err := buildStepTOTP(v, fallbackCurrent, fallbackPrev, cfg.clock)
		if err != nil {
			return authn.LoginFlowStep{}, projectStepError(where, err)
		}
		auth = attachLockoutCounter(auth, cfg)
		return authn.LoginFlowStep{Kind: string(StepKindTOTP), Authenticator: auth}, nil
	case StepEmailOTP:
		auth, err := buildStepEmailOTP(v, cfg.clock)
		if err != nil {
			return authn.LoginFlowStep{}, projectStepError(where, err)
		}
		auth = attachLockoutCounter(auth, cfg)
		return authn.LoginFlowStep{Kind: string(StepKindEmailOTP), Authenticator: auth}, nil
	case StepRecoveryCode:
		auth, err := buildStepRecoveryCode(v, cfg.clock)
		if err != nil {
			return authn.LoginFlowStep{}, projectStepError(where, err)
		}
		auth = attachLockoutCounter(auth, cfg)
		return authn.LoginFlowStep{Kind: string(StepKindRecoveryCode), Authenticator: auth}, nil
	case StepCaptcha:
		auth, err := buildStepCaptcha(v)
		if err != nil {
			return authn.LoginFlowStep{}, projectStepError(where, err)
		}
		return authn.LoginFlowStep{Kind: string(StepKindCaptcha), Authenticator: auth, IsCaptcha: true}, nil
	case PrimaryPassword:
		auth, err := buildPrimaryPassword(v, cfg)
		if err != nil {
			return authn.LoginFlowStep{}, projectStepError(where, err)
		}
		auth = attachLockoutCounter(auth, cfg)
		return authn.LoginFlowStep{Kind: string(StepKindPassword), Authenticator: auth}, nil
	default:
		// An unrecognised Step shape (a future built-in we forgot to
		// wire, or an embedder-defined value type that satisfies Step
		// but is not ExternalStep). Surface the same actionable
		// message so the upgrade path stays obvious.
		return authn.LoginFlowStep{}, newConfigurationError("WithLoginFlow: "+where+" uses built-in Step "+string(s.Kind())+" whose primitive is not yet exposed; wrap your own Authenticator in op.ExternalStep until the matching option lands", authn.ErrBuiltinStepNotWired)
	}
}

// totpFallbackKeys returns the Provider-level TOTP encryption keys
// configured through [WithMFAEncryptionKeys].
// The first return value is the active key (or nil when the option is
// unset), the second is the rotation history (nil when absent or when
// only the active key was supplied). Splitting the slice this way lets
// [buildStepTOTP] feed [selectTOTPKeys] without re-parsing the layout.
func totpFallbackKeys(cfg *config) ([]byte, [][]byte) {
	if len(cfg.mfaEncryptionKeys) == 0 {
		return nil, nil
	}
	current := cfg.mfaEncryptionKeys[0]
	if len(cfg.mfaEncryptionKeys) == 1 {
		return current, nil
	}
	return current, cfg.mfaEncryptionKeys[1:]
}

// projectStepError wraps a builder failure into a typed [Error] that
// names the offending Step's location ("Primary", "Rules[0].Then",
// ...). Centralising the wrapping keeps the [projectStepToFlow]
// switch arms readable.
func projectStepError(where string, err error) error {
	return newConfigurationError("WithLoginFlow: "+where+": "+err.Error(), err)
}

// stepKindsOf converts internal step-kind names to the public [StepKind].
func stepKindsOf[K ~string](kinds []K) []StepKind {
	out := make([]StepKind, len(kinds))
	for i, k := range kinds {
		out[i] = StepKind(k)
	}
	return out
}

// scopeSetOf converts scope names to a [ScopeSet]; empty input yields an
// empty, non-nil set.
func scopeSetOf[S ~string](names []S) ScopeSet {
	out := make(ScopeSet, len(names))
	for _, n := range names {
		out[ScopeName(n)] = struct{}{}
	}
	return out
}

// toPublicLoginContext projects the internal [authn.LoginFlowContext]
// onto the public [LoginContext] surface rule predicates consume.
// [op.RiskScore] is a type alias for [authn.RiskScore], so the field
// flows through without a conversion.
func toPublicLoginContext(lc authn.LoginFlowContext) LoginContext {
	scopes := scopeSetOf(lc.RequestedScopes)
	completed := stepKindsOf(lc.CompletedKinds)
	return LoginContext{
		Identity: Identity{
			Subject:               Subject(lc.Subject),
			AuthenticationContext: publicAuthContext(lc.AMR, lc.ACR, lc.AuthTime),
		},
		ClientID:        lc.ClientID,
		RequestedScopes: scopes,
		FailedAttempts:  lc.FailedAttempts,
		RiskScore:       lc.RiskScore,
		NewDevice:       lc.NewDevice,
		CompletedSteps:  completed,
		ACRValues:       lc.ACRValues,
		Remote: ClientHints{
			RemoteIP:       lc.RemoteIP,
			UserAgent:      lc.UserAgent,
			AcceptLanguage: lc.AcceptLanguage,
		},
		AAL:           lc.Level,
		SessionReused: lc.Inherited,
	}
}

// publicAuthContext builds the [AuthContext] a [LoginContext] carries. A
// zero authTime stays 0 ("unknown") rather than a negative Unix value.
func publicAuthContext(amr []string, acr string, authTime time.Time) AuthContext {
	ac := AuthContext{AMR: append([]string(nil), amr...), ACR: acr}
	if !authTime.IsZero() {
		ac.AuthTime = authTime.Unix()
	}
	return ac
}

// deciderAdapter projects the public [Decider] surface onto the
// internal [authn.LoginFlowDecider]. The adapter translates each
// public [Decision] case into its internal counterpart so the
// orchestrator's switch stays closed (LoginFlowDecision is a sealed
// sum). Pointer forms project like their values; nil or an
// unrecognised Decision projects to LoginFlowDeny so the login fails
// closed.
type deciderAdapter struct {
	inner Decider
}

// Decide implements [authn.LoginFlowDecider]. The adapter rebuilds the
// public LoginContext from the internal projection, calls the
// embedder's Decider, and translates the returned Decision back. A
// Require carries only a kind: the orchestrator resolves it against the
// steps the flow declared, and a kind that is not among them surfaces as
// ErrInvalidStep. Introducing a step at decision time is deliberately
// not possible — the factors a login can demand stay readable off the
// LoginFlow, which a Decider that could conjure one would undo.
func (a *deciderAdapter) Decide(ctx context.Context, lc authn.LoginFlowContext) authn.LoginFlowDecision { //nolint:ireturn,nolintlint // sealed-sum LoginFlowDecision is the contract.
	d := derefDecision(a.inner.Decide(ctx, toPublicLoginContext(lc)))
	switch v := d.(type) {
	case Allow:
		return authn.LoginFlowAllow{}
	case Pass:
		return authn.LoginFlowPass{}
	case Deny:
		return authn.LoginFlowDeny{Reason: v.Reason}
	case Require:
		// An empty kind names nothing, so there is nothing to require;
		// deferring to the rules is the only reading that does not
		// invent a factor.
		if v.Kind == "" {
			return authn.LoginFlowPass{}
		}
		return authn.LoginFlowRequire{
			Step: authn.LoginFlowStep{Kind: string(v.Kind)},
		}
	default:
		// nil, a nil pointer, or a shape this switch does not know: no verdict, so fail closed.
		return authn.LoginFlowDeny{Reason: "decider returned no decision"}
	}
}

// derefDecision maps the pointer forms of the four Decision shapes onto
// their value forms, so *Deny means Deny rather than an unknown shape.
// A nil pointer comes back as nil.
func derefDecision(d Decision) Decision { //nolint:ireturn // Decision is a sealed sum type.
	if nilcheck.IsNil(d) {
		return nil
	}
	switch v := d.(type) {
	case *Allow:
		return *v
	case *Pass:
		return *v
	case *Deny:
		return *v
	case *Require:
		return *v
	default:
		return d
	}
}

// newACRResolver builds the [authorizeendpoint.ACRResolver] closure the
// authorize endpoint consults before stamping acr / amr onto the
// persisted grant. The closure adapts the public [ACRPolicy] surface
// to the wire-layer input bundle: the input's CompletedKinds (raw
// strings carried by [authn.State]) project onto the public
// [StepKind] slice that [ACRPolicy.Resolve] / [ACRPolicy.Satisfies]
// consume, and the input's request-scoped fields fold into a fresh
// [LoginContext]. The function never returns nil so the wire layer
// always sees a configured resolver: a nil [config.acrPolicy] triggers
// the [DefaultACRPolicy] fallback.
//
// The authentication fields follow [toPublicLoginContext]: AAL is the
// recorded level, the acr its canonical URI, and auth_time is reported
// only for a reused session, so Resolve reads the same values a rule
// predicate reads for that authentication.
func newACRResolver(cfg *config) authorizeendpoint.ACRResolver {
	policy := cfg.effectiveACRPolicy()
	return func(ctx context.Context, in authorizeendpoint.ACRResolveInput) authorizeendpoint.ACRResolveOutput {
		scopes := scopeSetOf(in.RequestedScopes)
		completed := stepKindsOf(in.CompletedKinds)
		var authTime time.Time
		if in.SessionReused {
			authTime = in.AuthTime
		}
		lc := LoginContext{
			Identity: Identity{
				Subject:               Subject(in.Subject),
				AuthenticationContext: publicAuthContext(in.AMR, in.InternalAAL.ACRURI(), authTime),
			},
			ClientID:        in.ClientID,
			RequestedScopes: scopes,
			CompletedSteps:  completed,
			ACRValues:       append([]string(nil), in.RequestedACRValues...),
			Remote: ClientHints{
				RemoteIP:       in.RemoteIP,
				UserAgent:      in.UserAgent,
				AcceptLanguage: in.AcceptLanguage,
			},
			AAL:           in.InternalAAL,
			SessionReused: in.SessionReused,
		}
		acr, amr, ok := policy.Resolve(ctx, lc, in.InternalAAL)
		return authorizeendpoint.ACRResolveOutput{
			ACR: acr,
			AMR: append([]string(nil), amr...),
			OK:  ok,
		}
	}
}
