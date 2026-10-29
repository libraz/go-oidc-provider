package authn

import (
	"slices"
	"sort"
	"time"
)

// EntryAuthn is the authentication the session a request arrived with
// carries, recorded on [State.EntryAuthn] when the chain starts from that
// session's subject.
type EntryAuthn struct {
	// Subject is the session's subject. The record stands only while
	// the chain still serves the same one.
	Subject string `json:"subject"`

	// ACR is the canonical URI of the level the session reached
	// ([AAL.ACRURI]).
	ACR string `json:"acr,omitempty"`

	// AMR is the session's amr set.
	AMR []string `json:"amr,omitempty"`

	// AuthTime is the session's auth_time.
	AuthTime time.Time `json:"auth_time,omitempty"`
}

// AuthContext is the authentication a chain stands on at one point of
// an attempt: the entry session's authentication while it substitutes
// for Primary, plus every factor run during the attempt. Audit naming,
// the risk input, rule predicates, the ACR policy and the acr/amr a
// completed chain records all read this one value, so a step-up on a
// reused session is described the same way everywhere as a fresh login
// after the same factors.
type AuthContext struct {
	// Inherited reports that the entry session's authentication stands
	// in for Primary: it was recorded for this subject and the request
	// did not demand a fresh authentication.
	Inherited bool

	// Methods counts the authentications standing: each factor run
	// during the attempt, plus one for an inherited session.
	Methods int

	// CompletedKinds is the LoginFlow step kinds completed, led by the
	// kinds the session stands in for when it is inherited
	// ([Orchestrator.InheritedCompletedKinds]).
	CompletedKinds []string

	// AMR is the union of the session's and the attempt's amr values,
	// with "mfa" recomputed over the union.
	AMR []string

	// Level is the higher of the session's level and the attempt's.
	Level AAL

	// ACR is the canonical URI of Level.
	ACR string
}

// AuthContext builds the [AuthContext] for st. A nil receiver is
// accepted and contributes no LoginFlow Primary kind.
func (o *Orchestrator) AuthContext(st State) AuthContext {
	_, amr, level := Aggregate(st.Factors)
	ac := AuthContext{
		Methods:        len(st.Factors),
		CompletedKinds: append([]string(nil), st.CompletedStepKinds...),
		AMR:            amr,
		Level:          level,
	}
	entry := st.EntryAuthn
	if !entryStandsIn(st) {
		ac.ACR = ac.Level.ACRURI()
		return ac
	}
	ac.Inherited = true
	ac.Methods++
	var inherited []string
	for _, kind := range o.InheritedCompletedKinds(*entry) {
		if !containsString(ac.CompletedKinds, kind) {
			inherited = append(inherited, kind)
		}
	}
	ac.CompletedKinds = append(inherited, ac.CompletedKinds...)
	ac.Level = max(ac.Level, AALFromACRURI(entry.ACR))
	ac.ACR = ac.Level.ACRURI()
	ac.AMR = mergeAMR(entry.AMR, amr, ac.Level)
	return ac
}

// entryStandsIn reports whether the entry session's authentication
// stands in for Primary: it was recorded for st's subject and the
// request did not demand a fresh authentication.
func entryStandsIn(st State) bool {
	entry := st.EntryAuthn
	return entry != nil && !st.ReauthRequired && entry.Subject != "" && entry.Subject == st.Subject
}

// InheritedCompletedKinds returns the LoginFlow step kinds the entry
// session stands in for: Primary's, plus every rule step whose
// satisfying amr set meets the session's amr ("mfa" aside). A one-of
// step counts when any of its factors would; only its own kind is
// returned. Captcha and factors with no registered amr value have an
// empty set and never count. A nil receiver returns nil.
//
// The amr does not tell the otp factors apart, so a session made with
// one of them satisfies a step demanding another; max_age or acr_values
// force a fresh authentication where that matters.
func (o *Orchestrator) InheritedCompletedKinds(entry EntryAuthn) []string {
	if o == nil || o.cfg.LoginFlow == nil {
		return nil
	}
	flow := o.cfg.LoginFlow
	kinds := []string{flow.primary.kind}
	for _, r := range flow.rules {
		if !containsString(kinds, r.then.kind) && amrSatisfies(r.then, entry.AMR) {
			kinds = append(kinds, r.then.kind)
		}
	}
	return kinds
}

// amrSatisfies reports whether amr meets step's satisfying set, or for a
// one-of step the set of any of its factors.
func amrSatisfies(step compiledStep, amr []string) bool {
	if len(step.oneOf) > 0 {
		return slices.ContainsFunc(step.oneOf, func(inner compiledStep) bool { return amrSatisfies(inner, amr) })
	}
	for _, v := range satisfyingAMR(step) {
		if v != amrMFA && slices.Contains(amr, v) {
			return true
		}
	}
	return false
}

// satisfyingAMR is the set of session amr values that show step ran,
// derived from its factor type through [Factor.AMRValue] so it reads the
// session the way the session was written. A passkey step that demands
// user verification accepts only the verified value.
func satisfyingAMR(step compiledStep) []string {
	if step.isCaptcha {
		return nil
	}
	var set []string
	for _, uv := range []bool{true, false} {
		if !uv && step.requireUV {
			continue
		}
		v := Factor{Type: step.factor, UserVerified: uv}.AMRValue()
		if v != "" && !slices.Contains(set, v) {
			set = append(set, v)
		}
	}
	return set
}

// mergeAMR unions two amr sets and recomputes "mfa" over the result
// under the rule [Aggregate] applies to a single attempt.
func mergeAMR(a, b []string, level AAL) []string {
	var out []string
	for _, v := range slices.Concat(a, b) {
		if v == "" || v == amrMFA || slices.Contains(out, v) {
			continue
		}
		out = append(out, v)
	}
	if len(out) >= 2 && level >= AAL2 {
		out = append(out, amrMFA)
	}
	sort.Strings(out)
	return out
}
