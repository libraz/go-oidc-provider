package authn

import (
	"slices"
	"sort"
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

	// CompletedKinds is the LoginFlow step kinds completed, led by
	// Primary's kind when the session stands in for it.
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
	if entry == nil || st.ReauthRequired || entry.Subject == "" || entry.Subject != st.Subject {
		ac.ACR = ac.Level.ACRURI()
		return ac
	}
	ac.Inherited = true
	ac.Methods++
	if o != nil && o.cfg.LoginFlow != nil && !containsString(ac.CompletedKinds, o.cfg.LoginFlow.primary.kind) {
		ac.CompletedKinds = append([]string{o.cfg.LoginFlow.primary.kind}, ac.CompletedKinds...)
	}
	ac.Level = max(ac.Level, AALFromACRURI(entry.ACR))
	ac.ACR = ac.Level.ACRURI()
	ac.AMR = mergeAMR(entry.AMR, amr, ac.Level)
	return ac
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
