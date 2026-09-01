package authorizeendpoint

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// exitInvariants states, for one route into the terminal gate, the
// verdict the gate must reach for each invariant it enforces. A nil
// field means the gate admits that input on this route.
//
// It exists as a table rather than as assertions scattered through the
// per-route tests because the routes are a closed set and the invariants
// are a closed set, and the only interesting question is the cell where
// the two meet. A route whose freshness rules were quietly relaxed shows
// up here as a changed cell, next to the four cells that did not change.
type exitInvariants struct {
	// declared marks the row as written by hand. A route added to
	// exitKind without a row here leaves the zero value, which the
	// completeness check refuses — that refusal is the whole reason the
	// matrix is an array indexed by exitKind rather than a map.
	declared bool

	// baseline is the verdict for an otherwise-consistent authorization:
	// a bound subject, a matching grant, an hour-old backing
	// authentication, and a request that constrains neither freshness nor
	// authentication context.
	baseline error

	// subjectBound is the verdict when the exit reached the gate with no
	// subject to issue the code for.
	subjectBound error

	// authnSourced is the verdict when the exit named a route but pointed
	// at no record to read the backing authentication from.
	authnSourced error

	// grantMatches is the verdict when the grant the code would hang off
	// belongs to somebody other than the bound subject.
	grantMatches error

	// promptLogin is the verdict when the request demands a fresh
	// authentication with prompt=login.
	promptLogin error

	// maxAge is the verdict when the backing authentication is older than
	// the request's max_age.
	maxAge error

	// acrValues is the verdict when the backing authentication carries an
	// acr outside the set the request named.
	acrValues error

	// consentCovered is the verdict when the decision to skip the consent
	// screen came from a cached grant and the bound subject holds none.
	consentCovered error
}

// exitInvariantMatrix is the whole gate, one row per route.
//
// The three authentication cells split exactly as [exitSpec] says they
// do: a route serving an authentication established before this attempt
// re-applies the request's freshness and acr_values constraints to it,
// and a route that ran a credential chain does not, because the ceremony
// satisfies them by construction and its acr is the ACR resolution
// seam's verdict.
var exitInvariantMatrix = [exitCount]exitInvariants{
	// A call that names no route is refused before any other invariant is
	// consulted, so every cell carries the same answer.
	exitUnset: {
		declared:       true,
		baseline:       errTerminalExitUnknown,
		subjectBound:   errTerminalExitUnknown,
		authnSourced:   errTerminalExitUnknown,
		grantMatches:   errTerminalExitUnknown,
		promptLogin:    errTerminalExitUnknown,
		maxAge:         errTerminalExitUnknown,
		acrValues:      errTerminalExitUnknown,
		consentCovered: errTerminalExitUnknown,
	},
	exitSilentCachedGrant: {
		declared:       true,
		subjectBound:   errTerminalSubjectMissing,
		authnSourced:   errTerminalAuthnUnavailable,
		grantMatches:   errTerminalGrantMismatch,
		promptLogin:    errStaleAuthentication,
		maxAge:         errStaleAuthentication,
		acrValues:      errACRUnmet,
		consentCovered: errTerminalConsentUncovered,
	},
	exitFirstPartyAutoGrant: {
		declared:       true,
		subjectBound:   errTerminalSubjectMissing,
		authnSourced:   errTerminalAuthnUnavailable,
		grantMatches:   errTerminalGrantMismatch,
		promptLogin:    errStaleAuthentication,
		maxAge:         errStaleAuthentication,
		acrValues:      errACRUnmet,
		consentCovered: errTerminalConsentUncovered,
	},
	exitInteractiveChain: {
		declared:       true,
		subjectBound:   errTerminalSubjectMissing,
		authnSourced:   errTerminalAuthnUnavailable,
		grantMatches:   errTerminalGrantMismatch,
		consentCovered: errTerminalConsentUncovered,
	},
	exitInteractiveChooserSession: {
		declared:       true,
		subjectBound:   errTerminalSubjectMissing,
		authnSourced:   errTerminalAuthnUnavailable,
		grantMatches:   errTerminalGrantMismatch,
		promptLogin:    errStaleAuthentication,
		maxAge:         errStaleAuthentication,
		acrValues:      errACRUnmet,
		consentCovered: errTerminalConsentUncovered,
	},
	exitInteractiveEntrySession: {
		declared:       true,
		subjectBound:   errTerminalSubjectMissing,
		authnSourced:   errTerminalAuthnUnavailable,
		grantMatches:   errTerminalGrantMismatch,
		promptLogin:    errStaleAuthentication,
		maxAge:         errStaleAuthentication,
		acrValues:      errACRUnmet,
		consentCovered: errTerminalConsentUncovered,
	},
}

// exitInvariantProbe is one invariant, expressed as the input that
// violates it and the cell that says what the gate must answer.
type exitInvariantProbe struct {
	name string
	// build produces the authorization the gate is asked about. It starts
	// from the consistent baseline for the route and breaks exactly one
	// thing.
	build func(*authorize.Request, *terminalAuthorization)
	// want reads the expected verdict out of the route's row.
	want func(exitInvariants) error
}

// exitInvariantProbes enumerates every invariant the gate enforces. It
// is the second axis of the matrix; a check added to the gate without a
// probe here is a column the routes are never compared across.
var exitInvariantProbes = []exitInvariantProbe{
	{
		name:  "an otherwise consistent authorization",
		build: func(*authorize.Request, *terminalAuthorization) {},
		want:  func(row exitInvariants) error { return row.baseline },
	},
	{
		name:  "no subject to issue the code for",
		build: func(_ *authorize.Request, in *terminalAuthorization) { in.Subject = "" },
		want:  func(row exitInvariants) error { return row.subjectBound },
	},
	{
		name:  "no record to read the authentication from",
		build: func(_ *authorize.Request, in *terminalAuthorization) { in.Backing = nil },
		want:  func(row exitInvariants) error { return row.authnSourced },
	},
	{
		name: "a grant belonging to somebody else",
		build: func(_ *authorize.Request, in *terminalAuthorization) {
			in.Grant.Subject = "user-2"
		},
		want: func(row exitInvariants) error { return row.grantMatches },
	},
	{
		name: "a request demanding a fresh authentication",
		build: func(req *authorize.Request, _ *terminalAuthorization) {
			req.Prompt = []string{interaction.PromptLogin}
		},
		want: func(row exitInvariants) error { return row.promptLogin },
	},
	{
		name: "a backing authentication older than max_age",
		build: func(req *authorize.Request, _ *terminalAuthorization) {
			req.MaxAge = ptrInt64(60)
		},
		want: func(row exitInvariants) error { return row.maxAge },
	},
	{
		name: "a backing authentication outside the requested acr",
		build: func(req *authorize.Request, _ *terminalAuthorization) {
			req.ACRValues = []string{"urn:example:strong"}
		},
		want: func(row exitInvariants) error { return row.acrValues },
	},
	{
		name: "consent taken from a cached grant the subject does not hold",
		build: func(_ *authorize.Request, in *terminalAuthorization) {
			in.Subject = "user-without-grant"
			in.Grant = nil
			in.ConsentAnswered = false
			in.ConsentFromCachedGrant = true
		},
		want: func(row exitInvariants) error { return row.consentCovered },
	},
}

// exitProbeBaseline is the authorization every probe starts from: a
// consistent one, which the gate admits on every route it has rules for.
// The backing authentication is an hour old and carries a weak acr, so
// the freshness and acr_values probes have something to fail on without
// having to introduce a second variable.
func exitProbeBaseline(kind exitKind) (*authorize.Request, terminalAuthorization) {
	req := &authorize.Request{ClientID: "client-1", Scope: []string{"openid"}}
	in := terminalAuthorization{
		Exit: kind,
		Backing: stubTerminalAuthn{ctx: grantAuthContext{
			AuthTime: terminalNow.Add(-time.Hour),
			ACR:      "urn:example:weak",
		}},
		Subject:                "user-1",
		Scope:                  []string{"openid"},
		ConsentFromCachedGrant: true,
		Grant:                  terminalGrant(),
	}
	return req, in
}

// TestTerminalGateCoversEveryExit runs every invariant against every
// route.
//
// The loop is over the enumeration rather than over a hand-written list
// of cases, so the set of routes under test cannot fall behind the set
// of routes that exist: a new exitKind is a row the matrix has not
// declared, and the subtest for it fails before any of its cells are
// consulted.
func TestTerminalGateCoversEveryExit(t *testing.T) {
	t.Parallel()

	for kind := exitKind(0); kind < exitCount; kind++ {
		t.Run(kind.String(), func(t *testing.T) {
			t.Parallel()
			row := exitInvariantMatrix[kind]
			if !row.declared {
				t.Fatalf("exit %q has no row in exitInvariantMatrix; "+
					"a route the gate serves has to say what it does with each invariant", kind)
			}
			for _, probe := range exitInvariantProbes {
				t.Run(probe.name, func(t *testing.T) {
					t.Parallel()
					req, in := exitProbeBaseline(kind)
					probe.build(req, &in)
					want := probe.want(row)

					backing := inmem.New(inmem.WithClock(fixedAuthorizeClock(terminalNow)))
					if err := backing.Grants().Save(context.Background(), terminalGrant()); err != nil {
						t.Fatalf("Save grant: %v", err)
					}
					_, err := validateTerminalAuthorization(
						context.Background(), terminalDeps(backing.Grants()), req, in,
					)
					switch {
					case want == nil && err != nil:
						t.Fatalf("gate refused %s with %v, want the authorization served", probe.name, err)
					case want != nil && !errors.Is(err, want):
						t.Fatalf("gate answered %v for %s, want %v", err, probe.name, want)
					}
				})
			}
		})
	}
}

// TestExitSpecsAreComplete refuses an enumerator that carries no rules.
// exitSpecs is an array sized by exitCount, so a kind added without a
// spec is a zero row that would silently read as "no name, and the
// request's freshness constraints do not apply to it" — the most
// permissive answer the gate can give, arrived at by omission.
func TestExitSpecsAreComplete(t *testing.T) {
	t.Parallel()

	seen := map[string]exitKind{}
	for kind := exitKind(0); kind < exitCount; kind++ {
		spec := exitSpecs[kind]
		if spec.Name == "" {
			t.Errorf("exitKind(%d) has no spec in exitSpecs", uint8(kind))
			continue
		}
		if prior, dup := seen[spec.Name]; dup {
			t.Errorf("exitKind(%d) and exitKind(%d) are both named %q",
				uint8(prior), uint8(kind), spec.Name)
		}
		seen[spec.Name] = kind
		if got := kind.String(); got != spec.Name {
			t.Errorf("exitKind(%d).String() = %q, want %q", uint8(kind), got, spec.Name)
		}
	}
	if exitUnset.valid() {
		t.Error("the zero value names a route; an exit that says nothing would be served")
	}
	if exitCount.valid() {
		t.Error("exitCount names a route")
	}
	if (exitCount + 1).valid() {
		t.Error("a kind past the end of the enumeration names a route")
	}
	if got := (exitCount + 1).String(); got == "" {
		t.Error("a kind past the end of the enumeration has no printable form")
	}
}

// TestExitSpecAgreesWithTheInvariantMatrix ties the two tables together.
//
// exitSpec.ServesEstablishedSession is what the gate branches on, and
// the matrix is what the tests assert; flipping one without the other
// would leave a route whose documented rules and enforced rules disagree
// while both files still look internally consistent.
func TestExitSpecAgreesWithTheInvariantMatrix(t *testing.T) {
	t.Parallel()

	for kind := exitSilentCachedGrant; kind < exitCount; kind++ {
		row := exitInvariantMatrix[kind]
		established := exitSpecs[kind].ServesEstablishedSession
		for _, cell := range []struct {
			name string
			want error
		}{
			{"prompt=login", row.promptLogin},
			{"max_age", row.maxAge},
			{"acr_values", row.acrValues},
		} {
			if established && cell.want == nil {
				t.Errorf("%s serves an authentication established before this attempt "+
					"but the matrix admits %s unchecked", kind, cell.name)
			}
			if !established && cell.want != nil {
				t.Errorf("%s runs its own credential chain but the matrix re-applies %s to it; "+
					"the ceremony satisfies it by construction", kind, cell.name)
			}
		}
	}
}

// TestExitInvariantMatrixRefusesAnUndeclaredRoute measures the
// completeness check's detection power directly, so the guarantee the
// matrix is built around does not rest on nobody having tried it: a row
// nobody wrote is exactly the zero value, and the predicate the loop
// above uses rejects it.
func TestExitInvariantMatrixRefusesAnUndeclaredRoute(t *testing.T) {
	t.Parallel()

	if (exitInvariants{}).declared {
		t.Fatal("a route added to exitKind without a matrix row would pass the completeness check")
	}
}

// TestInteractionExitNamesTheRoute covers the production selector: which
// route a completed ceremony is on, and which record its authentication
// is read from. The gate's rules are only as good as this mapping, and
// the chain state it reads is the one place the three interactive routes
// are still told apart by predicate.
func TestInteractionExitNamesTheRoute(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name    string
		state   authn.State
		want    exitKind
		backing any
	}{
		{
			name: "a chain that presented a credential",
			state: authn.State{
				Factors: []authn.Factor{{Type: authn.FactorPassword, AssuranceLevel: authn.AAL1}},
			},
			want:    exitInteractiveChain,
			backing: chainAuthn{},
		},
		{
			name: "a chain that authenticated nobody and picked an account",
			state: authn.State{
				ChooserBoundSubject:      true,
				ChooserGroupID:           "group-1",
				ChooserSelectedSessionID: "session-1",
			},
			want:    exitInteractiveChooserSession,
			backing: chooserSessionAuthn{},
		},
		{
			name:    "a chain that authenticated nobody and picked nothing",
			state:   authn.State{},
			want:    exitInteractiveEntrySession,
			backing: entrySessionAuthn{},
		},
		{
			// A chooser that bound a subject but recorded no session to
			// read it from is not a chooser re-entry: there is nothing to
			// resolve. It falls back to the session the request carries
			// rather than to a lookup with empty keys.
			name:    "a chooser that named no session",
			state:   authn.State{ChooserBoundSubject: true, ChooserGroupID: "group-1"},
			want:    exitInteractiveEntrySession,
			backing: entrySessionAuthn{},
		},
		{
			// A credential chain wins over chooser state: the account was
			// picked, then a factor ran, and the authentication being
			// reported is the one that just happened.
			name: "a chooser pick followed by a credential",
			state: authn.State{
				ChooserBoundSubject:      true,
				ChooserGroupID:           "group-1",
				ChooserSelectedSessionID: "session-1",
				Factors:                  []authn.Factor{{Type: authn.FactorPassword, AssuranceLevel: authn.AAL1}},
			},
			want:    exitInteractiveChain,
			backing: chainAuthn{},
		},
	}

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://op.example.com/interaction/i-1", http.NoBody)
	rec := &store.Interaction{ID: "i-1", ClientID: "client-1"}
	req := &authorize.Request{ClientID: "client-1", Scope: []string{"openid"}}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			kind, backing := interactionExit(
				r, terminalDeps(nil), rec, req, row.state, "user-1", terminalNow,
			)
			if kind != row.want {
				t.Errorf("interactionExit = %s, want %s", kind, row.want)
			}
			if gotType, wantType := typeName(backing), typeName(row.backing); gotType != wantType {
				t.Errorf("interactionExit read the authentication from %s, want %s", gotType, wantType)
			}
		})
	}
}

// TestSilentExitNamesTheRoute covers the selector on the no-ceremony
// path. Both routes read the session the request arrived with; they
// differ in whether the consent behind the response already existed.
func TestSilentExitNamesTheRoute(t *testing.T) {
	t.Parallel()

	active := &sessions.Active{Session: &store.Session{
		ID: "session-1", Subject: "user-1", AuthTime: terminalNow.Add(-time.Hour),
	}}

	kind, backing := silentExit(authorizeHint{grant: terminalGrant()}, active)
	if kind != exitSilentCachedGrant {
		t.Errorf("a mint against a cached grant took %s, want %s", kind, exitSilentCachedGrant)
	}
	got, err := backing.authContext(context.Background())
	if err != nil {
		t.Fatalf("authContext: %v", err)
	}
	if !got.AuthTime.Equal(active.Session.AuthTime) {
		t.Errorf("auth_time=%v, want the session's %v", got.AuthTime, active.Session.AuthTime)
	}

	kind, _ = silentExit(authorizeHint{autoGrant: &grantUpsert{}}, active)
	if kind != exitFirstPartyAutoGrant {
		t.Errorf("a first-party auto-grant took %s, want %s", kind, exitFirstPartyAutoGrant)
	}
}

// TestActiveSessionAuthnRefusesAnAbsentSession fixes the fail-closed
// side of the silent path's reader: no session record means no
// authentication to report, not a zero-valued one that would answer
// max_age with the epoch and acr with "".
func TestActiveSessionAuthnRefusesAnAbsentSession(t *testing.T) {
	t.Parallel()

	for _, active := range []*sessions.Active{nil, {}} {
		if _, err := (activeSessionAuthn{active: active}).authContext(context.Background()); !errors.Is(
			err, errSessionAuthnUnavailable,
		) {
			t.Errorf("authContext(%+v) = %v, want %v", active, err, errSessionAuthnUnavailable)
		}
	}
}

// typeName renders a backing's concrete type for comparison, so a test
// can assert which record a route reads without exporting the readers.
func typeName(v any) string { return fmt.Sprintf("%T", v) }
