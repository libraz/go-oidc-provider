// Package authorizeendpoint_test — regression tests for the
// authn-sentinel-to-HTTP-status mapping in writeAuthnError.
//
// Every exported authn sentinel carries a wire class: a terminal
// failure that wraps [authn.ErrFactorAbort] produces HTTP 400, a soft
// retry ([authn.ErrFactorRetry]) re-prompts with HTTP 200, and only a
// server fault produces HTTP 500.
package authorizeendpoint_test

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/chooser"
	"github.com/libraz/go-oidc-provider/internal/authn/consent"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/authn/password"
	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// singleSentinelAuthenticator is a test-only authenticator that:
//   - Begin: emits a prompt (simulating the emailotp "send" screen)
//   - Continue: returns continueErr verbatim (simulating the terminal
//     error cases: ErrExpired, ErrLocked, ErrResetRequired, etc.)
//
// This drives the critical path: Begin succeeds (user sees a prompt),
// user posts a submission, Continue returns a sentinel error. The
// orchestrator must decide what to do with that error.
type singleSentinelAuthenticator struct {
	continueErr error
}

const sentinelSinglePromptType = "auth.testkit.sentinel-single"

func (a *singleSentinelAuthenticator) Type() op.FactorType { return "testkit.sentinel-single" }
func (a *singleSentinelAuthenticator) AAL() op.AAL         { return op.AAL1 }
func (a *singleSentinelAuthenticator) AMR() string         { return "" }
func (a *singleSentinelAuthenticator) Prompts() []string {
	return []string{sentinelSinglePromptType}
}

func (a *singleSentinelAuthenticator) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: &interaction.Prompt{
		Type: sentinelSinglePromptType,
		Inputs: []interaction.FieldSpec{{
			Name:     "code",
			Kind:     interaction.FieldText,
			Required: true,
			MinLen:   1,
			MaxLen:   64,
		}},
	}}, nil
}

func (a *singleSentinelAuthenticator) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, a.continueErr
}

var _ op.Authenticator = (*singleSentinelAuthenticator)(nil)

// buildSingleSentinelOrchestrator wires an orchestrator with a single
// singleSentinelAuthenticator factor. Begin emits a prompt; Continue
// returns the supplied sentinel error.
func buildSingleSentinelOrchestrator(t *testing.T, sentinelErr error) *authn.Orchestrator {
	t.Helper()
	signer, err := authn.NewStateRefSigner(bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatalf("NewStateRefSigner: %v", err)
	}
	orch, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{
			&singleSentinelAuthenticator{continueErr: sentinelErr},
		},
		StateRefSigner: signer,
	})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}
	return orch
}

// wireClass is the response class an authn sentinel maps to when it
// reaches writeAuthnError.
type wireClass int

const (
	// wireRetry re-emits the factor prompt (200).
	wireRetry wireClass = iota + 1
	// wireAbort ends the attempt with a 4xx through ErrFactorAbort.
	wireAbort
	// wireStateRef rejects the continuation token (403).
	wireStateRef
	// wireChainComplete answers a tick against a finished chain (410).
	wireChainComplete
	// wireRiskDenied redirects to the RP with access_denied.
	wireRiskDenied
	// wireServerFault is a deliberate 500: a store, codec or wiring fault.
	wireServerFault
	// wireTranslated never leaves its package bare; via names the
	// sentinel it becomes on the way to the orchestrator.
	wireTranslated
	// wireMarker only ever travels alongside an ErrFactorAbort sentinel.
	wireMarker
	// wireOffChain is returned only outside the login chain
	// (constructors, enrolment ceremonies), never by a tick.
	wireOffChain
)

// sentinelClass pins one exported authn sentinel to its wire class.
type sentinelClass struct {
	err   error
	class wireClass
	via   string
}

// authnSentinelClasses is the classification of every exported Err*
// variable under internal/authn. TestAuthnSentinels_Classified fails
// when a sentinel is added without an entry here, so a new failure mode
// has to choose its response instead of inheriting the 500 fallback.
var authnSentinelClasses = map[string]sentinelClass{
	"authn.ErrAAL3RequiresUV":          {err: authn.ErrAAL3RequiresUV, class: wireAbort},
	"authn.ErrBuiltinStepNotWired":     {err: authn.ErrBuiltinStepNotWired, class: wireOffChain},
	"authn.ErrCaptchaExhausted":        {err: authn.ErrCaptchaExhausted, class: wireAbort},
	"authn.ErrChainComplete":           {err: authn.ErrChainComplete, class: wireChainComplete},
	"authn.ErrCredentialRejected":      {err: authn.ErrCredentialRejected, class: wireMarker},
	"authn.ErrFactorAbort":             {err: authn.ErrFactorAbort, class: wireAbort},
	"authn.ErrFactorLocked":            {err: authn.ErrFactorLocked, class: wireAbort},
	"authn.ErrFactorNotEnrolled":       {err: authn.ErrFactorNotEnrolled, class: wireAbort},
	"authn.ErrFactorRetry":             {err: authn.ErrFactorRetry, class: wireRetry},
	"authn.ErrInvalidStateRef":         {err: authn.ErrInvalidStateRef, class: wireStateRef},
	"authn.ErrInvalidStep":             {err: authn.ErrInvalidStep, class: wireServerFault},
	"authn.ErrNoEligibleAuthenticator": {err: authn.ErrNoEligibleAuthenticator, class: wireServerFault},
	"authn.ErrReauthNotPerformed":      {err: authn.ErrReauthNotPerformed, class: wireServerFault},
	"authn.ErrRiskDenied":              {err: authn.ErrRiskDenied, class: wireRiskDenied},
	"authn.ErrStateRefExpired":         {err: authn.ErrStateRefExpired, class: wireTranslated, via: "authn.ErrInvalidStateRef"},
	"authn.ErrStateRefKeyLength":       {err: authn.ErrStateRefKeyLength, class: wireOffChain},
	"authn.ErrStateRefMalformed":       {err: authn.ErrStateRefMalformed, class: wireTranslated, via: "authn.ErrInvalidStateRef"},
	"authn.ErrStateRefSignature":       {err: authn.ErrStateRefSignature, class: wireTranslated, via: "authn.ErrInvalidStateRef"},
	"authn.ErrStateRefStepMismatch":    {err: authn.ErrStateRefStepMismatch, class: wireTranslated, via: "authn.ErrInvalidStateRef"},
	"authn.ErrStateRefUIDMismatch":     {err: authn.ErrStateRefUIDMismatch, class: wireTranslated, via: "authn.ErrInvalidStateRef"},
	"authn.ErrSubjectMismatch":         {err: authn.ErrSubjectMismatch, class: wireAbort},
	"authn.ErrSubmissionRejected":      {err: authn.ErrSubmissionRejected, class: wireAbort},

	"chooser.ErrChooserGroupRequired": {err: chooser.ErrChooserGroupRequired, class: wireServerFault},
	"chooser.ErrSessionIDMissing":     {err: chooser.ErrSessionIDMissing, class: wireAbort},
	"chooser.ErrSessionNotInGroup":    {err: chooser.ErrSessionNotInGroup, class: wireAbort},

	"consent.ErrApprovedScopeNotRequested": {err: consent.ErrApprovedScopeNotRequested, class: wireAbort},
	"consent.ErrApprovedScopesMissing":     {err: consent.ErrApprovedScopesMissing, class: wireAbort},
	"consent.ErrRequiredScopeDeclined":     {err: consent.ErrRequiredScopeDeclined, class: wireAbort},
	"consent.ErrSubjectRequired":           {err: consent.ErrSubjectRequired, class: wireServerFault},

	"emailotp.ErrCodeMissing":        {err: emailotp.ErrCodeMissing, class: wireAbort},
	"emailotp.ErrConsumed":           {err: emailotp.ErrConsumed, class: wireAbort},
	"emailotp.ErrDeliver":            {err: emailotp.ErrDeliver, class: wireServerFault},
	"emailotp.ErrEmailMissing":       {err: emailotp.ErrEmailMissing, class: wireAbort},
	"emailotp.ErrEmailNotBound":      {err: emailotp.ErrEmailNotBound, class: wireAbort},
	"emailotp.ErrExpired":            {err: emailotp.ErrExpired, class: wireAbort},
	"emailotp.ErrLocked":             {err: emailotp.ErrLocked, class: wireAbort},
	"emailotp.ErrMailerRequired":     {err: emailotp.ErrMailerRequired, class: wireOffChain},
	"emailotp.ErrNoChallenge":        {err: emailotp.ErrNoChallenge, class: wireAbort},
	"emailotp.ErrResetRequired":      {err: emailotp.ErrResetRequired, class: wireAbort},
	"emailotp.ErrRetry":              {err: emailotp.ErrRetry, class: wireRetry},
	"emailotp.ErrStoreRequired":      {err: emailotp.ErrStoreRequired, class: wireOffChain},
	"emailotp.ErrSubjectRequired":    {err: emailotp.ErrSubjectRequired, class: wireServerFault},
	"emailotp.ErrTooManyOutstanding": {err: emailotp.ErrTooManyOutstanding, class: wireAbort},
	"emailotp.ErrUsersRequired":      {err: emailotp.ErrUsersRequired, class: wireOffChain},
	"emailotp.ErrWrongCode":          {err: emailotp.ErrWrongCode, class: wireTranslated, via: "emailotp.ErrRetry"},

	"lockout.ErrLocked":         {err: lockout.ErrLocked, class: wireTranslated, via: "authn.ErrFactorLocked"},
	"lockout.ErrResetRequired":  {err: lockout.ErrResetRequired, class: wireTranslated, via: "totp.ErrResetRequired"},
	"lockout.ErrSwapContention": {err: lockout.ErrSwapContention, class: wireServerFault},

	"passkey.ErrAAGUIDDisallowed":        {err: passkey.ErrAAGUIDDisallowed, class: wireTranslated, via: "authn.ErrFactorAbort"},
	"passkey.ErrAssertionInvalid":        {err: passkey.ErrAssertionInvalid, class: wireTranslated, via: "authn.ErrFactorRetry"},
	"passkey.ErrAttestationInvalid":      {err: passkey.ErrAttestationInvalid, class: wireOffChain},
	"passkey.ErrChallengeExpired":        {err: passkey.ErrChallengeExpired, class: wireTranslated, via: "authn.ErrFactorRetry"},
	"passkey.ErrCloneDetected":           {err: passkey.ErrCloneDetected, class: wireTranslated, via: "authn.ErrFactorAbort"},
	"passkey.ErrCredentialAlreadyExists": {err: passkey.ErrCredentialAlreadyExists, class: wireOffChain},
	"passkey.ErrCredentialNotRegistered": {err: passkey.ErrCredentialNotRegistered, class: wireTranslated, via: "authn.ErrFactorAbort"},
	"passkey.ErrInvalidConfig":           {err: passkey.ErrInvalidConfig, class: wireOffChain},
	"passkey.ErrInvalidResponse":         {err: passkey.ErrInvalidResponse, class: wireTranslated, via: "authn.ErrFactorRetry"},
	"passkey.ErrResponseMissing":         {err: passkey.ErrResponseMissing, class: wireTranslated, via: "authn.ErrFactorAbort"},
	"passkey.ErrSessionMissing":          {err: passkey.ErrSessionMissing, class: wireTranslated, via: "authn.ErrFactorAbort"},
	"passkey.ErrStoreRequired":           {err: passkey.ErrStoreRequired, class: wireOffChain},
	"passkey.ErrSubjectRequired":         {err: passkey.ErrSubjectRequired, class: wireServerFault},
	"passkey.ErrVerifierRequired":        {err: passkey.ErrVerifierRequired, class: wireOffChain},

	"password.ErrFieldMissing":       {err: password.ErrFieldMissing, class: wireAbort},
	"password.ErrInvalidCredentials": {err: password.ErrInvalidCredentials, class: wireRetry},
	"password.ErrInvalidHash":        {err: password.ErrInvalidHash, class: wireTranslated, via: "password.ErrInvalidCredentials"},
	"password.ErrPasswordMismatch":   {err: password.ErrPasswordMismatch, class: wireTranslated, via: "password.ErrInvalidCredentials"},
	"password.ErrStoreRequired":      {err: password.ErrStoreRequired, class: wireOffChain},

	"recovery.ErrAllConsumed":      {err: recovery.ErrAllConsumed, class: wireAbort},
	"recovery.ErrBatchOversized":   {err: recovery.ErrBatchOversized, class: wireServerFault},
	"recovery.ErrCodeInvalid":      {err: recovery.ErrCodeInvalid, class: wireTranslated, via: "recovery.ErrRetry"},
	"recovery.ErrCodeMissing":      {err: recovery.ErrCodeMissing, class: wireAbort},
	"recovery.ErrInvalidHash":      {err: recovery.ErrInvalidHash, class: wireServerFault},
	"recovery.ErrLocked":           {err: recovery.ErrLocked, class: wireAbort},
	"recovery.ErrNoCodes":          {err: recovery.ErrNoCodes, class: wireAbort},
	"recovery.ErrResetRequired":    {err: recovery.ErrResetRequired, class: wireAbort},
	"recovery.ErrRetry":            {err: recovery.ErrRetry, class: wireRetry},
	"recovery.ErrStoreRequired":    {err: recovery.ErrStoreRequired, class: wireOffChain},
	"recovery.ErrSubjectRequired":  {err: recovery.ErrSubjectRequired, class: wireServerFault},
	"recovery.ErrVerifierRequired": {err: recovery.ErrVerifierRequired, class: wireOffChain},

	"totp.ErrCodeMissing":      {err: totp.ErrCodeMissing, class: wireAbort},
	"totp.ErrDecrypt":          {err: totp.ErrDecrypt, class: wireServerFault},
	"totp.ErrInvalidKey":       {err: totp.ErrInvalidKey, class: wireOffChain},
	"totp.ErrLocked":           {err: totp.ErrLocked, class: wireAbort},
	"totp.ErrNotConfirmed":     {err: totp.ErrNotConfirmed, class: wireAbort},
	"totp.ErrReplayed":         {err: totp.ErrReplayed, class: wireTranslated, via: "totp.ErrRetry"},
	"totp.ErrResetRequired":    {err: totp.ErrResetRequired, class: wireAbort},
	"totp.ErrRetry":            {err: totp.ErrRetry, class: wireRetry},
	"totp.ErrStoreRequired":    {err: totp.ErrStoreRequired, class: wireOffChain},
	"totp.ErrSubjectRequired":  {err: totp.ErrSubjectRequired, class: wireServerFault},
	"totp.ErrVerifierRequired": {err: totp.ErrVerifierRequired, class: wireOffChain},
	"totp.ErrWrongCode":        {err: totp.ErrWrongCode, class: wireTranslated, via: "totp.ErrRetry"},
}

// exportedAuthnSentinels parses every non-test source file under
// internal/authn and returns the package-qualified name of each exported
// Err* variable.
func exportedAuthnSentinels(t *testing.T) []string {
	t.Helper()
	var names []string
	err := filepath.WalkDir(filepath.Join("..", "authn"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				for _, name := range spec.(*ast.ValueSpec).Names {
					if strings.HasPrefix(name.Name, "Err") {
						names = append(names, f.Name.Name+"."+name.Name)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/authn: %v", err)
	}
	sort.Strings(names)
	return names
}

// TestAuthnSentinels_Classified pins every exported authn sentinel to
// one wire class and drives each class that can reach writeAuthnError
// through POST /interaction. A sentinel missing from
// authnSentinelClasses fails here rather than surfacing as a 500.
func TestAuthnSentinels_Classified(t *testing.T) {
	t.Parallel()

	declared := exportedAuthnSentinels(t)
	seen := make(map[string]bool, len(declared))
	for _, name := range declared {
		seen[name] = true
		if _, ok := authnSentinelClasses[name]; !ok {
			t.Errorf("%s has no wire class; add it to authnSentinelClasses", name)
		}
	}
	for name := range authnSentinelClasses {
		if !seen[name] {
			t.Errorf("authnSentinelClasses lists %s, which internal/authn no longer declares", name)
		}
	}

	for name, sc := range authnSentinelClasses {
		switch sc.class {
		case wireTranslated:
			target, ok := authnSentinelClasses[sc.via]
			if !ok || target.class == wireTranslated || target.class == wireMarker || target.class == wireOffChain {
				t.Errorf("%s translates via %q, which is not a sentinel with a wire response", name, sc.via)
			}
			continue
		case wireMarker:
			if errors.Is(sc.err, authn.ErrFactorAbort) {
				t.Errorf("%s is a marker but wraps ErrFactorAbort itself", name)
			}
			continue
		case wireOffChain:
			continue
		default:
		}
		if got, want := errors.Is(sc.err, authn.ErrFactorAbort), sc.class == wireAbort; got != want {
			t.Errorf("errors.Is(%s, ErrFactorAbort) = %v, want %v", name, got, want)
		}
		if got, want := errors.Is(sc.err, authn.ErrFactorRetry), sc.class == wireRetry; got != want {
			t.Errorf("errors.Is(%s, ErrFactorRetry) = %v, want %v", name, got, want)
		}
	}

	names := make([]string, 0, len(authnSentinelClasses))
	for name := range authnSentinelClasses {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sc := authnSentinelClasses[name]
		if sc.class == wireTranslated || sc.class == wireMarker || sc.class == wireOffChain {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rr := submitSentinel(t, sc.err)
			assertWireClass(t, rr, sc.class)
		})
	}
}

// submitSentinel runs /authorize → GET /interaction → POST /interaction
// against a factor whose Continue returns err.
func submitSentinel(t *testing.T, err error) *httptest.ResponseRecorder {
	t.Helper()
	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Authn = buildSingleSentinelOrchestrator(t, err)
	})
	start := startInteractionFlow(t, h)
	getResp := doInteractionGet(t, h, start)
	defer func() { _ = getResp.Body.Close() }()
	stateRef, csrfCookie := readPromptStateRef(t, getResp)
	return postSubmission(t, h, start, csrfCookie, interaction.FormSubmission{
		StateRef: stateRef,
		Values:   map[string]string{"code": "123456"},
	})
}

func assertWireClass(t *testing.T, rr *httptest.ResponseRecorder, class wireClass) {
	t.Helper()
	want := map[wireClass]int{
		wireRetry:         http.StatusOK,
		wireAbort:         http.StatusBadRequest,
		wireStateRef:      http.StatusForbidden,
		wireChainComplete: http.StatusGone,
		wireServerFault:   http.StatusInternalServerError,
	}
	if class == wireRiskDenied {
		loc, err := url.Parse(rr.Header().Get("Location"))
		if rr.Code < 300 || rr.Code >= 400 || err != nil || loc.Query().Get("error") != "access_denied" {
			t.Fatalf("status=%d Location=%q, want an RP redirect carrying access_denied", rr.Code, rr.Header().Get("Location"))
		}
		return
	}
	if rr.Code != want[class] {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, want[class], rr.Body.String())
	}
}

// TestWriteAuthnError_DefaultBranch_Is500 confirms that writeAuthnError's
// default case returns HTTP 500 for any unrecognised error. The shortest
// route to the default branch is a Begin that fails immediately (no CSRF
// dance needed).
func TestWriteAuthnError_DefaultBranch_Is500(t *testing.T) {
	t.Parallel()

	arbitraryErr := errors.New("some unknown factor error not in writeAuthnError switch")

	signer, err := authn.NewStateRefSigner(bytes.Repeat([]byte{0xBC}, 32))
	if err != nil {
		t.Fatalf("NewStateRefSigner: %v", err)
	}
	orch, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{
			&alwaysErrAuthenticator{err: arbitraryErr},
		},
		StateRefSigner: signer,
	})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}

	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Authn = orch
	})
	start := startInteractionFlow(t, h)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.interactionPth+"/"+start.uid, nil)
	req.AddCookie(start.interactionCk)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("default branch: got HTTP %d want 500 body=%s", rr.Code, rr.Body.String())
	}
}

// alwaysErrAuthenticator returns its stored error on Begin. This drives
// writeAuthnError's default branch via the GET /interaction path.
type alwaysErrAuthenticator struct {
	err error
}

func (a *alwaysErrAuthenticator) Type() op.FactorType { return "testkit.always-err" }
func (a *alwaysErrAuthenticator) AAL() op.AAL         { return op.AAL1 }
func (a *alwaysErrAuthenticator) AMR() string         { return "" }
func (a *alwaysErrAuthenticator) Prompts() []string   { return []string{"auth.testkit.always-err"} }
func (a *alwaysErrAuthenticator) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{}, a.err
}

func (a *alwaysErrAuthenticator) Continue(_ context.Context, _ op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{}, a.err
}

var _ op.Authenticator = (*alwaysErrAuthenticator)(nil)
