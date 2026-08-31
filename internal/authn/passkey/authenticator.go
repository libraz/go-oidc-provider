package passkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// PromptType is the [interaction.Prompt.Type] the adapter emits. The
// string is part of the orchestrator's stable wire surface and matches
// the constant set [op.Authenticator.Prompts] returns.
const PromptType = "auth.passkey"

// ResponseFieldName is the [interaction.FieldSpec.Name] the adapter
// expects in [interaction.FormSubmission.Values]. The SPA serialises
// the WebAuthn AssertionResponse to JSON (per
// PublicKeyCredential.toJSON) and submits it under this key.
const ResponseFieldName = "response"

// responseMaxBytes caps the WebAuthn assertion response the adapter
// accepts. Browser-emitted PublicKeyCredential JSON is on the order of
// 1–2 KiB; 16 KiB is comfortably above the realistic upper bound while
// keeping the parser away from pathological inputs.
const responseMaxBytes = 16 * 1024

// ErrSubjectRequired is returned by [Authenticator.Begin] /
// [Authenticator.Continue] when the orchestrator passes an empty
// [op.BeginInput.Subject] / [op.ContinueInput.Subject]. v1.0 wires
// passkey as a known-subject factor (see [Verifier.BeginLogin]); a
// chain that places passkey first must run an identifying factor
// (password, login_hint binding) ahead of it.
var ErrSubjectRequired = errors.New("passkey: subject is required")

// ErrResponseMissing is returned by [Authenticator.Continue] when the
// SPA's submission omits [ResponseFieldName]. The orchestrator's
// [interaction.FieldSpec] validation should already have caught this;
// the adapter re-checks at the trust boundary.
var ErrResponseMissing = errors.New("passkey: response field is missing")

// ErrSessionMissing is returned by [Authenticator.Continue] when the
// orchestrator dispatches a submission without the prior Begin's
// scratch payload. It signals chain corruption — a tampered or absent
// [State.FactorScratch] — and the orchestrator aborts the chain.
var ErrSessionMissing = errors.New("passkey: session scratch is missing")

// Authenticator is the [op.Authenticator] adapter for the WebAuthn
// passkey factor. It binds a [Verifier] (the primitive that drives the
// assertion ceremony) to a [store.PasskeyStore] (the persistent
// credential record) so the orchestrator can drive the factor without
// knowing about either.
// The session that ferries the challenge and allow-list across the
// Begin → Continue boundary rides the orchestrator's
// [interaction.Step.Scratch] / [op.ContinueInput.Scratch] channel; it
// never reaches the SPA, the cookie, or any persistent store. Callers
// MUST construct the adapter through [NewAuthenticator]; the zero
// value is not usable.
//
// The UV bit observed on a successful assertion rides
// [interaction.Result.UserVerified] back to the orchestrator:
// the adapter does NOT keep an in-process cache, so a multi-replica
// deployment without sticky sessions stays consistent — the bit
// travels with the request that produced it.
type Authenticator struct {
	verifier *Verifier
	store    store.PasskeyStore
	driver   CloneDetectionHandler
}

// CloneDetectionHandler is the optional embedder hook the adapter
// invokes when the WebAuthn library reports a credential clone
// Implementations decide the policy: disable the credential,
// page the SOC, force a re-enrolment. The adapter calls the handler
// with the rotated [Credential] (CloneWarning bit set, original sign
// counter preserved) so the embedder can correlate the credential
// against its account-management UI.
//
// The hook is best-effort: a non-nil error is logged through the
// orchestrator's audit pipeline but does not change the response the
// SPA observes — [ErrCloneDetected] still bubbles up through
// Continue. Implementations MUST be safe for concurrent use.
type CloneDetectionHandler interface {
	HandleCloneDetected(ctx context.Context, subject string, cred *Credential) error
}

// CloneDetectionHandlerFunc adapts a plain function to the
// [CloneDetectionHandler] interface.
type CloneDetectionHandlerFunc func(ctx context.Context, subject string, cred *Credential) error

// HandleCloneDetected implements [CloneDetectionHandler].
func (f CloneDetectionHandlerFunc) HandleCloneDetected(ctx context.Context, subject string, cred *Credential) error {
	return f(ctx, subject, cred)
}

// ErrVerifierRequired / ErrStoreRequired are returned by
// [NewAuthenticator] when one of its arguments is nil. Surfacing the
// configuration error at construction is preferred to a runtime panic
// on the first Begin / Continue: the caller decides whether the
// missing dependency is a fatal startup condition or a graceful
// degradation.
var (
	ErrVerifierRequired = errors.New("passkey: verifier is required")
	ErrStoreRequired    = errors.New("passkey: store is required")
)

// NewAuthenticator constructs an [Authenticator]. Both arguments are
// required; a nil verifier or store would surface as a panic on the
// first Begin / Continue otherwise, which is harder to diagnose than
// the construction-time error returned here.
func NewAuthenticator(verifier *Verifier, passkeyStore store.PasskeyStore) (*Authenticator, error) {
	if verifier == nil {
		return nil, ErrVerifierRequired
	}
	if passkeyStore == nil {
		return nil, ErrStoreRequired
	}
	return &Authenticator{verifier: verifier, store: passkeyStore}, nil
}

// WithCloneDetectionHandler returns a copy of the adapter that calls
// h every time the WebAuthn library raises [ErrCloneDetected].
// The hook is invoked with the persisted Credential (CloneWarning bit
// set, sign counter preserved from the prior record) so the embedder
// can disable the affected credential in its account-management UI.
// The hook runs after the credential is persisted; a hook error does
// not change the response the SPA observes.
func (a *Authenticator) WithCloneDetectionHandler(h CloneDetectionHandler) *Authenticator {
	cp := *a
	cp.driver = h
	return &cp
}

// Type implements [authn.Authenticator]. Always returns [authn.FactorPasskey].
func (*Authenticator) Type() authn.FactorType { return authn.FactorPasskey }

// AAL implements [authn.Authenticator]. The returned level is the
// ceiling a passkey assertion can reach, not a promise every assertion
// reaches it: AAL2 requires the user-verification gesture that turns
// proof of possession into two factors, and under
// [Config.UserVerification] = "preferred" an authenticator MAY answer
// with a presence-only assertion. The per-assertion UV flag rides
// [interaction.Result.UserVerified] onto [authn.Factor.UserVerified],
// and [authn.Factor.EffectiveAAL] drops a UV-less assertion back to
// AAL1 there — so a deployment that must have AAL2 from every login
// sets [Config.UserVerification] to "required".
//
// The ceiling stays AAL2 rather than AAL3 per the conservative reading
// of NIST SP 800-63B §5.1.7 documented on [authn.AAL]: reaching AAL3
// takes a hardware-attested cross-platform key the deployment vouches
// for. The orchestrator takes the maximum across factors when computing
// the session AAL.
func (*Authenticator) AAL() authn.AAL { return authn.AAL2 }

// AMR implements [authn.Authenticator]. The value is the RFC 8176 token
// for the strongest ceremony the adapter drives; the runtime token is
// picked per assertion by [authn.Factor.AMRValue] from the UV flag the
// Result carried — "hwk" (hardware key with verified user) when the
// authenticator verified the user, "swk" when it only proved presence.
func (*Authenticator) AMR() string { return "hwk" }

// Prompts implements [authn.Authenticator]. The adapter emits a single
// prompt type; the slice is read-only by contract.
func (*Authenticator) Prompts() []string { return []string{PromptType} }

// Begin implements [authn.Authenticator]. It loads the subject's
// registered credentials, kicks off a WebAuthn assertion ceremony, and
// returns the prompt with the challenge plus the encoded session in
// [interaction.Step.Scratch].
// Subject is required; v1.0 does not support discoverable-credential
// flows where the subject is unknown until after the assertion. A
// subject with no registered credentials returns
// [ErrCredentialNotRegistered] — the orchestrator surfaces that as a
// chain failure rather than treating "no passkey" as "skip this
// factor".
func (a *Authenticator) Begin(ctx context.Context, in authn.BeginInput) (interaction.Step, error) {
	if in.Subject == "" {
		return interaction.Step{}, ErrSubjectRequired
	}
	creds, err := a.loadCredentials(ctx, in.Subject)
	if err != nil {
		return interaction.Step{}, err
	}
	if len(creds) == 0 {
		return interaction.Step{}, ErrCredentialNotRegistered
	}
	_, session, err := a.verifier.BeginLogin(ctx, in.Subject, in.Subject, creds)
	if err != nil {
		return interaction.Step{}, err
	}
	scratch, err := json.Marshal(session)
	if err != nil {
		return interaction.Step{}, fmt.Errorf("passkey: encode session: %w", err)
	}
	return interaction.Step{
		Prompt:  a.prompt(*session, creds),
		Scratch: scratch,
	}, nil
}

// Continue implements [authn.Authenticator]. It decodes the session from
// the orchestrator-supplied scratch, replays the credential list from
// the store, and validates the SPA-supplied assertion response through
// the [Verifier]. On success it persists the rotated credential record
// (sign counter, UV / BS flags, clone-warning).
// Outcomes:
//   - On success: [interaction.Step.Result] is populated with the
//     bound subject and the orchestrator's [authn.ContinueInput.AuthTime].
//   - On a rejected assertion (bad signature, challenge mismatch,
//     unregistered credential, unparsable payload, expired ceremony):
//     the error carries [authn.ErrFactorRetry], so the orchestrator
//     records the attempt and re-issues a fresh challenge instead of
//     surfacing a server fault at a user who touched the wrong key.
//   - On [ErrCloneDetected]: the updated credential record is persisted
//     (so the audit trail is intact) and the error carries
//     [authn.ErrFactorAbort] — terminal for this attempt, and the
//     orchestrator owns the policy decision.
//   - On a store or configuration fault: the error flows through
//     unclassified so the HTTP layer surfaces it as a server error and
//     the failure counters stay clean.
//
// See [classifyContinueError] for which error lands in which class and
// why the distinction has to be made here rather than upstream.
func (a *Authenticator) Continue(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	response, session, err := a.parseContinueInput(in)
	if err != nil {
		return interaction.Step{}, classifyContinueError(err)
	}
	creds, err := a.loadCredentials(ctx, in.Subject)
	if err != nil {
		return interaction.Step{}, err
	}
	if len(creds) == 0 {
		return interaction.Step{}, classifyContinueError(ErrCredentialNotRegistered)
	}

	cred, ferr := a.verifier.FinishLogin(ctx, session, in.Subject, in.Subject, creds, response)
	step, err := a.continueResult(ctx, in.Subject, in.AuthTime, cred, ferr)
	return step, classifyContinueError(err)
}

// classifyContinueError stamps the orchestrator-facing failure class on
// a ceremony error. The orchestrator reads one of two sentinels to decide
// both what it records and where the chain goes, and an error carrying
// neither is treated as an authenticator fault: nothing reaches the
// observer feed or the audit stream, and the HTTP layer renders a 500.
// That is the right answer for a store outage and the wrong one for
// everything the SPA can cause, which is why every exit the submitted
// assertion or the ceremony's own clock can reach is classified here.
//
//   - [authn.ErrFactorRetry] for a rejected assertion. The submission was
//     judged and refused, and a fresh ceremony can succeed: a cancelled
//     WebAuthn dialog, the wrong security key, a challenge that ran out
//     its five minutes. The orchestrator observes the failure and
//     re-prompts with a new challenge.
//   - [authn.ErrFactorAbort] for a terminal refusal. A clone warning or
//     an authenticator model that has fallen out of the allowlist is not
//     retryable — a fresh challenge would be refused the same way — and a
//     submission arriving without the ceremony state, or without the
//     response field its own prompt declared required, cannot have come
//     from the prompt as rendered.
//
// Anything else — a store failure, an unusable configuration, a corrupt
// scratch payload — is returned unchanged. Those never evaluated a
// credential, and filing them as credential failures would make an outage
// read as credential stuffing while an embedder driving lockout off the
// observer feed locked out the users it was unable to authenticate.
func classifyContinueError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrAssertionInvalid),
		errors.Is(err, ErrCredentialNotRegistered),
		errors.Is(err, ErrInvalidResponse),
		errors.Is(err, ErrChallengeExpired):
		return fmt.Errorf("%w: %w", err, authn.ErrFactorRetry)
	case errors.Is(err, ErrCloneDetected),
		errors.Is(err, ErrAAGUIDDisallowed),
		errors.Is(err, ErrSessionMissing),
		errors.Is(err, ErrResponseMissing):
		return fmt.Errorf("%w: %w", err, authn.ErrFactorAbort)
	default:
		return err
	}
}

// parseContinueInput validates the orchestrator-supplied input and
// returns the parsed assertion bytes plus the decoded session ready
// for [Verifier.FinishLogin]. The split keeps [Authenticator.Continue]
// below the gocognit budget while preserving the trust-boundary checks
// (subject, scratch, field presence, byte cap, JSON shape).
func (a *Authenticator) parseContinueInput(in authn.ContinueInput) ([]byte, *Session, error) {
	if in.Subject == "" {
		return nil, nil, ErrSubjectRequired
	}
	if len(in.Scratch) == 0 {
		return nil, nil, ErrSessionMissing
	}
	response, ok := in.Submission.Values[ResponseFieldName]
	if !ok || response == "" {
		return nil, nil, ErrResponseMissing
	}
	if len(response) > responseMaxBytes {
		return nil, nil, fmt.Errorf("%w: response exceeds %d bytes", ErrInvalidResponse, responseMaxBytes)
	}
	var session Session
	if err := json.Unmarshal(in.Scratch, &session); err != nil {
		return nil, nil, fmt.Errorf("passkey: decode session: %w", err)
	}
	return []byte(response), &session, nil
}

// continueResult dispatches the [Verifier.FinishLogin] outcome. A nil
// error persists the rotated credential and returns Result; an
// [ErrCloneDetected] error still persists (so the clone-warning bit
// survives) but surfaces verbatim so the orchestrator can stop the
// chain; any other error flows through unchanged.
func (a *Authenticator) continueResult(ctx context.Context, subject string, authTime time.Time, cred *Credential, ferr error) (interaction.Step, error) {
	switch {
	case ferr == nil:
		if _, perr := a.persistCredential(ctx, cred); perr != nil {
			return interaction.Step{}, perr
		}
		// Stamp the UV bit on the Result so the orchestrator's
		// appendFactor can pick the RFC 8176 "hwk" vs "swk" token
		// from the assertion's real flag rather than a process-local
		// cache. The bit is request-scoped: it travels with
		// the Step and is dropped once the Factor has been recorded.
		uv := false
		if cred != nil {
			uv = cred.Flags.UserVerified
		}
		return interaction.Step{Result: &interaction.Result{
			Subject:      subject,
			AuthTime:     authTime,
			UserVerified: uv,
		}}, nil
	case errors.Is(ferr, ErrCloneDetected):
		if cred != nil {
			persisted, perr := a.persistCredential(ctx, cred)
			if perr != nil {
				return interaction.Step{}, perr
			}
			// Notify the embedder so it can disable the affected
			// credential. The hook is best-effort: a hook
			// error does not change the response the SPA sees, but
			// it MUST NOT stop the [ErrCloneDetected] surfacing —
			// embedders that want to observe failures should log
			// internally.
			if a.driver != nil {
				_ = a.driver.HandleCloneDetected(ctx, subject, persisted)
			}
		}
		return interaction.Step{}, ferr
	default:
		return interaction.Step{}, ferr
	}
}

// loadCredentials reads the subject's registered passkeys and projects
// the [store.PasskeyRecord] rows onto the package's [Credential] shape.
// The orchestrator calls Begin and Continue with the same subject, so
// the slice is identical between the two calls modulo a concurrent
// account-management mutation; that race is the embedder's
// responsibility to serialise.
func (a *Authenticator) loadCredentials(ctx context.Context, subject string) ([]Credential, error) {
	records, err := a.store.ListBySubject(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("passkey: list credentials: %w", err)
	}
	out := make([]Credential, 0, len(records))
	for _, r := range records {
		if r == nil {
			continue
		}
		out = append(out, CredentialFromRecord(*r))
	}
	return out, nil
}

// persistCredential atomically applies the assertion fields through
// the store. The verifier stamps expectedSignCount from the exact
// record used for signature verification, allowing the backend to
// preserve monotonic security state when concurrent assertions finish
// in reverse order. A missing row is rejected because every Continue
// must observe a credential the assertion matched against.
func (a *Authenticator) persistCredential(ctx context.Context, c *Credential) (*Credential, error) {
	if c == nil {
		return nil, errors.New("passkey: cannot persist nil credential")
	}

	rec, err := a.store.UpdateAssertion(ctx, c.ID, store.PasskeyAssertionUpdate{
		ExpectedSignCount: c.expectedSignCount,
		SignCount:         c.Authenticator.SignCount,
		UserPresent:       c.Flags.UserPresent,
		UserVerified:      c.Flags.UserVerified,
		BackupState:       c.Flags.BackupState,
		CloneWarning:      c.Authenticator.CloneWarning,
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: persist assertion: %w", err)
	}
	if rec == nil {
		return nil, errors.New("passkey: persist assertion returned nil record")
	}
	persisted := CredentialFromRecord(*rec)
	return &persisted, nil
}

// prompt builds the [interaction.PasskeyPromptData] payload exposed to
// the SPA. Challenge bytes ride [Session.Challenge] (base64url-decoded);
// the allow-list is projected from the credential records so the SPA
// can hand it to navigator.credentials.get without re-reading the
// store. The session is NOT embedded here — it travels separately
// through [interaction.Step.Scratch].
func (*Authenticator) prompt(session Session, creds []Credential) *interaction.Prompt {
	descriptors := make([]interaction.PasskeyCredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		descriptors = append(descriptors, interaction.PasskeyCredentialDescriptor{
			ID:         append([]byte(nil), c.ID...),
			Type:       "public-key",
			Transports: append([]string(nil), c.Transports...),
		})
	}
	challenge := decodeChallenge(session.Challenge)
	return &interaction.Prompt{
		Type: PromptType,
		Data: interaction.PasskeyPromptData{
			Challenge:        challenge,
			AllowCredentials: descriptors,
		},
		Inputs: []interaction.FieldSpec{{
			Name:     ResponseFieldName,
			Kind:     interaction.FieldHidden,
			Label:    "auth.passkey.response",
			Required: true,
			MaxLen:   responseMaxBytes,
		}},
	}
}

// Compile-time confirmation that *Authenticator satisfies the public
// interface. The receiver is a pointer because verifier and store are
// reference-typed; a value-receiver method set would force an
// unnecessary copy at every interface dispatch.
var _ authn.Authenticator = (*Authenticator)(nil)

// CredentialFromRecord projects a [store.PasskeyRecord] onto the
// package's [Credential] shape so the verifier can consume it. The
// mapping is field-for-field; byte fields are defensively cloned so a
// later mutation by the caller cannot reach the verifier-side state.
//
// It is exported so the enrolment facade in op/passkeykit can build the
// already-registered list the registration ceremony needs without
// duplicating the projection.
func CredentialFromRecord(r store.PasskeyRecord) Credential {
	return Credential{
		ID:              slices.Clone(r.CredentialID),
		PublicKey:       slices.Clone(r.PublicKey),
		AttestationType: r.AttestationType,
		Transports:      append([]string(nil), r.Transports...),
		Flags: CredentialFlags{
			UserPresent:    r.UserPresent,
			UserVerified:   r.UserVerified,
			BackupEligible: r.BackupEligible,
			BackupState:    r.BackupState,
		},
		Authenticator: AuthenticatorData{
			AAGUID:       slices.Clone(r.AAGUID),
			SignCount:    r.SignCount,
			CloneWarning: r.CloneWarning,
			Attachment:   r.Attachment,
		},
		CreatedAt:         r.CreatedAt,
		expectedSignCount: r.SignCount,
	}
}

// RecordFromCredential is the inverse of [CredentialFromRecord]: it
// projects a freshly registered [Credential] onto the persistent
// [store.PasskeyRecord] shape. The subject is supplied separately
// because a Credential carries no owner — the ceremony result says what
// the authenticator produced, not who it belongs to, and binding the
// two is a decision the caller makes from its own authenticated
// context.
//
// expectedSignCount is deliberately not carried across: it is the
// assertion-time comparison snapshot, and a record being created for
// the first time has no prior counter to compare against.
func RecordFromCredential(subject string, c Credential) store.PasskeyRecord {
	return store.PasskeyRecord{
		CredentialID:    slices.Clone(c.ID),
		Subject:         subject,
		PublicKey:       slices.Clone(c.PublicKey),
		AAGUID:          slices.Clone(c.Authenticator.AAGUID),
		SignCount:       c.Authenticator.SignCount,
		AttestationType: c.AttestationType,
		Transports:      append([]string(nil), c.Transports...),
		UserPresent:     c.Flags.UserPresent,
		UserVerified:    c.Flags.UserVerified,
		BackupEligible:  c.Flags.BackupEligible,
		BackupState:     c.Flags.BackupState,
		CloneWarning:    c.Authenticator.CloneWarning,
		Attachment:      c.Authenticator.Attachment,
		CreatedAt:       c.CreatedAt,
	}
}

// decodeChallenge converts a [Session.Challenge] string to the raw
// challenge bytes the [interaction.PasskeyPromptData] surface expects.
// The webauthn library emits the challenge as base64url WITHOUT
// padding; a decoding failure returns nil so the SPA receives a
// recognisably-bad challenge rather than a partial one.
func decodeChallenge(challenge string) []byte {
	if challenge == "" {
		return nil
	}
	out, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil {
		return nil
	}
	return out
}
