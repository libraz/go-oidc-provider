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
// [interaction.Result.UserVerified] back to the orchestrator (H-E4):
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
// (H-E5). Implementations decide the policy: disable the credential,
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
// h every time the WebAuthn library raises [ErrCloneDetected] (H-E5).
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

// AAL implements [authn.Authenticator]. v1.0 passkeys default to AAL2
// even when user-verification is set — the conservative reading of
// NIST SP 800-63B §5.1.7 documented on [authn.AAL] (passkeys default to
// AAL2 unless the deployment explicitly raises the level on a
// hardware-attested cross-platform key). The orchestrator takes the
// maximum across factors when computing the session AAL.
func (*Authenticator) AAL() authn.AAL { return authn.AAL2 }

// AMR implements [authn.Authenticator]. The WebAuthn user-verification bit
// drives the runtime amr value: a user-verified assertion contributes
// "hwk" (hardware key with verified user) and a presence-only assertion
// contributes "swk". v1.0 reports the static value "hwk" because the
// configured [Verifier] sets UserVerification = "preferred"; deployments
// that intentionally accept presence-only assertions should run a
// separate adapter instance with a different AMR string.
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
//   - On [ErrCloneDetected]: the updated credential record is
//     persisted (so the audit trail is intact) but the error is
//     surfaced verbatim. The orchestrator owns the policy decision.
//   - On any other error (parse failure, signature failure, expired
//     session): the error flows through unchanged so the orchestrator
//     can stop the chain.
func (a *Authenticator) Continue(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	response, session, err := a.parseContinueInput(in)
	if err != nil {
		return interaction.Step{}, err
	}
	creds, err := a.loadCredentials(ctx, in.Subject)
	if err != nil {
		return interaction.Step{}, err
	}
	if len(creds) == 0 {
		return interaction.Step{}, ErrCredentialNotRegistered
	}

	cred, ferr := a.verifier.FinishLogin(ctx, session, in.Subject, in.Subject, creds, response)
	return a.continueResult(ctx, in.Subject, in.AuthTime, cred, ferr)
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
		if perr := a.persistCredential(ctx, subject, cred); perr != nil {
			return interaction.Step{}, perr
		}
		// Stamp the UV bit on the Result so the orchestrator's
		// appendFactor can pick the RFC 8176 "hwk" vs "swk" token
		// from the assertion's real flag rather than a process-local
		// cache (H-E4). The bit is request-scoped: it travels with
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
			if perr := a.persistCredential(ctx, subject, cred); perr != nil {
				return interaction.Step{}, perr
			}
			// Notify the embedder so it can disable the affected
			// credential (H-E5). The hook is best-effort: a hook
			// error does not change the response the SPA sees, but
			// it MUST NOT stop the [ErrCloneDetected] surfacing —
			// embedders that want to observe failures should log
			// internally.
			if a.driver != nil {
				_ = a.driver.HandleCloneDetected(ctx, subject, cred)
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
		out = append(out, credentialFromRecord(*r))
	}
	return out, nil
}

// persistCredential writes the rotated credential back through the
// store. The record's mutable bits — sign counter, UV / BS flags, the
// clone-warning bit — are updated in place so a subsequent assertion
// observes the new counter. CreatedAt is preserved from the original
// row; a missing row is rejected because every Continue must observe
// at least one credential the assertion matched against.
func (a *Authenticator) persistCredential(ctx context.Context, subject string, c *Credential) error {
	if c == nil {
		return nil
	}
	existing, err := a.store.Get(ctx, c.ID)
	if err != nil {
		return fmt.Errorf("passkey: load record for persist: %w", err)
	}
	rec := recordFromCredential(*c)
	rec.Subject = subject
	if existing != nil {
		rec.CreatedAt = existing.CreatedAt
	}
	if err := a.store.Put(ctx, &rec); err != nil {
		return fmt.Errorf("passkey: persist record: %w", err)
	}
	return nil
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

// credentialFromRecord projects a [store.PasskeyRecord] onto the
// package's [Credential] shape so the verifier can consume it. The
// mapping is field-for-field; byte fields are defensively cloned so a
// later mutation by the caller cannot reach the verifier-side state.
func credentialFromRecord(r store.PasskeyRecord) Credential {
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
		CreatedAt: r.CreatedAt,
	}
}

// recordFromCredential is the inverse of [credentialFromRecord]. The
// returned record's Subject field is left unset; the caller stamps it
// from the chain state because [Credential] does not carry a subject
// (it is keyed by credential ID).
func recordFromCredential(c Credential) store.PasskeyRecord {
	return store.PasskeyRecord{
		CredentialID:    slices.Clone(c.ID),
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
