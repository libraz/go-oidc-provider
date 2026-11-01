package op

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/internal/ssf"
)

// SecurityEvent is a security event the embedder reports to SSF
// receivers through [Provider.EmitSecurityEvent]. The set is sealed: the
// implementations are [CredentialChange], [SessionRevoked],
// [AccountDisabled], [AccountEnabled], [AccountPurged] and
// [CredentialCompromise].
//
// Stable since v1.5.
type SecurityEvent interface {
	securityEvent() (ssf.EventType, string, ssf.Fields, error)
}

// CredentialType names the kind of credential a [CredentialChange] or
// [CredentialCompromise] is about (CAEP 1.0 §3.3).
//
// Stable since v1.5.
type CredentialType string

const (
	// CredentialTypePassword is a password.
	//
	// Stable since v1.5.
	CredentialTypePassword CredentialType = "password"

	// CredentialTypePIN is a PIN.
	//
	// Stable since v1.5.
	CredentialTypePIN CredentialType = "pin"

	// CredentialTypeX509 is an X.509 certificate.
	//
	// Stable since v1.5.
	CredentialTypeX509 CredentialType = "x509"

	// CredentialTypeFIDO2Platform is a FIDO2 platform authenticator.
	//
	// Stable since v1.5.
	CredentialTypeFIDO2Platform CredentialType = "fido2-platform"

	// CredentialTypeFIDO2Roaming is a FIDO2 roaming authenticator.
	//
	// Stable since v1.5.
	CredentialTypeFIDO2Roaming CredentialType = "fido2-roaming"

	// CredentialTypeFIDOU2F is a FIDO U2F authenticator.
	//
	// Stable since v1.5.
	CredentialTypeFIDOU2F CredentialType = "fido-u2f"

	// CredentialTypeApp is an authenticator app (for example TOTP).
	//
	// Stable since v1.5.
	CredentialTypeApp CredentialType = "app"

	// CredentialTypePhoneSMS is a phone number reached by SMS.
	//
	// Stable since v1.5.
	CredentialTypePhoneSMS CredentialType = "phone-sms"

	// CredentialTypePhoneVoice is a phone number reached by voice call.
	//
	// Stable since v1.5.
	CredentialTypePhoneVoice CredentialType = "phone-voice"
)

func (t CredentialType) valid() bool {
	switch t {
	case CredentialTypePassword, CredentialTypePIN, CredentialTypeX509,
		CredentialTypeFIDO2Platform, CredentialTypeFIDO2Roaming, CredentialTypeFIDOU2F,
		CredentialTypeApp, CredentialTypePhoneSMS, CredentialTypePhoneVoice:
		return true
	}
	return false
}

// CredentialChangeType is what happened to the credential in a
// [CredentialChange] (CAEP 1.0 §3.3).
//
// Stable since v1.5.
type CredentialChangeType string

const (
	// CredentialChangeCreate reports a newly enrolled credential.
	//
	// Stable since v1.5.
	CredentialChangeCreate CredentialChangeType = "create"

	// CredentialChangeRevoke reports a revoked credential.
	//
	// Stable since v1.5.
	CredentialChangeRevoke CredentialChangeType = "revoke"

	// CredentialChangeUpdate reports a changed credential.
	//
	// Stable since v1.5.
	CredentialChangeUpdate CredentialChangeType = "update"

	// CredentialChangeDelete reports a deleted credential.
	//
	// Stable since v1.5.
	CredentialChangeDelete CredentialChangeType = "delete"
)

func (t CredentialChangeType) valid() bool {
	switch t {
	case CredentialChangeCreate, CredentialChangeRevoke, CredentialChangeUpdate, CredentialChangeDelete:
		return true
	}
	return false
}

// AccountDisabledReason is the optional reason of an [AccountDisabled]
// event. The zero value omits it.
//
// Experimental: the RISC 1.0 event types are published as a draft, so
// the RISC surface MAY change in a minor release to track it.
type AccountDisabledReason string

const (
	// AccountDisabledHijacking reports an account disabled because it
	// was hijacked.
	AccountDisabledHijacking AccountDisabledReason = "hijacking"

	// AccountDisabledBulkAccount reports an account disabled as one of
	// a set of accounts created in bulk.
	AccountDisabledBulkAccount AccountDisabledReason = "bulk-account"
)

func (r AccountDisabledReason) valid() bool {
	return r == "" || r == AccountDisabledHijacking || r == AccountDisabledBulkAccount
}

// CredentialChange is the CAEP 1.0 §3.3 credential-change event: a
// credential of Subject was created, changed, revoked or deleted.
//
// Stable since v1.5.
type CredentialChange struct {
	// Subject is the OP-internal subject. Required.
	Subject string

	// CredentialType is the kind of credential. Required.
	CredentialType CredentialType

	// ChangeType is what happened to it. Required.
	ChangeType CredentialChangeType

	// FriendlyName is the optional user-facing name of the credential.
	FriendlyName string

	// ReasonAdmin is the administrative reason, BCP 47 language tag to
	// text. Empty substitutes a default English text.
	ReasonAdmin map[string]string
}

func (e CredentialChange) securityEvent() (ssf.EventType, string, ssf.Fields, error) {
	if !e.CredentialType.valid() {
		return "", "", ssf.Fields{}, errSecurityEvent("CredentialChange.CredentialType is not a CAEP credential type")
	}
	if !e.ChangeType.valid() {
		return "", "", ssf.Fields{}, errSecurityEvent("CredentialChange.ChangeType is not a CAEP change type")
	}
	return ssf.EventCredentialChange, e.Subject, ssf.Fields{
		ReasonAdmin:    e.ReasonAdmin,
		CredentialType: string(e.CredentialType),
		ChangeType:     string(e.ChangeType),
		FriendlyName:   e.FriendlyName,
	}, nil
}

// SessionRevoked is the CAEP 1.0 §3.1 session-revoked event: the
// sessions of Subject have ended. The OP emits it on its own for an
// RP-Initiated Logout (one per session the logout ends, so a subject
// with several sessions produces several) and for
// [Provider.RevokeSubject]; report it here for a session ended out of
// band.
//
// Stable since v1.5.
type SessionRevoked struct {
	// Subject is the OP-internal subject. Required.
	Subject string

	// ReasonAdmin is the administrative reason, BCP 47 language tag to
	// text. Empty substitutes a default English text.
	ReasonAdmin map[string]string
}

func (e SessionRevoked) securityEvent() (ssf.EventType, string, ssf.Fields, error) {
	return ssf.EventSessionRevoked, e.Subject, ssf.Fields{ReasonAdmin: e.ReasonAdmin}, nil
}

// AccountDisabled is the RISC account-disabled event.
//
// Experimental: the RISC 1.0 event types are published as a draft, so
// the RISC surface MAY change in a minor release to track it.
type AccountDisabled struct {
	// Subject is the OP-internal subject. Required.
	Subject string

	// Reason is the optional reason the account was disabled.
	Reason AccountDisabledReason
}

func (e AccountDisabled) securityEvent() (ssf.EventType, string, ssf.Fields, error) {
	if !e.Reason.valid() {
		return "", "", ssf.Fields{}, errSecurityEvent("AccountDisabled.Reason is not a RISC reason")
	}
	return ssf.EventAccountDisabled, e.Subject, ssf.Fields{Reason: string(e.Reason)}, nil
}

// AccountEnabled is the RISC account-enabled event.
//
// Experimental: the RISC 1.0 event types are published as a draft, so
// the RISC surface MAY change in a minor release to track it.
type AccountEnabled struct {
	// Subject is the OP-internal subject. Required.
	Subject string
}

func (e AccountEnabled) securityEvent() (ssf.EventType, string, ssf.Fields, error) {
	return ssf.EventAccountEnabled, e.Subject, ssf.Fields{}, nil
}

// AccountPurged is the RISC account-purged event.
//
// Experimental: the RISC 1.0 event types are published as a draft, so
// the RISC surface MAY change in a minor release to track it.
type AccountPurged struct {
	// Subject is the OP-internal subject. Required.
	Subject string
}

func (e AccountPurged) securityEvent() (ssf.EventType, string, ssf.Fields, error) {
	return ssf.EventAccountPurged, e.Subject, ssf.Fields{}, nil
}

// CredentialCompromise is the RISC credential-compromise event.
//
// Experimental: the RISC 1.0 event types are published as a draft, so
// the RISC surface MAY change in a minor release to track it.
type CredentialCompromise struct {
	// Subject is the OP-internal subject. Required.
	Subject string

	// CredentialType is the kind of credential compromised. Required.
	CredentialType CredentialType
}

func (e CredentialCompromise) securityEvent() (ssf.EventType, string, ssf.Fields, error) {
	if !e.CredentialType.valid() {
		return "", "", ssf.Fields{}, errSecurityEvent("CredentialCompromise.CredentialType is not a CAEP credential type")
	}
	return ssf.EventCredentialCompromise, e.Subject, ssf.Fields{CredentialType: string(e.CredentialType)}, nil
}

func errSecurityEvent(description string) *Error {
	return newConfigurationError("EmitSecurityEvent: "+description, nil)
}

// EmitSecurityEvent queues ev as a Security Event Token for every SSF
// receiver whose client the subject holds a grant with and whose stream
// delivers the event type. The receivers are resolved from the grants,
// so call it BEFORE [Provider.RevokeSubject] or deleting the user: after
// either, the subject names no receiver and the event reaches nobody.
//
// Without [WithSharedSignals] the call is a silent no-op returning nil,
// so a deployment that forgot the option sees no error here. The event
// is still checked first: a nil event, an empty Subject, or a value
// outside its enumeration is a configuration_error [*Error] whether or
// not the transmitter is on.
//
// A store failure is a server_error [*Error]. Each receiver is attempted
// even when another fails, and every failure is also audited as
// ssf.enqueue_failed. Delivery itself is asynchronous.
//
// Stable since v1.5.
func (p *Provider) EmitSecurityEvent(ctx context.Context, ev SecurityEvent) error {
	if nilcheck.IsNil(ev) {
		return errSecurityEvent("event must not be nil")
	}
	et, subject, fields, err := ev.securityEvent()
	if err != nil {
		return err
	}
	if subject == "" {
		return errSecurityEvent("Subject must not be empty")
	}
	if p == nil || p.cfg == nil || p.cfg.ssfTransmitter == nil {
		return nil
	}
	if _, err := p.cfg.ssfTransmitter.Publish(ctx, et, subject, fields); err != nil {
		if errors.Is(err, ssf.ErrInvalidEvent) {
			return newConfigurationError("EmitSecurityEvent: event rejected", err)
		}
		return &Error{
			Code:        codeServerError,
			Description: "EmitSecurityEvent: store rejected the event",
			Cause:       err,
		}
	}
	return nil
}
