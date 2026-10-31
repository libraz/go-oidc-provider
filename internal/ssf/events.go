package ssf

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// EventType is the URI that keys a SET's single events member.
type EventType string

// Ordinary event types the transmitter emits.
const (
	// EventSessionRevoked is CAEP 1.0 §3.1 session-revoked.
	EventSessionRevoked EventType = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	// EventCredentialChange is CAEP 1.0 §3.3 credential-change.
	EventCredentialChange EventType = "https://schemas.openid.net/secevent/caep/event-type/credential-change" //nolint:gosec // G101: event type URI, not a credential.
	// EventAccountDisabled is RISC 1.0 account-disabled.
	EventAccountDisabled EventType = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	// EventAccountEnabled is RISC 1.0 account-enabled.
	EventAccountEnabled EventType = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
	// EventAccountPurged is RISC 1.0 account-purged.
	EventAccountPurged EventType = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	// EventCredentialCompromise is RISC 1.0 credential-compromise.
	EventCredentialCompromise EventType = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise" //nolint:gosec // G101: event type URI, not a credential.
)

// Control event types, built per stream and delivered whatever its status.
const (
	// EventStreamUpdated is SSF 1.0 §8.1.5 stream-updated.
	EventStreamUpdated EventType = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
	// EventVerification is SSF 1.0 §8.1.4 verification.
	EventVerification EventType = "https://schemas.openid.net/secevent/ssf/event-type/verification"
)

// supportedEvents is the ordinary-event set a stream may request, in the
// order the metadata and events_delivered list them.
func supportedEvents() []EventType {
	return []EventType{
		EventSessionRevoked,
		EventCredentialChange,
		EventAccountDisabled,
		EventAccountEnabled,
		EventAccountPurged,
		EventCredentialCompromise,
	}
}

// SupportedEvents returns the ordinary event type URIs a stream may
// request. Control events are not listed: every stream receives them.
func SupportedEvents() []string {
	events := supportedEvents()
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = string(e)
	}
	return out
}

// InitiatingEntityUser is the CAEP initiating_entity value for an
// end-user initiated action (the OP's own logout path).
const InitiatingEntityUser = "user"

// Default reason_admin texts (CAEP Interoperability Profile §3.1 / §3.2
// require a non-empty value).
const (
	defaultSessionRevokedReason   = "Session revoked by the identity provider"
	defaultCredentialChangeReason = "Credential changed at the identity provider" //nolint:gosec // G101: reason text, not a credential.
)

// ErrInvalidEvent reports an event type or field set the transmitter
// cannot turn into a SET payload.
var ErrInvalidEvent = errors.New("ssf: invalid event")

// Fields carries the per-event payload members of an ordinary event.
// Members that do not apply to the event type are ignored.
type Fields struct {
	// ReasonAdmin is the CAEP reason_admin (BCP 47 tag to text). Empty
	// substitutes a default English text.
	ReasonAdmin map[string]string

	// InitiatingEntity is the CAEP initiating_entity; omitted when empty.
	InitiatingEntity string

	// CredentialType is credential_type for credential-change and
	// credential-compromise, where it is required.
	CredentialType string

	// ChangeType is change_type for credential-change, where it is required.
	ChangeType string

	// FriendlyName is the optional credential-change friendly_name.
	FriendlyName string

	// Reason is the optional account-disabled reason.
	Reason string
}

// ControlFields carries the payload members of a control event.
type ControlFields struct {
	// Status is the stream status stream-updated announces. Required for
	// stream-updated.
	Status store.SSFStreamStatus

	// Reason is the optional stream-updated reason.
	Reason string

	// State is the optional verification state echoed to the receiver.
	State string
}

// isOrdinary reports whether t is an event [Transmitter.Publish] accepts.
func isOrdinary(t EventType) bool {
	return slices.Contains(supportedEvents(), t)
}

// eventPayload builds the members of an ordinary event's payload.
func eventPayload(t EventType, f Fields, now time.Time) (map[string]any, error) {
	p := map[string]any{}
	switch t {
	case EventSessionRevoked:
		addCAEPCommon(p, f, defaultSessionRevokedReason, now)
	case EventCredentialChange:
		if f.CredentialType == "" || f.ChangeType == "" {
			return nil, fmt.Errorf("%w: credential-change requires credential_type and change_type", ErrInvalidEvent)
		}
		addCAEPCommon(p, f, defaultCredentialChangeReason, now)
		p["credential_type"] = f.CredentialType
		p["change_type"] = f.ChangeType
		if f.FriendlyName != "" {
			p["friendly_name"] = f.FriendlyName
		}
	case EventAccountDisabled:
		if f.Reason != "" {
			p["reason"] = f.Reason
		}
	case EventAccountEnabled, EventAccountPurged:
	case EventCredentialCompromise:
		if f.CredentialType == "" {
			return nil, fmt.Errorf("%w: credential-compromise requires credential_type", ErrInvalidEvent)
		}
		p["credential_type"] = f.CredentialType
	default:
		return nil, fmt.Errorf("%w: %q is not an ordinary event type", ErrInvalidEvent, t)
	}
	return p, nil
}

// addCAEPCommon sets the CAEP 1.0 §2 common members.
func addCAEPCommon(p map[string]any, f Fields, defaultReason string, now time.Time) {
	p["event_timestamp"] = now.Unix()
	reason := maps.Clone(f.ReasonAdmin)
	if len(reason) == 0 {
		reason = map[string]string{"en": defaultReason}
	}
	p["reason_admin"] = reason
	if f.InitiatingEntity != "" {
		p["initiating_entity"] = f.InitiatingEntity
	}
}

// controlPayload builds the members of a control event's payload.
func controlPayload(t EventType, f ControlFields) (map[string]any, error) {
	p := map[string]any{}
	switch t {
	case EventStreamUpdated:
		if f.Status == "" {
			return nil, fmt.Errorf("%w: stream-updated requires status", ErrInvalidEvent)
		}
		p["status"] = string(f.Status)
		if f.Reason != "" {
			p["reason"] = f.Reason
		}
	case EventVerification:
		if f.State != "" {
			p["state"] = f.State
		}
	default:
		return nil, fmt.Errorf("%w: %q is not a control event type", ErrInvalidEvent, t)
	}
	return p, nil
}

// controlKind maps a control event type to its queue kind.
func controlKind(t EventType) store.SSFEventKind {
	if t == EventVerification {
		return store.SSFEventKindVerification
	}
	return store.SSFEventKindStreamUpdated
}
