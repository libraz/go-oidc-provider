package sessions

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// EstablishMode names the idempotent Session operation encoded in an
// authorization completion intent.
type EstablishMode string

const (
	// EstablishReuse keeps the already-active same-subject Session.
	EstablishReuse EstablishMode = "reuse"

	// EstablishIssue creates a stable Session and chooser group.
	EstablishIssue EstablishMode = "issue"

	// EstablishRotate creates a stable replacement Session and removes
	// the previous Session ID.
	EstablishRotate EstablishMode = "rotate"

	// EstablishAddAccount creates a stable Session in an existing chooser
	// group and selects it.
	EstablishAddAccount EstablishMode = "add_account"

	// EstablishSwitch selects an existing Session without mutating it.
	EstablishSwitch EstablishMode = "switch"
)

// Establishment is the stable Session portion of an authorization
// completion intent. Record is required for every mode and contains the
// exact Session identity the retry must converge on.
type Establishment struct {
	Mode              EstablishMode
	Record            store.Session
	PreviousSessionID string
}

// EstablishPlan is the authorization endpoint's input for selecting a
// stable Session operation before it persists its completion intent.
type EstablishPlan struct {
	Active                   *Active
	Login                    Login
	FreshAuthn               bool
	StableSessionID          string
	StableChooserGroupID     string
	ChooserGroupID           string
	ChooserSelectedSessionID string
	ChooserAddAccount        bool
	ChooserAddAccountGroupID string
	Now                      time.Time
}

// PlanEstablishment resolves the existing chooser/session relationships
// and returns the exact stable record a resumable completion must persist.
// It performs no writes.
func (m *Manager) PlanEstablishment(ctx context.Context, in EstablishPlan) (Establishment, error) {
	now := in.Now.UTC()
	if in.Active != nil && in.Active.Session != nil && in.Active.Session.Subject == in.Login.Subject {
		return m.planSameSubjectEstablishment(in, now), nil
	}
	if in.ChooserGroupID != "" && in.ChooserSelectedSessionID != "" {
		return m.planSwitchEstablishment(ctx, in)
	}
	groupID := in.StableChooserGroupID
	mode := EstablishIssue
	if in.ChooserAddAccount && in.ChooserAddAccountGroupID != "" {
		groupID = in.ChooserAddAccountGroupID
		mode = EstablishAddAccount
	}
	if in.StableSessionID == "" || groupID == "" || in.Login.Subject == "" {
		return Establishment{}, errors.New("sessions: stable SessionID, ChooserGroupID, and Subject required")
	}
	record := store.Session{
		ID:             in.StableSessionID,
		Subject:        in.Login.Subject,
		AuthTime:       in.Login.AuthTime,
		AMR:            slices.Clone(in.Login.AMR),
		ACR:            in.Login.ACR,
		ChooserGroupID: groupID,
		ExpiresAt:      now.Add(m.idleTTL),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	return Establishment{Mode: mode, Record: record}, nil
}

func (m *Manager) planSameSubjectEstablishment(
	in EstablishPlan,
	now time.Time,
) Establishment {
	record := *cloneSession(in.Active.Session)
	if !in.FreshAuthn {
		return Establishment{Mode: EstablishReuse, Record: record}
	}
	record.ID = in.StableSessionID
	record.AuthTime = in.Login.AuthTime
	record.AMR = slices.Clone(in.Login.AMR)
	record.ACR = in.Login.ACR
	record.ExpiresAt = now.Add(m.idleTTL)
	record.CreatedAt = now
	record.UpdatedAt = now
	return Establishment{
		Mode:              EstablishRotate,
		Record:            record,
		PreviousSessionID: in.Active.Session.ID,
	}
}

func (m *Manager) planSwitchEstablishment(
	ctx context.Context,
	in EstablishPlan,
) (Establishment, error) {
	target, err := m.store.Find(ctx, in.ChooserSelectedSessionID)
	if err == nil && target == nil {
		// A nil record alongside a nil error violates the store contract.
		// The selected session cannot be shown to be live, so the plan takes
		// the same path a garbage-collected session takes.
		err = store.ErrNotFound
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Establishment{}, ErrCurrentSessionExpired
		}
		return Establishment{}, fmt.Errorf("sessions: find selected stable session: %w", err)
	}
	if target.ID != in.ChooserSelectedSessionID ||
		target.Subject != in.Login.Subject ||
		target.ChooserGroupID != in.ChooserGroupID {
		return Establishment{}, ErrCookieInvalid
	}
	return Establishment{Mode: EstablishSwitch, Record: *cloneSession(target)}, nil
}

// Establish applies in idempotent fashion. Repeating the same input either
// observes the exact existing Session or creates it once; a conflicting
// record under the stable ID is rejected. Rotate deletes the previous ID
// only after the replacement exists and absorbs ErrNotFound on retries.
func (m *Manager) Establish(ctx context.Context, in Establishment) (Outcome, error) {
	if err := validateEstablishment(in); err != nil {
		return Outcome{}, err
	}
	switch in.Mode {
	case EstablishReuse:
		return Outcome{
			ChooserGroupID: in.Record.ChooserGroupID,
			SessionID:      in.Record.ID,
		}, nil
	case EstablishSwitch:
		if err := m.validateStableSession(ctx, &in.Record); err != nil {
			return Outcome{}, err
		}
	case EstablishIssue, EstablishAddAccount, EstablishRotate:
		if err := m.ensureStableSession(ctx, &in.Record); err != nil {
			return Outcome{}, err
		}
		if in.Mode == EstablishRotate {
			if err := m.store.Delete(ctx, in.PreviousSessionID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return Outcome{}, fmt.Errorf("sessions: delete previous stable session: %w", err)
			}
		}
	default:
		return Outcome{}, errors.New("sessions: unsupported Establish mode")
	}
	value, err := m.codec.Encode(Payload{
		ChooserGroupID:   in.Record.ChooserGroupID,
		CurrentSessionID: in.Record.ID,
		IssuedAt:         in.Record.UpdatedAt.UTC().Unix(),
	})
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{
		Cookie:         value,
		ChooserGroupID: in.Record.ChooserGroupID,
		SessionID:      in.Record.ID,
	}, nil
}

func validateEstablishment(in Establishment) error {
	if in.Record.ID == "" || in.Record.ChooserGroupID == "" {
		return errors.New("sessions: Establish requires SessionID and ChooserGroupID")
	}
	switch in.Mode {
	case EstablishReuse, EstablishIssue, EstablishAddAccount, EstablishSwitch:
		return nil
	case EstablishRotate:
		if in.PreviousSessionID == "" || in.PreviousSessionID == in.Record.ID {
			return errors.New("sessions: Establish rotate requires a distinct previous SessionID")
		}
		return nil
	default:
		return errors.New("sessions: Establish requires a supported mode")
	}
}

func (m *Manager) ensureStableSession(ctx context.Context, expected *store.Session) error {
	err := m.validateStableSession(ctx, expected)
	if err == nil {
		return nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := m.store.Save(ctx, cloneSession(expected)); err != nil {
		if !errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("sessions: save stable session: %w", err)
		}
		return m.validateStableSession(ctx, expected)
	}
	return nil
}

func (m *Manager) validateStableSession(ctx context.Context, expected *store.Session) error {
	actual, err := m.store.Find(ctx, expected.ID)
	if err != nil {
		return err
	}
	if !sameStableSession(actual, expected) {
		return errors.New("sessions: stable SessionID collision")
	}
	return nil
}

func sameStableSession(a, b *store.Session) bool {
	if a == nil || b == nil {
		return false
	}
	return a.ID == b.ID &&
		a.Subject == b.Subject &&
		a.AuthTime.Equal(b.AuthTime) &&
		slices.Equal(a.AMR, b.AMR) &&
		a.ACR == b.ACR &&
		a.ChooserGroupID == b.ChooserGroupID &&
		a.ExpiresAt.Equal(b.ExpiresAt) &&
		a.CreatedAt.Equal(b.CreatedAt) &&
		a.UpdatedAt.Equal(b.UpdatedAt)
}

func cloneSession(in *store.Session) *store.Session {
	if in == nil {
		return nil
	}
	out := *in
	out.AMR = slices.Clone(in.AMR)
	return &out
}
