package sessions

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// IDLength is the byte length of randomly-generated chooser_group_id and
// session_id values. 16 bytes (128 bits) is well above the birthday bound
// for the lifetime of a single OP deployment; the values are never reused.
const IDLength = 16

// IdleTTLDefault is the default idle lifetime applied to session records
// when no override is configured (§F.1: 14d for __Host-oidc_session).
const IdleTTLDefault = 14 * 24 * time.Hour

// ErrCurrentSessionExpired is returned by [Manager.Resolve] when the cookie
// successfully decrypts but the referenced session has expired or been
// deleted. The cookie should be cleared in the response.
var ErrCurrentSessionExpired = errors.New("sessions: current session expired")

// Manager orchestrates the SessionStore + cookie codec + clock. It owns the
// chooser-group lifecycle without exposing the raw [*store.Session] type to
// the HTTP layer.
//
// A Manager is immutable after construction and safe for concurrent use.
type Manager struct {
	codec   *Codec
	store   store.SessionStore
	clock   func() time.Time
	idleTTL time.Duration
}

// Config is the parameter bundle for [NewManager]. It exists to keep the
// function signature small and to allow zero-value defaults for IdleTTL.
type Config struct {
	// Codec is the session cookie codec; required.
	Codec *Codec

	// Store is the SessionStore backing the chooser group; required.
	Store store.SessionStore

	// Clock returns the current wall-clock time. Defaults to [time.Now]
	// when nil. Tests inject a deterministic clock here.
	Clock func() time.Time

	// IdleTTL is the absolute idle lifetime applied to every session
	// record on creation and refreshed on activity. Defaults to
	// [IdleTTLDefault] when zero.
	IdleTTL time.Duration
}

// NewManager constructs a [Manager] from cfg. It validates that the required
// dependencies are non-nil so a misconfiguration surfaces at startup rather
// than at the first request.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.Codec == nil {
		return nil, errors.New("sessions: NewManager requires Codec")
	}
	if cfg.Store == nil {
		return nil, errors.New("sessions: NewManager requires Store")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = timex.SystemClock.Now
	}
	idle := cfg.IdleTTL
	if idle == 0 {
		idle = IdleTTLDefault
	}
	return &Manager{
		codec:   cfg.Codec,
		store:   cfg.Store,
		clock:   clock,
		idleTTL: idle,
	}, nil
}

// Login is the input bundle for [Manager.Issue]. The fields mirror the
// [*store.Session] columns the OP populates from the authenticator output.
type Login struct {
	// Subject is the OP-internal stable identifier of the authenticated
	// user (not the federated provider's external ID).
	Subject string

	// AuthTime is the wall-clock time at which authentication completed.
	// Copied verbatim into the issued ID Token's auth_time claim.
	AuthTime time.Time

	// AMR lists the authenticator method references used (RFC 8176).
	AMR []string

	// ACR is the authentication context class reference, if any.
	ACR string
}

// Outcome is the result of an Issue / Switch operation: the freshly-minted
// cookie value, plus the underlying chooser_group_id / session_id so the
// caller can populate audit logs.
type Outcome struct {
	// Cookie is the encrypted, base64url-encoded value to place in the
	// __Host-oidc_session cookie.
	Cookie string

	// ChooserGroupID is the (possibly newly created) chooser group ID.
	ChooserGroupID string

	// SessionID is the freshly-issued or newly-active session ID.
	SessionID string
}

// Issue creates a brand-new chooser group and a session inside it for the
// supplied login. It is the operation invoked at the end of a "fresh login"
// interaction (no prior cookie or after [Manager.LogoutAll]).
//
// Callers that want to add an account to an existing group should use
// [Manager.AddAccount] instead.
func (m *Manager) Issue(ctx context.Context, login Login) (Outcome, error) {
	if login.Subject == "" {
		return Outcome{}, errors.New("sessions: Issue requires Subject")
	}
	now := m.clock().UTC()
	chooser, err := newID()
	if err != nil {
		return Outcome{}, err
	}
	sid, err := newID()
	if err != nil {
		return Outcome{}, err
	}
	sess := &store.Session{
		ID:             sid,
		Subject:        login.Subject,
		AuthTime:       login.AuthTime,
		AMR:            append([]string(nil), login.AMR...),
		ACR:            login.ACR,
		ChooserGroupID: chooser,
		ExpiresAt:      now.Add(m.idleTTL),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := m.store.Save(ctx, sess); err != nil {
		return Outcome{}, fmt.Errorf("sessions: save: %w", err)
	}
	value, err := m.codec.Encode(Payload{
		ChooserGroupID:   chooser,
		CurrentSessionID: sid,
		IssuedAt:         now.Unix(),
	})
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Cookie: value, ChooserGroupID: chooser, SessionID: sid}, nil
}

// Active is the resolved view of a session cookie: the validated payload
// plus the live session record fetched from the store.
type Active struct {
	// Payload is the decoded cookie content.
	Payload Payload

	// Session is the SessionStore record for Payload.CurrentSessionID.
	// Always non-nil when [Manager.Resolve] returns nil.
	Session *store.Session
}

// Resolve reads the supplied cookie value, decrypts it, and returns the
// matching live session record. It performs every safety check required by
// §A.9: cookie integrity (via the codec), session existence (via the
// store), idle expiry (via Session.ExpiresAt), and chooser-group cross-
// reference (Session.ChooserGroupID must match the cookie).
//
// The error path distinguishes between "cookie invalid" (treat as logged
// out, do not clear) and "current session expired" (clear cookie). All
// other failures are wrapped store errors.
func (m *Manager) Resolve(ctx context.Context, cookieValue string) (*Active, error) {
	payload, err := m.codec.Decode(cookieValue)
	if err != nil {
		return nil, err
	}
	sess, err := m.store.Find(ctx, payload.CurrentSessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrCurrentSessionExpired
		}
		return nil, fmt.Errorf("sessions: find: %w", err)
	}
	if sess.ChooserGroupID != payload.ChooserGroupID {
		// Cookie references a session that was reassigned to another
		// chooser group — treat as tampered.
		return nil, ErrCookieInvalid
	}
	return &Active{Payload: payload, Session: sess}, nil
}

// Touch refreshes the active session's idle timer to now + idleTTL. It is
// a no-op when [Manager.Resolve] has already failed; callers should only
// invoke Touch after a successful Resolve.
func (m *Manager) Touch(ctx context.Context, sessionID string) error {
	now := m.clock().UTC()
	if err := m.store.Touch(ctx, sessionID, now.Add(m.idleTTL), now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrCurrentSessionExpired
		}
		return fmt.Errorf("sessions: touch: %w", err)
	}
	return nil
}

// Logout deletes the supplied session. It does not clear other accounts in
// the same chooser group; that is [Manager.LogoutAll]'s job.
//
// The function is idempotent: deleting an already-removed session returns
// nil so a double-click on "log out" does not produce a 5xx.
func (m *Manager) Logout(ctx context.Context, sessionID string) error {
	err := m.store.Delete(ctx, sessionID)
	if err == nil || errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("sessions: delete: %w", err)
}

// AddAccount adds a new authenticated account to an existing chooser group
// and switches the cookie to point at it. It is the operation invoked when
// the user clicks "sign in to another account" on the chooser screen
// (002-product-design §A.9).
//
// chooserGroupID identifies the existing group to add to; the caller MUST
// have previously confirmed the cookie's group via [Manager.Resolve] so
// that an attacker cannot graft a session into someone else's group.
func (m *Manager) AddAccount(ctx context.Context, chooserGroupID string, login Login) (Outcome, error) {
	if chooserGroupID == "" {
		return Outcome{}, errors.New("sessions: AddAccount requires ChooserGroupID")
	}
	if login.Subject == "" {
		return Outcome{}, errors.New("sessions: AddAccount requires Subject")
	}
	now := m.clock().UTC()
	sid, err := newID()
	if err != nil {
		return Outcome{}, err
	}
	sess := &store.Session{
		ID:             sid,
		Subject:        login.Subject,
		AuthTime:       login.AuthTime,
		AMR:            append([]string(nil), login.AMR...),
		ACR:            login.ACR,
		ChooserGroupID: chooserGroupID,
		ExpiresAt:      now.Add(m.idleTTL),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := m.store.Save(ctx, sess); err != nil {
		return Outcome{}, fmt.Errorf("sessions: save: %w", err)
	}
	value, err := m.codec.Encode(Payload{
		ChooserGroupID:   chooserGroupID,
		CurrentSessionID: sid,
		IssuedAt:         now.Unix(),
	})
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Cookie: value, ChooserGroupID: chooserGroupID, SessionID: sid}, nil
}

// Switch rebinds the cookie's "current session" to a different account
// already present in the chooser group. It returns an updated cookie value
// without touching the underlying session record (no Touch — Switch is a
// pure UX selection, not authentication activity).
//
// The function fails with [ErrCurrentSessionExpired] when targetSessionID
// either does not exist or has been garbage-collected; the caller should
// clear the cookie or re-render the chooser. It fails with
// [ErrCookieInvalid] when targetSessionID belongs to a different chooser
// group than chooserGroupID — the caller MUST treat this as tampering.
func (m *Manager) Switch(ctx context.Context, chooserGroupID, targetSessionID string) (Outcome, error) {
	if chooserGroupID == "" || targetSessionID == "" {
		return Outcome{}, errors.New("sessions: Switch requires ChooserGroupID and SessionID")
	}
	sess, err := m.store.Find(ctx, targetSessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Outcome{}, ErrCurrentSessionExpired
		}
		return Outcome{}, fmt.Errorf("sessions: find: %w", err)
	}
	if sess.ChooserGroupID != chooserGroupID {
		return Outcome{}, ErrCookieInvalid
	}
	now := m.clock().UTC()
	value, err := m.codec.Encode(Payload{
		ChooserGroupID:   chooserGroupID,
		CurrentSessionID: targetSessionID,
		IssuedAt:         now.Unix(),
	})
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Cookie: value, ChooserGroupID: chooserGroupID, SessionID: targetSessionID}, nil
}

// Account is a projection of [store.Session] suitable for rendering the
// account chooser. It deliberately omits internal-only fields like
// ChooserGroupID and ExpiresAt so the UI never accidentally leaks them.
type Account struct {
	// SessionID is the value the chooser passes back to [Manager.Switch]
	// or [Manager.Remove].
	SessionID string

	// Subject is the OP-internal stable identifier of the user; the UI
	// resolves this to a display name via the caller's user lookup.
	Subject string

	// AuthTime is the wall-clock time at which this session authenticated.
	AuthTime time.Time

	// UpdatedAt is the wall-clock time of the most recent activity. The
	// chooser uses this to sort accounts "most recent first".
	UpdatedAt time.Time
}

// Accounts returns every live account in the chooser group, in unspecified
// order. Callers that render the chooser sort by UpdatedAt descending so
// the most recently active account appears first.
func (m *Manager) Accounts(ctx context.Context, chooserGroupID string) ([]Account, error) {
	if chooserGroupID == "" {
		return nil, errors.New("sessions: Accounts requires ChooserGroupID")
	}
	sessions, err := m.store.ListByChooserGroup(ctx, chooserGroupID)
	if err != nil {
		return nil, fmt.Errorf("sessions: list: %w", err)
	}
	out := make([]Account, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, Account{
			SessionID: s.ID,
			Subject:   s.Subject,
			AuthTime:  s.AuthTime,
			UpdatedAt: s.UpdatedAt,
		})
	}
	return out, nil
}

// Removal describes the post-Remove cookie state. When Remaining is empty
// the chooser group has been fully torn down and the caller MUST clear the
// session cookie. When Cookie is non-empty the cookie's "current session"
// has been rebound to a different account — the caller MUST set the
// returned value as the new cookie payload.
type Removal struct {
	// Cookie is the new cookie value when the removed session was the
	// current account; empty when no rebind was needed.
	Cookie string

	// CurrentSessionID is the new "current" account; empty when the
	// chooser group has been fully torn down.
	CurrentSessionID string

	// Remaining is the set of session IDs still in the chooser group
	// after the removal.
	Remaining []string
}

// Remove deletes a single account from the chooser group. When the removed
// session was the cookie's "current" account, Remove rebinds current to the
// most recently active remaining account (sorted by UpdatedAt descending);
// when the group becomes empty the caller MUST clear the cookie.
//
// removeID need not be live — Remove is idempotent for already-deleted
// sessions, mirroring [Manager.Logout].
func (m *Manager) Remove(ctx context.Context, chooserGroupID, currentSessionID, removeID string) (Removal, error) {
	if chooserGroupID == "" || removeID == "" {
		return Removal{}, errors.New("sessions: Remove requires ChooserGroupID and removeID")
	}
	if err := m.store.Delete(ctx, removeID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return Removal{}, fmt.Errorf("sessions: delete: %w", err)
	}
	remaining, err := m.store.ListByChooserGroup(ctx, chooserGroupID)
	if err != nil {
		return Removal{}, fmt.Errorf("sessions: list: %w", err)
	}
	out := Removal{Remaining: remainingIDs(remaining)}
	if removeID != currentSessionID || len(remaining) == 0 {
		// Either the removed account was not current (no cookie rebind
		// needed) or the chooser is empty (caller clears cookie).
		return out, nil
	}
	next := mostRecent(remaining)
	now := m.clock().UTC()
	value, err := m.codec.Encode(Payload{
		ChooserGroupID:   chooserGroupID,
		CurrentSessionID: next.ID,
		IssuedAt:         now.Unix(),
	})
	if err != nil {
		return Removal{}, err
	}
	out.Cookie = value
	out.CurrentSessionID = next.ID
	return out, nil
}

// LogoutAll deletes every session in the chooser group. The caller MUST
// clear the session cookie after a successful return. The function is
// idempotent: an empty chooser group succeeds silently so a double-click on
// "log out everywhere" does not produce a 5xx.
func (m *Manager) LogoutAll(ctx context.Context, chooserGroupID string) error {
	if chooserGroupID == "" {
		return errors.New("sessions: LogoutAll requires ChooserGroupID")
	}
	sessions, err := m.store.ListByChooserGroup(ctx, chooserGroupID)
	if err != nil {
		return fmt.Errorf("sessions: list: %w", err)
	}
	for _, s := range sessions {
		if err := m.store.Delete(ctx, s.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("sessions: delete %s: %w", s.ID, err)
		}
	}
	return nil
}

func remainingIDs(sessions []*store.Session) []string {
	out := make([]string, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, s.ID)
	}
	return out
}

// mostRecent returns the session with the latest UpdatedAt. The caller has
// already filtered out empty slices.
func mostRecent(sessions []*store.Session) *store.Session {
	best := sessions[0]
	for _, s := range sessions[1:] {
		if s.UpdatedAt.After(best.UpdatedAt) {
			best = s
		}
	}
	return best
}

// newID generates a base64url-encoded random identifier of [IDLength]
// bytes, suitable for chooser_group_id / session_id values.
func newID() (string, error) {
	buf := make([]byte, IDLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("sessions: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
