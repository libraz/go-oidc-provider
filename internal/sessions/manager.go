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
// when no override is configured (14 days for the __Host-oidc_session
// cookie). The canonical value lives in [timex.SessionIdleTTLDefault];
// this name is preserved so internal callers and tests retain the
// session-domain-specific spelling.
//
//nolint:gochecknoglobals // re-export of the canonical timex value; var is required for cross-package alias.
var IdleTTLDefault = timex.SessionIdleTTLDefault

// ErrCurrentSessionExpired is returned by [Manager.Resolve] when the cookie
// successfully decrypts but the referenced session has expired or been
// deleted. The cookie should be cleared in the response.
var ErrCurrentSessionExpired = errors.New("sessions: current session expired")

// AbsoluteTTLDefault is the default cap on a session's total wall-clock
// lifetime. Idle activity refreshes ExpiresAt up to this bound; once
// CreatedAt + AbsoluteTTLDefault is in the past the session is considered
// expired and the next [Manager.Touch] tears it down. The canonical
// value lives in [timex.SessionAbsoluteTTLDefault]; this name is
// preserved so internal callers and tests retain the
// session-domain-specific spelling.
//
//nolint:gochecknoglobals // re-export of the canonical timex value; var is required for cross-package alias.
var AbsoluteTTLDefault = timex.SessionAbsoluteTTLDefault

// Manager orchestrates the SessionStore + cookie codec + clock. It owns the
// chooser-group lifecycle without exposing the raw [*store.Session] type to
// the HTTP layer.
//
// A Manager is immutable after construction and safe for concurrent use.
type Manager struct {
	codec       *Codec
	store       store.SessionStore
	clock       func() time.Time
	idleTTL     time.Duration
	absoluteTTL time.Duration
}

// Config is the parameter bundle for [NewManager]. It exists to keep the
// function signature small and to allow zero-value defaults for IdleTTL.
type Config struct {
	// Codec is the session cookie codec; required.
	Codec *Codec

	// Store is the SessionStore backing the chooser group; required.
	Store store.SessionStore

	// Clock returns the current wall-clock time. Defaults to [time.Now()]
	// when nil. Tests inject a deterministic clock here.
	Clock func() time.Time

	// IdleTTL is the absolute idle lifetime applied to every session
	// record on creation and refreshed on activity. Defaults to
	// [IdleTTLDefault] when zero.
	IdleTTL time.Duration

	// AbsoluteTTL caps the total lifetime of a session regardless of
	// idle refreshes. A zero value substitutes [AbsoluteTTLDefault]; a
	// negative value disables the cap entirely (legacy behaviour). Once
	// CreatedAt + AbsoluteTTL is in the past, [Manager.Touch] returns
	// [ErrCurrentSessionExpired] and deletes the underlying record so a
	// hijacked cookie cannot be kept alive indefinitely by a busy client.
	AbsoluteTTL time.Duration
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
	abs := cfg.AbsoluteTTL
	switch {
	case abs == 0:
		abs = AbsoluteTTLDefault
	case abs < 0:
		// Caller explicitly disabled the cap.
		abs = 0
	}
	return &Manager{
		codec:       cfg.Codec,
		store:       cfg.Store,
		clock:       clock,
		idleTTL:     idle,
		absoluteTTL: abs,
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
// matching live session record. It performs every safety check the cookie
// contract requires: cookie integrity (via the codec), session existence (via the
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
	sess, err := m.findSession(ctx, payload.CurrentSessionID)
	if err != nil {
		return nil, err
	}
	if sess.ChooserGroupID != payload.ChooserGroupID {
		// Cookie references a session that was reassigned to another
		// chooser group — treat as tampered.
		return nil, ErrCookieInvalid
	}
	if sessionExpired(sess.ExpiresAt, m.clock().UTC()) {
		return nil, ErrCurrentSessionExpired
	}
	return &Active{Payload: payload, Session: sess}, nil
}

func sessionExpired(expiresAt, now time.Time) bool {
	return !expiresAt.IsZero() && expiresAt.UTC().Before(now.UTC())
}

// findSession reads one session record and normalises the lookup outcome the
// manager's read paths share: a missing row becomes
// [ErrCurrentSessionExpired] so the caller clears the cookie, and any other
// backend failure is wrapped.
//
// A nil record returned alongside a nil error violates the store contract. It
// is folded into the same expired signal rather than dereferenced: a backend
// that cannot produce the record has not proven the cookie still names a live
// session, and the caller's existing branch already handles that.
func (m *Manager) findSession(ctx context.Context, id string) (*store.Session, error) {
	sess, err := m.store.Find(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrCurrentSessionExpired
		}
		return nil, fmt.Errorf("sessions: find: %w", err)
	}
	if sess == nil {
		return nil, ErrCurrentSessionExpired
	}
	return sess, nil
}

// Touch refreshes the active session's idle timer to now + idleTTL. It is
// a no-op when [Manager.Resolve] has already failed; callers should only
// invoke Touch after a successful Resolve.
//
// When an absolute TTL is configured and the session's CreatedAt is older
// than the cap, Touch deletes the record and returns [ErrCurrentSessionExpired]
// so the caller clears the cookie. The deletion is best-effort: a delete
// failure is wrapped and returned but the absolute-expiry signal still wins
// — a backend hiccup must not silently keep an over-aged session alive.
func (m *Manager) Touch(ctx context.Context, sessionID string) error {
	now := m.clock().UTC()
	if m.absoluteTTL > 0 {
		sess, err := m.findSession(ctx, sessionID)
		if err != nil {
			return err
		}
		if now.Sub(sess.CreatedAt) > m.absoluteTTL {
			// Best-effort delete: ignore not-found, surface only real errors.
			if derr := m.store.Delete(ctx, sessionID); derr != nil && !errors.Is(derr, store.ErrNotFound) {
				return fmt.Errorf("sessions: delete absolute-expired: %w", derr)
			}
			return ErrCurrentSessionExpired
		}
	}
	if err := m.store.Touch(ctx, sessionID, now.Add(m.idleTTL), now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrCurrentSessionExpired
		}
		return fmt.Errorf("sessions: touch: %w", err)
	}
	return nil
}

// Rotate reissues a fresh session ID for the record currently keyed by
// oldSessionID, returning a new cookie value bound to the same chooser
// group / subject / auth metadata. It is the session-fixation defence for
// re-authentication: the caller invokes Rotate immediately after the user
// proves identity again so any pre-fixation cookie value the attacker may
// have planted becomes useless.
//
// Atomicity: the rotation is implemented as Save(new) + Delete(old)
// without a dedicated store contract, so any [store.SessionStore]
// implementation works. The pair is NOT atomic — between Save(new) and
// Delete(old) two records reference the same Subject / ChooserGroupID,
// and embedders MUST tolerate that transient dual-active window
// (documented on [store.SessionStore]). A concurrent Rotate on the same
// oldSessionID either succeeds with distinct new IDs (both records exist
// briefly until the old is deleted by whichever racer reaches Delete
// first; subsequent Deletes surface [store.ErrNotFound] and are absorbed)
// or fails with a wrapped store error; the function never silently
// produces two cookies pointing at the same SessionID.
//
// On store.ErrNotFound for the lookup the function returns
// [ErrCurrentSessionExpired] so the caller clears the cookie. A delete
// failure on the old record after a successful Save is wrapped: the new
// cookie is already valid, but the operator should investigate the leak.
func (m *Manager) Rotate(ctx context.Context, oldSessionID string) (Outcome, error) {
	if oldSessionID == "" {
		return Outcome{}, errors.New("sessions: Rotate requires oldSessionID")
	}
	sess, err := m.findSession(ctx, oldSessionID)
	if err != nil {
		return Outcome{}, err
	}
	now := m.clock().UTC()
	newID, err := newID()
	if err != nil {
		return Outcome{}, err
	}
	rotated := &store.Session{
		ID:             newID,
		Subject:        sess.Subject,
		AuthTime:       sess.AuthTime,
		AMR:            append([]string(nil), sess.AMR...),
		ACR:            sess.ACR,
		ChooserGroupID: sess.ChooserGroupID,
		ExpiresAt:      now.Add(m.idleTTL),
		// Preserve the original CreatedAt so the absolute-TTL clock is
		// not reset by a rotation: an attacker who steals a cookie does
		// not gain extra lifetime by triggering a rotation.
		CreatedAt: sess.CreatedAt,
		UpdatedAt: now,
	}
	if err := m.store.Save(ctx, rotated); err != nil {
		return Outcome{}, fmt.Errorf("sessions: save rotated: %w", err)
	}
	if err := m.store.Delete(ctx, oldSessionID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return Outcome{}, fmt.Errorf("sessions: delete old: %w", err)
	}
	value, err := m.codec.Encode(Payload{
		ChooserGroupID:   sess.ChooserGroupID,
		CurrentSessionID: newID,
		IssuedAt:         now.Unix(),
	})
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Cookie: value, ChooserGroupID: sess.ChooserGroupID, SessionID: newID}, nil
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
// the user clicks "sign in to another account" on the chooser screen.
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
	sess, err := m.findSession(ctx, targetSessionID)
	if err != nil {
		return Outcome{}, err
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

// SessionAuthContext is the authentication context a single session
// recorded at login: the acr / amr / auth_time carried on the session
// record. It is separate from [Account] because acr / amr are
// server-side assurance values the chooser UI must never render, whereas
// [Account] is UI-facing.
type SessionAuthContext struct {
	// Subject is the selected session's authenticated subject.
	Subject string

	// ACR is the session's recorded Authentication Context Class
	// Reference (empty when none was asserted).
	ACR string

	// AMR is a defensive copy of the session's Authentication Methods
	// References (RFC 8176), in recorded order.
	AMR []string

	// AuthTime is the wall-clock time the session authenticated.
	AuthTime time.Time
}

// AuthContext returns the authentication context of the session
// identified by sessionID, validated to belong to chooserGroupID. It
// mirrors [Manager.Switch]'s membership check but reads only the
// auth-context fields instead of rebinding the cookie, so the account
// chooser rebind path can seed a fresh grant / id_token with the chosen
// session's assurance rather than silently downgrading it. A session
// outside the group yields [ErrCookieInvalid]; a garbage-collected
// session yields [ErrCurrentSessionExpired].
func (m *Manager) AuthContext(ctx context.Context, chooserGroupID, sessionID string) (SessionAuthContext, error) {
	if chooserGroupID == "" || sessionID == "" {
		return SessionAuthContext{}, errors.New("sessions: AuthContext requires ChooserGroupID and SessionID")
	}
	sess, err := m.findSession(ctx, sessionID)
	if err != nil {
		return SessionAuthContext{}, err
	}
	if sess.ID != sessionID || sess.ChooserGroupID != chooserGroupID {
		return SessionAuthContext{}, ErrCookieInvalid
	}
	return SessionAuthContext{
		Subject:  sess.Subject,
		ACR:      sess.ACR,
		AMR:      append([]string(nil), sess.AMR...),
		AuthTime: sess.AuthTime,
	}, nil
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
// bytes, suitable for chooser_group_id / session_id values. A
// [crypto/rand] read failure propagates to the caller so the
// in-flight transaction fails closed rather than admitting a
// predictable identifier; see the entropy-failure policy on
// internal/keys for the central
// rule.
func newID() (string, error) {
	buf := make([]byte, IDLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("sessions: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
