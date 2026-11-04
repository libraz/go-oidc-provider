package password

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/libraz/go-oidc-provider/internal/argon2id"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	opauthn "github.com/libraz/go-oidc-provider/op/authn"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// PromptType is the [interaction.Prompt.Type] the adapter emits, fixed
// to mirror the existing "auth.password" wire shape that the SSR
// HTMLDriver already renders.
const PromptType = "auth.password"

// Field names in the SPA submission. Exported so SPA documentation
// references the canonical wire keys without a stringly-typed copy.
const (
	UsernameFieldName = "username"
	PasswordFieldName = "password"
)

// Length bounds the adapter applies to the prompt fields. The library
// is opinionated only on upper bounds (denial-of-service guard) and
// non-emptiness; password-policy minimums (8, 12, 14 chars …) are an
// embedder concern that the SPA enforces before submission.
const (
	usernameMinLen = 1
	usernameMaxLen = 254
	passwordMinLen = 1
	passwordMaxLen = 1024
)

// ErrInvalidCredentials is the single sentinel the adapter returns
// for every failed-login branch — username unknown, hash missing,
// hash unparseable, candidate mismatch. Collapsing all four onto one
// error is intentional: distinguishing them in the response lets an
// attacker enumerate which usernames exist or which accounts have a
// password set. The error wraps [authn.ErrFactorRetry] so the
// orchestrator observes the failure and re-emits the password
// prompt rather than terminating the chain with a 500.
var ErrInvalidCredentials = fmt.Errorf("password: invalid credentials: %w", authn.ErrFactorRetry)

// ErrFieldMissing is returned by [Authenticator.Continue] when the
// submission omits the username or password field. The orchestrator's
// [interaction.FieldSpec] validation should already have caught this;
// the adapter re-checks at the trust boundary.
var ErrFieldMissing = fmt.Errorf("password: required field is missing: %w", authn.ErrFactorAbort)

// Authenticator is the [authn.Authenticator] adapter for the built-in
// PrimaryPassword Step. It wraps a [store.UserPasswordStore] and
// drives the verify ceremony: prompt for username + password, look
// up the user, fetch the stored Argon2id hash, verify in
// constant time.
//
// Construct through [NewAuthenticator]; the zero value is not usable.
type Authenticator struct {
	store           store.UserPasswordStore
	lockout         *lockout.Counter
	legacy          []LegacyScheme
	updater         store.UserPasswordHashUpdater
	logger          *slog.Logger
	unsupportedOnce *sync.Once

	// unrecognizedOnce limits the unrecognized-hash warning to one per
	// process-lifetime Authenticator; copies made by the With* methods share it.
	unrecognizedOnce *sync.Once
}

// LegacyScheme verifies password hashes that are not argon2id PHC
// strings; the declaration is
// [github.com/libraz/go-oidc-provider/op/authn.PasswordHashScheme].
type LegacyScheme = opauthn.PasswordHashScheme

// Config carries the optional legacy-hash settings applied by
// [Authenticator.WithConfig].
type Config struct {
	// LegacySchemes are consulted in order for a stored hash that is not
	// an argon2id PHC string.
	LegacySchemes []LegacyScheme
	// HashUpdater, when non-nil, receives the argon2id re-encoding after a
	// successful legacy verify.
	HashUpdater store.UserPasswordHashUpdater
	// Logger receives rehash diagnostics; nil falls back to slog.Default.
	Logger *slog.Logger
}

// WithConfig returns a copy of a that accepts cfg.LegacySchemes and
// rehashes through cfg.HashUpdater. The receiver is not mutated; the
// caller MUST use the returned pointer.
func (a *Authenticator) WithConfig(cfg Config) *Authenticator {
	cp := *a
	cp.legacy = cfg.LegacySchemes
	cp.updater = cfg.HashUpdater
	cp.logger = cfg.Logger
	cp.unsupportedOnce = &sync.Once{}
	cp.unrecognizedOnce = &sync.Once{}
	return &cp
}

// WithLockout returns a copy of a that records wrong passwords on the
// supplied cross-factor [lockout.Counter] and refuses a locked subject
// even when the password is correct. A nil counter disables the gate.
// A successful login does not reset the counter, so a known password
// cannot refill the budget a second factor shares. The receiver is not
// mutated; the caller MUST use the returned pointer.
func (a *Authenticator) WithLockout(c *lockout.Counter) *Authenticator {
	cp := *a
	cp.lockout = c
	return &cp
}

// ErrStoreRequired is returned by [NewAuthenticator] when its store
// argument is nil. Surfacing the configuration error at construction
// is preferred to a runtime panic on the first Begin.
var ErrStoreRequired = errors.New("password: store is required")

// NewAuthenticator constructs an [Authenticator]. The store argument
// is required; the function returns an error rather than panicking
// on a nil dependency so callers can surface the misconfiguration
// through their normal startup error path.
func NewAuthenticator(s store.UserPasswordStore) (*Authenticator, error) {
	if s == nil {
		return nil, ErrStoreRequired
	}
	return &Authenticator{store: s, unsupportedOnce: &sync.Once{}, unrecognizedOnce: &sync.Once{}}, nil
}

// Type implements [authn.Authenticator]. Always returns
// [authn.FactorPassword].
func (*Authenticator) Type() authn.FactorType { return authn.FactorPassword }

// AAL implements [authn.Authenticator]. Password is a single-factor
// knowledge credential and reports [authn.AAL1]; step-up to AAL2
// happens through a follow-on factor (TOTP, passkey).
func (*Authenticator) AAL() authn.AAL { return authn.AAL1 }

// AMR implements [authn.Authenticator]. Password maps to RFC 8176 §2
// "pwd".
func (*Authenticator) AMR() string { return "pwd" }

// Prompts implements [authn.Authenticator]. The adapter emits a single
// prompt type; the slice is read-only by contract.
func (*Authenticator) Prompts() []string { return []string{PromptType} }

// Begin implements [authn.Authenticator]. It emits the password
// prompt with username + password fields. Begin does not touch the
// store: the look-up runs in Continue once the SPA submits values,
// so a misconfigured store surfaces only on a real attempt rather
// than at every interaction creation.
func (*Authenticator) Begin(_ context.Context, _ authn.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: passwordPrompt()}, nil
}

// Continue implements [authn.Authenticator]. It extracts the username
// and password, runs the lookup chain, and verifies the hash in
// constant time relative to the lookup result so user enumeration
// cannot proceed via timing.
//
// On match the returned [interaction.Result] carries the resolved
// subject and the orchestrator's [authn.ContinueInput.AuthTime].
// Every non-match path collapses onto [ErrInvalidCredentials] so the
// SPA renders one prompt regardless of which sub-step failed.
func (a *Authenticator) Continue(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	username, candidate, err := extractCredentials(in.Submission)
	if err != nil {
		return interaction.Step{}, err
	}
	subject, err := a.resolveAndVerify(ctx, username, candidate)
	if err != nil {
		return interaction.Step{}, err
	}
	return interaction.Step{Result: &interaction.Result{
		Subject:  subject,
		AuthTime: in.AuthTime,
	}}, nil
}

// extractCredentials reads the SPA submission and returns the
// username + password values, or [ErrFieldMissing] when either is
// absent or empty. The orchestrator's [interaction.FieldSpec]
// validation should already have caught this; the helper re-checks
// at the trust boundary.
func extractCredentials(s interaction.FormSubmission) (username, candidate string, err error) {
	u, ok := s.Values[UsernameFieldName]
	if !ok || u == "" {
		return "", "", ErrFieldMissing
	}
	c, ok := s.Values[PasswordFieldName]
	if !ok || c == "" {
		return "", "", ErrFieldMissing
	}
	return u, c, nil
}

// resolveAndVerify runs the username -> subject -> hash lookup chain
// and verifies candidate against the resolved hash in constant time
// relative to the lookup outcome. Backend faults that are not
// "missing record" are surfaced verbatim so the orchestrator can stop
// the chain rather than silently rolling to the next factor on
// transient infrastructure failure. Every other failure mode collapses
// onto [ErrInvalidCredentials] for enumeration safety.
func (a *Authenticator) resolveAndVerify(ctx context.Context, username, candidate string) (string, error) {
	user, hash, err := a.lookupCredential(ctx, username)
	if err != nil {
		return "", err
	}
	usable := user != nil && len(hash) > 0

	// Only a subject that has a password consults or feeds the shared
	// counter, so password spray cannot spend the budget of an account
	// that has no password to guess.
	counted := usable && a.lockout != nil
	locked, err := a.lockedSubject(ctx, counted, user)
	if err != nil {
		return "", err
	}

	outcome, err := a.verifyCandidate(ctx, hash, candidate, usable && !locked)
	if err != nil {
		return "", err
	}
	scheme, verifyErr := outcome.scheme, outcome.err

	if !usable || locked {
		return "", ErrInvalidCredentials
	}
	if verifyErr != nil {
		if counted && errors.Is(verifyErr, ErrPasswordMismatch) {
			return "", a.recordMismatch(ctx, user.Subject)
		}
		return "", ErrInvalidCredentials
	}
	if scheme != nil {
		a.rehash(ctx, user.Subject, candidate)
	}
	return user.Subject, nil
}

// verifyCandidate checks candidate against hash, or against the dummy
// hash when the stored one must not be consulted. Every path costs one
// Argon2id derivation or one legacy verify, so the outcome of the lookup
// does not show in the timing; the dummy hash is parameter-compatible
// with library-emitted hashes. The returned error is a backend fault from
// a legacy scheme.
func (a *Authenticator) verifyCandidate(ctx context.Context, hash []byte, candidate string, consult bool) (verifyOutcome, error) {
	var scheme LegacyScheme
	if consult {
		scheme = a.legacySchemeFor(hash)
	}
	if scheme == nil && consult {
		a.warnUnrecognized(ctx, hash)
	}
	if scheme != nil {
		ok, err := scheme.Verify(ctx, hash, candidate)
		if err != nil {
			return verifyOutcome{}, fmt.Errorf("password: legacy verify: %w", err)
		}
		if !ok {
			return verifyOutcome{scheme: scheme, err: ErrPasswordMismatch}, nil
		}
		return verifyOutcome{scheme: scheme}, nil
	}
	if !consult {
		hash = dummyHash()
	}
	verifyErr := Verify(hash, candidate)
	if errors.Is(verifyErr, ErrInvalidHash) {
		// An unparsable or out-of-policy stored hash is refused before any
		// derivation runs; pay the dummy one so the refusal costs the same.
		_ = Verify(dummyHash(), candidate)
	}
	return verifyOutcome{err: verifyErr}, nil
}

// argon2idPrefix opens every argon2id PHC string.
const argon2idPrefix = "$argon2id$"

// verifyOutcome is a candidate check's result: the legacy scheme that
// verified (nil on the argon2id path) and the mismatch or invalid-hash
// error, if any.
type verifyOutcome struct {
	scheme LegacyScheme
	err    error
}

// legacySchemeFor returns the first configured scheme that recognizes
// hash, or nil when hash is an argon2id PHC or no scheme claims it.
func (a *Authenticator) legacySchemeFor(hash []byte) LegacyScheme { //nolint:ireturn // the scheme is the embedder-supplied interface value.
	if bytes.HasPrefix(hash, []byte(argon2idPrefix)) {
		return nil
	}
	for _, s := range a.legacy {
		if s.Recognizes(hash) {
			return s
		}
	}
	return nil
}

// warnUnrecognized logs once that a stored hash is neither argon2id nor
// claimed by a configured scheme. It names neither the user nor the hash.
func (a *Authenticator) warnUnrecognized(ctx context.Context, hash []byte) {
	if bytes.HasPrefix(hash, []byte(argon2idPrefix)) {
		return
	}
	a.unrecognizedOnce.Do(func() {
		logger := a.logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.WarnContext(ctx, "password: a stored password hash is not argon2id and no configured legacy scheme recognizes it; "+
			"logins with such hashes fail. Set PrimaryPassword.LegacySchemes (for example op.BcryptHashScheme()) to verify and migrate them")
	})
}

// rehash upgrades a verified legacy password to argon2id. A failure never
// fails the login; the next successful login retries.
func (a *Authenticator) rehash(ctx context.Context, subject, candidate string) {
	if a.updater == nil {
		return
	}
	enc, err := (&clientauth.Argon2id{}).Hash(candidate)
	if err == nil {
		err = a.updater.UpdatePasswordHash(ctx, subject, []byte(enc))
	}
	if err == nil {
		return
	}
	logger := a.logger
	if logger == nil {
		logger = slog.Default()
	}
	if errors.Is(err, store.ErrPasswordHashUpdateUnsupported) {
		a.unsupportedOnce.Do(func() {
			logger.InfoContext(ctx, "password: store does not support hash updates; legacy hashes are kept")
		})
		return
	}
	logger.WarnContext(ctx, "password: rehash to argon2id failed; will retry on next login",
		slog.String("subject", subject), slog.Any("error", err))
}

// lookupCredential resolves username to its user and stored hash. A
// missing user (nil) or missing hash (empty) is not an error; any other
// backend fault is returned so the chain stops.
func (a *Authenticator) lookupCredential(ctx context.Context, username string) (*store.User, []byte, error) {
	user, err := a.store.FindByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("password: lookup user: %w", err)
	}
	if user == nil {
		return nil, nil, nil
	}
	hash, err := a.store.ReadPasswordHash(ctx, user.Subject)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, nil, fmt.Errorf("password: read hash: %w", err)
	}
	return user, hash, nil
}

// lockedSubject reports whether the shared counter currently locks
// user. counted is false when the counter must not be consulted.
func (a *Authenticator) lockedSubject(ctx context.Context, counted bool, user *store.User) (bool, error) {
	if !counted {
		return false, nil
	}
	locked, _, err := a.lockout.IsLocked(ctx, user.Subject)
	if err != nil {
		return false, fmt.Errorf("password: lockout guard: %w", err)
	}
	return locked, nil
}

// recordMismatch counts a wrong password against subject and returns
// [ErrInvalidCredentials]. A lock taking effect, including the long one,
// answers like any other wrong password so the response never reveals
// the account; a counter fault is returned instead.
func (a *Authenticator) recordMismatch(ctx context.Context, subject string) error {
	if _, err := a.lockout.RecordFailure(ctx, subject); err != nil && !errors.Is(err, lockout.ErrResetRequired) {
		return fmt.Errorf("password: lockout record failure: %w", err)
	}
	return ErrInvalidCredentials
}

// passwordPrompt builds the [interaction.Prompt] the adapter emits on
// Begin. Centralising the shape keeps the FieldSpec values consistent
// across calls and aligns with the existing HTMLDriver template.
func passwordPrompt() *interaction.Prompt {
	return &interaction.Prompt{
		Type: PromptType,
		Data: interaction.PasswordPromptData{},
		Inputs: []interaction.FieldSpec{
			{
				Name:     UsernameFieldName,
				Kind:     interaction.FieldText,
				Label:    "auth.password.username",
				Required: true,
				MinLen:   usernameMinLen,
				MaxLen:   usernameMaxLen,
			},
			{
				Name:     PasswordFieldName,
				Kind:     interaction.FieldPassword,
				Label:    "auth.password.password",
				Required: true,
				MinLen:   passwordMinLen,
				MaxLen:   passwordMaxLen,
			},
		},
	}
}

// dummyHash returns a precomputed, parameter-compatible Argon2id PHC
// encoding the verifier consumes when a username lookup misses or a
// password column is absent. The caller's
// [subtle.ConstantTimeCompare] over the derived bytes matches the
// real-account path, equalising verify latency.
//
// The salt and password value are arbitrary fixed strings (the hash
// is never matched in practice — every call against it fails the
// constant-time compare). The cost is paid once per process via
// [sync.Once].
func dummyHash() []byte {
	dummyHashOnce.Do(initDummyHash)
	return dummyHashCache
}

//nolint:gochecknoglobals // package-internal precompute, guarded by sync.Once.
var (
	dummyHashOnce  sync.Once
	dummyHashCache []byte
)

// initDummyHash runs once via [dummyHashOnce] to precompute the
// timing-equalisation hash. The parameters mirror the library's
// recommended Argon2id tuning so the derivation cost matches what an
// embedder using a sane password-hashing library will produce.
func initDummyHash() {
	salt := []byte("op-password-eq16")
	dummyHashCache = []byte(argon2id.Hash([]byte("dummy"), salt, argon2id.DefaultParams()))
}

// Compile-time confirmation that *Authenticator satisfies the public
// interface.
var _ authn.Authenticator = (*Authenticator)(nil)
