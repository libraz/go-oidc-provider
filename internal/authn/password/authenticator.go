package password

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/libraz/go-oidc-provider/internal/argon2id"
	"github.com/libraz/go-oidc-provider/internal/authn"
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
var ErrFieldMissing = errors.New("password: required field is missing")

// Authenticator is the [authn.Authenticator] adapter for the built-in
// PrimaryPassword Step. It wraps a [store.UserPasswordStore] and
// drives the verify ceremony: prompt for username + password, look
// up the user, fetch the stored Argon2id hash, verify in
// constant time.
//
// Construct through [NewAuthenticator]; the zero value is not usable.
type Authenticator struct {
	store store.UserPasswordStore
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
	return &Authenticator{store: s}, nil
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
	user, lookupErr := a.store.FindByUsername(ctx, username)
	if lookupErr != nil && !errors.Is(lookupErr, store.ErrNotFound) {
		return "", fmt.Errorf("password: lookup user: %w", lookupErr)
	}
	userExists := lookupErr == nil && user != nil

	var (
		hash    []byte
		hashErr error
	)
	if userExists {
		hash, hashErr = a.store.ReadPasswordHash(ctx, user.Subject)
		if hashErr != nil && !errors.Is(hashErr, store.ErrNotFound) {
			return "", fmt.Errorf("password: read hash: %w", hashErr)
		}
	}

	// Equalise the verify cost regardless of which sub-step failed:
	// every path computes one Argon2id derivation, then a constant-time
	// compare. The dummyHash is parameter-compatible with library-emitted
	// hashes so the verify cost matches a real account.
	verifyAgainst := hash
	if !userExists || len(hash) == 0 {
		verifyAgainst = dummyHash()
	}
	verifyErr := Verify(verifyAgainst, candidate)

	if !userExists || len(hash) == 0 || verifyErr != nil {
		return "", ErrInvalidCredentials
	}
	return user.Subject, nil
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
	const (
		memory      uint32 = 64 * 1024
		iterations  uint32 = 3
		parallelism uint8  = 1
		keyLen      uint32 = 32
	)
	salt := []byte("op-password-eq16")
	key := argon2id.Key([]byte("dummy"), salt, iterations, memory, parallelism, keyLen)
	dummyHashCache = []byte(fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2id.Version,
		memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	))
}

// Compile-time confirmation that *Authenticator satisfies the public
// interface.
var _ authn.Authenticator = (*Authenticator)(nil)
