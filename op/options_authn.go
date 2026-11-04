package op

import (
	"strconv"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/op/store"
)

// WithCookieKeys registers the AES-256-GCM keys used for cookie encryption.
// The first key is the active encryption key; remaining keys are accepted on
// decryption only, supporting graceful rotation. Every key MUST be 32 bytes;
// an empty list is rejected so the misconfiguration surfaces at startup.
// Pass every active and rotated key (single key in the typical case) in a
// single call; a second WithCookieKeys makes [New] fail.
// Stable since v1.0.
func WithCookieKeys(keys ...[]byte) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithCookieKeys"); err != nil {
			return err
		}
		if len(keys) == 0 {
			return newConfigurationError("WithCookieKeys requires at least one key", nil)
		}
		// Defensive copy so a later mutation of the caller's slice does
		// not silently change the OP's keys at runtime.
		cp := make([][]byte, len(keys))
		for i, k := range keys {
			b := make([]byte, len(k))
			copy(b, k)
			cp[i] = b
		}
		c.cookieKeys = cp
		return nil
	})
}

// WithMFAEncryptionKeys registers the AES-256-GCM keys used to seal
// per-user TOTP shared secrets at rest. The first key is the active
// encryption key; remaining keys are accepted on decryption only,
// supporting graceful rotation. Every key MUST be 32 bytes; an empty
// list is rejected so the misconfiguration surfaces at startup.
//
// Pass every active and rotated key (a single key in the typical case) in
// a single call; a second WithMFAEncryptionKeys makes [New] fail.
//
// The keys back every [StepTOTP] whose own EncryptionKey is empty;
// a per-step EncryptionKey overrides the global value when present
// (more-specific-wins). Retain previous keys until every persisted
// TOTP record has been re-sealed under the active key.
// Stable since v1.0.
func WithMFAEncryptionKeys(keys ...[]byte) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithMFAEncryptionKeys"); err != nil {
			return err
		}
		if len(keys) == 0 {
			return newConfigurationError("WithMFAEncryptionKeys requires at least one key", nil)
		}
		for i, k := range keys {
			if len(k) != mfaEncryptionKeyLen {
				return newConfigurationError("WithMFAEncryptionKeys: entry "+strconv.Itoa(i)+" is not 32 bytes (got "+
					strconv.Itoa(len(k))+")", nil)
			}
		}
		// Defensive copy so a later mutation of the caller's slice does
		// not silently change the OP's keys at runtime.
		cp := make([][]byte, len(keys))
		for i, k := range keys {
			b := make([]byte, len(k))
			copy(b, k)
			cp[i] = b
		}
		c.mfaEncryptionKeys = cp
		return nil
	})
}

// mfaEncryptionKeyLen mirrors the AES-256-GCM key length the TOTP
// codec accepts. The constant is duplicated here so option-level
// validation can return a stable [*Error] without instantiating the
// codec.
const mfaEncryptionKeyLen = 32

// WithAuthnLockoutStore wires the cross-factor brute-force counter.
// Every built-in [Step] that checks a guessable secret ([PrimaryPassword],
// [StepTOTP], [StepEmailOTP], [StepRecoveryCode]) consults the same
// per-subject counter so an attacker pivoting between factors cannot
// double their guess budget. The store backs a rolling 24-hour
// window: a 1-hour lockout at 30 cumulative failures, 24-hour at 90.
//
// Password behaviour — a wrong password is counted; once the subject is
// locked even the correct password is refused, with the same response as
// a wrong one, so the lock does not reveal that the account exists.
// Unknown usernames and accounts without a password hash never touch the
// counter. A successful password login does not reset it: the budget is
// shared with the second factors, and a reset there would let anyone who
// knows the password refill their guesses. A counter or store error fails
// the attempt with a server error rather than letting it through.
//
// Scope — the counter is NOT attached to [PrimaryPasskey], and an
// [ExternalStep] custom factor is not counted unless it opts in through
// [ExternalStep.CountFailures]. Opting in needs a subject to count
// against, so [New] rejects it at [LoginFlow.Primary]; an ExternalStep
// there relies on the lockout policy of whatever it verifies against.
//
// Automatic wiring — when this option is not set and the [WithStore]
// value implements [store.AuthnLockoutProvider] (an AuthnLockouts()
// [store.AuthnLockoutStore] method; the in-memory, SQL and DynamoDB
// adapters do, and composite.Store forwards the backend routed for its AuthnLockouts kind), that
// store is used. An explicit option always wins.
//
// Backends MUST implement the versioned atomic-transition contract on
// [store.AuthnLockoutStore.CompareAndSwap]. The library uses that one
// primitive for increments, rolling-window rollover, lock stamping, and
// success reset so none of those paths can overwrite a concurrently
// recorded failure.
//
// Durability follows the backend. The SQL adapter implements
// [store.AuthnLockoutStore] over its own lockout table
// ([sql.Store.AuthnLockouts]), as does the DynamoDB adapter
// ([dynamodb.Store.AuthnLockouts]), so a counter wired to either
// survives a restart and is shared across replicas. The in-memory
// reference ([inmem.Store.AuthnLockouts]) is process-local: it resets
// on restart and gives each replica its own guess budget, which is
// the wrong shape for anything but a single-process demo. An embedder
// on another backend supplies its own implementation.
//
// When this option is unset the store is taken from the [WithStore] value
// if it implements [store.AuthnLockoutProvider]. A [LoginFlow] with a
// password or second-factor step and no resolved store makes [New] fail
// with [ErrAuthnLockoutStoreRequired]; route the store to a backend every
// replica shares.
//
// At most one store may be registered; a second [WithAuthnLockoutStore]
// call fails [New] with a structured configuration error.
//
// Stable since v1.0.
func WithAuthnLockoutStore(s store.AuthnLockoutStore) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithAuthnLockoutStore"); err != nil {
			return err
		}
		if nilcheck.IsNil(s) {
			return newConfigurationError("WithAuthnLockoutStore received nil AuthnLockoutStore", nil)
		}
		c.authnLockoutStore = s
		return nil
	})
}

// WithScope registers metadata for a single OAuth scope. Calling the
// option multiple times accumulates entries; duplicate Name values
// across calls are rejected at [New] construction time.
// Standard OIDC scopes (openid, profile, email, address, phone,
// offline_access) are recognised automatically with built-in defaults
// (Public: true, no UI text). Registering a standard scope through
// [WithScope] overrides the built-in entry — typically to attach
// translations or claim mappings — but registering one with
// Public: false fails [New] so the discovery document never violates
// OpenID Connect Discovery 1.0 §3.
// AllowedClients is enforced at the authorize and token endpoints: a
// non-empty list restricts the scope to the listed client_id values
// and any other client receives invalid_scope per RFC 6749 §5.2.
// Stable since v1.0.
func WithScope(s Scope) Option {
	return optionFunc(func(c *config) error {
		if s.Name == "" {
			return newConfigurationError("WithScope: Name must not be empty", nil)
		}
		c.scopes = append(c.scopes, s)
		return nil
	})
}

// WithLoginAttemptObserver registers a [LoginAttemptObserver]. Multiple
// observers stack; the orchestrator fans out every [LoginAttempt] to
// each registered observer in registration order. This is the brute-
// force / risk-counter feed; general audit events are emitted by the
// library to slog and observers MUST NOT duplicate them here.
//
// Stable since v1.5.
func WithLoginAttemptObserver(o LoginAttemptObserver) Option {
	return optionFunc(func(c *config) error {
		if nilcheck.IsNil(o) {
			return newConfigurationError("WithLoginAttemptObserver received nil LoginAttemptObserver", nil)
		}
		c.loginObservers = append(c.loginObservers, o)
		return nil
	})
}

// WithInteractions registers non-factor [Interaction] values (T&C,
// KYC, device-trust prompts...). Order is preserved within an
// [InteractionTrigger] bucket; cross-trigger ordering is orchestrator-
// defined. Calling WithInteractions multiple times appends; duplicates
// by [Interaction.Name] are rejected at [New] construction time.
// The library-built-in consent screen and account chooser are
// registered automatically by the orchestrator, and their names
// "consent" and "chooser" are reserved: an extension using either fails
// [New]. User extensions ship with a unique dotted [Interaction.Name]
// (e.g., "myorg.tos.accept").
//
// Stable since v1.5.
func WithInteractions(i ...Interaction) Option {
	return optionFunc(func(c *config) error {
		if len(i) == 0 {
			return newConfigurationError("WithInteractions requires at least one Interaction", nil)
		}
		for idx, item := range i {
			if nilcheck.IsNil(item) {
				return newConfigurationError("WithInteractions received nil Interaction at position "+strconv.Itoa(idx), nil)
			}
		}
		c.interactions = append(c.interactions, i...)
		c.recordBrowserSurface("WithInteractions")
		return nil
	})
}

// WithLoginFlow registers the [LoginFlow] the orchestrator drives.
// The option compiles the flow into an internal runtime structure at
// [New] and routes the authenticator chain through the
// LoginFlow / Rule / Decider evaluation loop.
// Validation:
//   - Primary MUST be non-nil. A flow with a nil Primary is rejected
//     at the option site.
//   - No two [Rule.Then] entries may share a [Step.Kind]; duplicate
//     kinds are rejected so the orchestrator's completed-step
//     deduplication has a unique discriminator per rule.
//   - [LoginFlow.Registration], when set, MUST be an [ExternalStep]
//     with CountFailures false and a KindLabel no other step uses; a
//     Rule whose Then names that kind is rejected.
//   - Decider MAY be nil; the orchestrator treats nil as "always
//     defer to rules".
//   - Repeated [WithLoginFlow] calls are rejected so the
//     misconfiguration surfaces at [New].
//
// Built-in [Step] values (PrimaryPassword, PrimaryPasskey, StepTOTP,
// StepEmailOTP, StepRecoveryCode, StepCaptcha) are wired: pass them
// directly and [New] builds the authenticator, including the
// cross-factor lockout counter [WithAuthnLockoutStore] attaches.
// [ExternalStep] wraps an already-constructed [Authenticator] and is
// the seam for factors this package does not implement — a step taken
// through it receives that counter only when it sets
// [ExternalStep.CountFailures], so reach for it only when no built-in
// Step covers the factor.
//
// Stable since v1.5.
func WithLoginFlow(flow LoginFlow) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithLoginFlow"); err != nil {
			return err
		}
		if nilcheck.IsNil(flow.Primary) {
			return newConfigurationError("WithLoginFlow: LoginFlow.Primary must not be nil", nil)
		}
		if err := checkLoginFlowRuleKinds(flow); err != nil {
			return err
		}
		c.loginFlow = flow
		c.loginFlowSet = true
		c.recordBrowserSurface("WithLoginFlow")
		return nil
	})
}

// checkLoginFlowRuleKinds rejects a Rule whose Then is nil, names the
// Registration StepKind, or repeats another Rule's StepKind.
func checkLoginFlowRuleKinds(flow LoginFlow) error {
	seen := make(map[StepKind]struct{}, len(flow.Rules))
	var registration StepKind
	if !nilcheck.IsNil(flow.Registration) {
		registration = flow.Registration.Kind()
	}
	for i, r := range flow.Rules {
		if nilcheck.IsNil(r.Then) {
			return newConfigurationError("WithLoginFlow: Rules["+strconv.Itoa(i)+"].Then must not be nil", nil)
		}
		k := r.Then.Kind()
		if registration != "" && k == registration {
			return newConfigurationError("WithLoginFlow: Rules["+strconv.Itoa(i)+"].Then must not name the Registration StepKind "+k.String(), nil)
		}
		if _, dup := seen[k]; dup {
			return newConfigurationError("WithLoginFlow: duplicate StepKind "+k.String()+" across Rules", nil)
		}
		seen[k] = struct{}{}
	}
	return nil
}
