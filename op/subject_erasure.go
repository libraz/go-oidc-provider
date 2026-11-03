package op

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/op/store"
)

// ForgetSubject erases what the OP holds for a subject, for an embedder
// that deletes a user. In order it calls [Provider.RevokeSubject] (every
// grant, with its access and refresh tokens), deletes every browser
// session of the subject through [store.SessionSubjectDeleter], deletes
// its cross-factor lockout record through [store.AuthnLockoutDeleter],
// and deletes its factor records in every store the [LoginFlow]
// references: the TOTP enrolment ([StepTOTP]), the recovery-code batch
// ([StepRecoveryCode]), the pending email OTP challenge ([StepEmailOTP])
// and every registered passkey ([PrimaryPasskey]). Sessions of other
// subjects stay, including those sharing a browser's account chooser.
// The user stores themselves are never written: the user record is the
// embedder's to delete.
//
// # Order
//
// Delete the user first, so that every user store the OP reads (the
// [WithUserStore] claim source and each login step's own store,
// [PrimaryPassword.Store] and [StepEmailOTP.Users]) answers
// [store.ErrNotFound] for the subject, and call ForgetSubject after.
// ForgetSubject enforces the order: while any of those stores still
// resolves the subject it returns a configuration_error [*Error] and
// changes nothing. Otherwise a login running concurrently with the
// erasure could re-create a session after it was deleted.
//
// # Preconditions and errors
//
// Nothing is changed until every precondition holds. An empty subject,
// a user store that still resolves the subject, and a session or lockout
// store that lacks its extension are configuration_error [*Error]s; the
// last names every missing interface in one error. A user store failing
// the lookup is a server_error [*Error].
//
// Once the preconditions hold, every step is attempted even when an
// earlier one fails, and the failures are joined into one server_error
// [*Error]. A record that is already gone counts as deleted, so the call
// is idempotent: repeating it after a partial failure completes what is
// left, and repeating it after success returns nil.
//
// # What is not reached
//
// The credentials [Provider.RevokeSubject] does not reach stay until
// they expire: tokens a [CustomGrantHandler] or the jwt-bearer grant
// issued, and device code or CIBA requests approved but not yet
// redeemed. Interactions, pushed authorization requests and consumed
// JTIs are short-lived and not keyed by subject. Audit sinks, the Shared
// Signals queue, the [WithPreferredLocaleStore] data and the state of an
// [ExternalStep] belong to the embedder or are invisible to the library.
//
// On Redis and DynamoDB a session written before the upgrade that added
// the subject index joins the index on its next Touch; one never touched
// again is not reached and stays until it expires. It cannot mint tokens
// once the grants are gone, and the user store no longer resolves its
// subject.
//
// # Notifications
//
// No Back-Channel Logout is sent to relying parties and no audit event
// is emitted, matching [Provider.RevokeSubject]. Under
// [WithSharedSignals], RevokeSubject queues a CAEP session-revoked SET
// for every receiver the subject holds a grant with.
//
// ForgetSubject cannot serve an embedder that keeps the user row (a legal
// hold, a soft-delete flag FindBySubject ignores): it refuses while the
// subject resolves. Call [Provider.RevokeSubject] and the factor stores'
// Delete methods directly instead.
//
// Stable since v1.5.
func (p *Provider) ForgetSubject(ctx context.Context, subject string) error {
	if subject == "" {
		return newConfigurationError("ForgetSubject: subject must not be empty", nil)
	}
	stores := p.cfg.subjectStores()
	if err := checkUsersForgotten(ctx, stores.users, subject); err != nil {
		return err
	}
	sessions, lockouts, err := p.cfg.erasureDeleters()
	if err != nil {
		return err
	}

	var errs []error
	if err := p.RevokeSubject(ctx, subject); err != nil {
		errs = append(errs, err)
	}
	if sessions != nil {
		if err := sessions.DeleteBySubject(ctx, subject); err != nil {
			errs = append(errs, fmt.Errorf("session store: %w", err))
		}
	}
	if lockouts != nil {
		if err := lockouts.Delete(ctx, subject); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, fmt.Errorf("authn lockout store: %w", err))
		}
	}
	errs = append(errs, stores.deleteFactors(ctx, subject)...)
	if err := errors.Join(errs...); err != nil {
		return &Error{
			Code:        codeServerError,
			Description: "ForgetSubject: store rejected the erasure",
			Cause:       err,
		}
	}
	return nil
}

// checkUsersForgotten refuses the erasure while any user store still
// resolves subject.
func checkUsersForgotten(ctx context.Context, users []namedStore[store.UserStore], subject string) error {
	for _, u := range users {
		_, err := u.store.FindBySubject(ctx, subject)
		switch {
		case err == nil:
			return newConfigurationError("ForgetSubject: "+u.label+
				" still resolves the subject; make FindBySubject return store.ErrNotFound for it first", nil)
		case !errors.Is(err, store.ErrNotFound):
			return &Error{
				Code:        codeServerError,
				Description: "ForgetSubject: " + u.label + " rejected FindBySubject",
				Cause:       err,
			}
		}
	}
	return nil
}

// erasureDeleters returns the session and lockout deleters, nil where the
// configuration has no such store, or one configuration error naming
// every store that lacks its extension.
func (c *config) erasureDeleters() (store.SessionSubjectDeleter, store.AuthnLockoutDeleter, error) { //nolint:ireturn,nolintlint // the extension interfaces are the substore contract.
	var (
		missing  []string
		sessions store.SessionSubjectDeleter
		lockouts store.AuthnLockoutDeleter
	)
	if s := c.store.Sessions(); !nilcheck.IsNil(s) {
		d, ok := s.(store.SessionSubjectDeleter)
		if ok {
			sessions = d
		} else {
			missing = append(missing, "the session store does not implement store.SessionSubjectDeleter")
		}
	}
	if l := resolveAuthnLockoutStore(c); l != nil {
		d, ok := l.(store.AuthnLockoutDeleter)
		if ok {
			lockouts = d
		} else {
			missing = append(missing, "the authn lockout store does not implement store.AuthnLockoutDeleter")
		}
	}
	if len(missing) > 0 {
		return nil, nil, newConfigurationError("ForgetSubject: "+strings.Join(missing, "; ")+"; nothing was erased", nil)
	}
	return sessions, lockouts, nil
}

// namedStore is a store paired with the option field it came from, the
// label an erasure failure is reported under.
type namedStore[T any] struct {
	label string
	store T
}

// subjectStoreSet holds the distinct per-subject stores the configuration
// references, one list per record kind.
type subjectStoreSet struct {
	users      []namedStore[store.UserStore]
	passkeys   []namedStore[store.PasskeyStore]
	totps      []namedStore[store.TOTPStore]
	recoveries []namedStore[store.RecoveryStore]
	emailOTPs  []namedStore[store.EmailOTPStore]
}

// subjectStores collects the claim-source user store and the stores of
// every built-in login step. Embedder-supplied steps, whose internals the
// library cannot inspect, contribute nothing.
func (c *config) subjectStores() subjectStoreSet {
	var set subjectStoreSet
	set.users = appendDistinct(set.users, claimSourceOption(c), c.effectiveUserStore())
	for _, s := range c.loginFlowSteps() {
		switch step := s.(type) {
		case PrimaryPassword:
			set.users = appendDistinct(set.users, "LoginFlow PrimaryPassword.Store", store.UserStore(step.Store))
		case PrimaryPasskey:
			set.passkeys = appendDistinct(set.passkeys, "LoginFlow PrimaryPasskey.Store", step.Store)
		case StepTOTP:
			set.totps = appendDistinct(set.totps, "LoginFlow StepTOTP.Store", step.Store)
		case StepRecoveryCode:
			set.recoveries = appendDistinct(set.recoveries, "LoginFlow StepRecoveryCode.Store", step.Store)
		case StepEmailOTP:
			set.users = appendDistinct(set.users, "LoginFlow StepEmailOTP.Users", step.Users)
			set.emailOTPs = appendDistinct(set.emailOTPs, "LoginFlow StepEmailOTP.Store", step.Store)
		}
	}
	return set
}

// appendDistinct appends s unless it is nil or already listed. Identity
// follows [schemaAlreadyChecked]: a store of a non-comparable dynamic type
// is never treated as listed, so it is visited again, which every
// visitor here tolerates.
func appendDistinct[T any](list []namedStore[T], label string, s T) []namedStore[T] {
	if nilcheck.IsNil(s) {
		return list
	}
	for _, prev := range list {
		if schemaAlreadyChecked([]any{prev.store}, s) {
			return list
		}
	}
	return append(list, namedStore[T]{label: label, store: s})
}

// deleteFactors deletes subject's record in every factor store, treating
// [store.ErrNotFound] as deleted, and returns every other failure.
func (set *subjectStoreSet) deleteFactors(ctx context.Context, subject string) []error {
	var errs []error
	record := func(label string, err error) {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, fmt.Errorf("%s: %w", label, err))
		}
	}
	for _, s := range set.totps {
		record(s.label, s.store.Delete(ctx, subject))
	}
	for _, s := range set.recoveries {
		record(s.label, s.store.Delete(ctx, subject))
	}
	for _, s := range set.emailOTPs {
		record(s.label, s.store.Delete(ctx, subject))
	}
	for _, s := range set.passkeys {
		creds, err := s.store.ListBySubject(ctx, subject)
		if err != nil {
			record(s.label+" ListBySubject", err)
			continue
		}
		for _, cred := range creds {
			if cred == nil || len(cred.CredentialID) == 0 {
				continue
			}
			record(s.label+" Delete", s.store.Delete(ctx, cred.CredentialID))
		}
	}
	return errs
}
