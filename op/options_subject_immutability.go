package op

import (
	"context"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/op/store"
)

// ErrSubjectModeMismatch is returned by [New] when the configured
// subject-issuance mode disagrees with the marker the OP previously
// recorded against a non-empty grant store. Switching strategies after
// any "sub" has been issued reassigns subjects, breaking OIDC Core
// 1.0 §5.7 stability and orphaning resource-server caches keyed on
// "sub". Embedders who need to switch provision a new issuer (and
// therefore a new marker store) and migrate RPs deliberately.
var ErrSubjectModeMismatch = &Error{
	Code:        codeConfiguration,
	Description: "subject-issuance mode disagrees with the persisted marker; provision a new issuer instead of switching strategies on a populated store",
}

// effectiveSubjectMode returns the [store.SubjectModeKey] value the
// gate compares against the persisted marker. The mapping is the
// inverse of the option layer: empty source (no subject option
// supplied) is the public passthrough; the two named sources name
// themselves.
func (c *config) effectiveSubjectMode() string {
	switch c.subjectGeneratorSource {
	case "WithPairwiseSubject":
		return store.SubjectModePairwise
	case "WithSubjectGenerator":
		return store.SubjectModeCustom
	default:
		return store.SubjectModePublic
	}
}

// enforceSubjectModeGate runs the subject-mode immutability check
// at op.New. The gate consults [store.MetadataStore] for the persisted
// subject-mode marker and compares it to the construction-time mode.
// On a fresh store the gate writes the marker so a later boot can
// detect a switch; on a populated store with no marker the gate
// infers "public" (the only mode v0.9.0 supported) and refuses any
// non-public construction.
//
// To defend against the empty-store edge case where a previously-used
// store has been truncated (or its [store.SubjectModeKey] row wiped
// out of band) — leaving neither the subject-mode marker, nor any
// grants — the gate also probes the [store.OpInitKey] sentinel. The
// sentinel is written on every successful construction; if it is
// present at op.New time it means the store has been used by some OP
// before, so the absence of [store.SubjectModeKey] cannot be trusted
// as a fresh install signal. In that case the gate refuses any
// non-public construction so a deliberate or accidental wipe cannot
// silently re-key every future "sub".
//
// The gate is tolerant of [store.Store.Metadata] returning nil: the
// SQL / Redis adapters in v0.9.1 have not yet provisioned the
// substore and the library logs a warning rather than refusing to
// boot. Embedders running pairwise on those adapters carry the
// switch-by-accident risk explicitly until the adapter pass lands.
func (c *config) enforceSubjectModeGate(ctx context.Context) error {
	current := c.effectiveSubjectMode()
	meta := c.store.Metadata()
	if meta == nil {
		if c.logger != nil && current != store.SubjectModePublic {
			c.logger.Warn(
				"subject-mode immutability gate skipped: store does not implement MetadataStore (sql / redis adapters defer the substore to a future release); switching subject strategies on a populated store will silently reassign sub values.",
				"mode", current,
			)
		}
		return nil
	}
	persisted, err := meta.Get(ctx, store.SubjectModeKey)
	if err == nil {
		if persisted == current {
			return c.writeOpInitMarker(ctx, meta)
		}
		return fmt.Errorf("%w: persisted=%q, configured=%q", ErrSubjectModeMismatch, persisted, current)
	}
	if !errors.Is(err, store.ErrNotFound) {
		return &Error{
			Code:        codeConfiguration,
			Description: "subject-mode marker read failed",
			Cause:       err,
		}
	}
	// SubjectModeKey is absent. Two paths reach here legitimately —
	// a truly fresh install, and a v0.9.0 → v0.9.x upgrade with grants
	// already in the store — and one path reaches here illegitimately:
	// a previously-used store whose SubjectModeKey row was wiped while
	// other artifacts (or the OpInitKey sentinel itself) remain. The
	// OpInitKey probe distinguishes the two: presence means the store
	// has been used by some OP before so a "no marker" reading cannot
	// be trusted as fresh.
	priorInit, initErr := c.metadataHasOpInit(ctx, meta)
	if initErr != nil {
		return initErr
	}
	if priorInit && current != store.SubjectModePublic {
		return fmt.Errorf("%w: subject-mode marker absent but op-init sentinel present (store has been used previously), configured=%q",
			ErrSubjectModeMismatch, current)
	}
	hasGrants, hasErr := c.store.Grants().HasAny(ctx)
	if hasErr != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "grant-store probe for subject-mode gate failed",
			Cause:       hasErr,
		}
	}
	if hasGrants && current != store.SubjectModePublic {
		return fmt.Errorf("%w: persisted marker absent on a populated store (legacy upgrade infers %q), configured=%q",
			ErrSubjectModeMismatch, store.SubjectModePublic, current)
	}
	if err := meta.Set(ctx, store.SubjectModeKey, current); err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "subject-mode marker write failed",
			Cause:       err,
		}
	}
	return c.writeOpInitMarker(ctx, meta)
}

// metadataHasOpInit reports whether the store has previously been
// initialised by an OP. The probe reads [store.OpInitKey]: a
// matching value means a prior op.New invocation completed against
// this metadata store, so an absent [store.SubjectModeKey] cannot be
// trusted as a "first install" signal.
func (c *config) metadataHasOpInit(ctx context.Context, meta store.MetadataStore) (bool, error) {
	val, err := meta.Get(ctx, store.OpInitKey)
	if err == nil {
		return val == store.OpInitMarker, nil
	}
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return false, &Error{
		Code:        codeConfiguration,
		Description: "op-init sentinel read failed",
		Cause:       err,
	}
}

// writeOpInitMarker stamps the [store.OpInitKey] sentinel after the
// gate has accepted the construction. Idempotent by design: re-writing
// the same value lets backends implement the substore as a plain map
// without an upsert distinction.
func (c *config) writeOpInitMarker(ctx context.Context, meta store.MetadataStore) error {
	if err := meta.Set(ctx, store.OpInitKey, store.OpInitMarker); err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "op-init sentinel write failed",
			Cause:       err,
		}
	}
	return nil
}
