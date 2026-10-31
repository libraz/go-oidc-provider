package cibaendpoint

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/op/store"
)

// HintResolver maps a CIBA hint to a stable end-user subject.
// The library calls Resolve once per /bc-authorize POST after
// classifying the hint kind.
//
// What value arrives depends on the kind:
//
//   - [ciba.HintLoginHint] and [ciba.HintLoginHintToken] deliver the
//     raw wire parameter. The OP has no way to interpret either, so
//     verifying a login_hint_token's signature and issuer is the
//     implementation's job.
//   - [ciba.HintIDTokenHint] delivers the OP-verified sub claim, NOT
//     the JWT. The handler has already checked the signature against
//     the OP keyset, the iss claim, and that the audience identifies
//     the authenticated client (CIBA Core 1.0 §7.1), so the value is
//     an OP-issued subject the implementation can look up directly.
//
// Implementations MUST:
//
//   - return a non-empty subject on success;
//   - return [ErrUnknownUser] when the hint does not resolve to a
//     known end-user (the handler maps this to unknown_user_id);
//   - return any other error to surface as login_required (the
//     handler treats non-[ErrUnknownUser] failures as an
//     authentication failure rather than a soft "no such user"
//     answer).
type HintResolver interface {
	Resolve(ctx context.Context, kind ciba.HintKind, value string) (subject string, err error)
}

// ErrUnknownUser is the sentinel a [HintResolver] returns to signal
// the hint did not match a known end-user. Maps to the
// unknown_user_id wire code.
var ErrUnknownUser = errors.New("cibaendpoint: hint did not resolve to a known end-user")

// classifyHint dispatches to [ciba.ClassifyHint] and maps the
// sentinel onto the wire response. On success the helper returns
// the kind and the trimmed hint value.
func classifyHint(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	form url.Values,
	clientID string,
) (ciba.HintKind, string, bool) {
	kind, value, err := ciba.ClassifyHint(
		form.Get("login_hint"),
		form.Get("id_token_hint"),
		form.Get("login_hint_token"),
	)
	if err != nil {
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: hint combination invalid",
			ClientID: clientID,
			Extras: map[string]any{
				"reason": "hint_combination_invalid",
			},
		})
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"exactly one of login_hint, id_token_hint, or login_hint_token is required")
		return ciba.HintNone, "", false
	}
	return kind, value, true
}

// pairwiseSubjectType is the OIDC Core 1.0 §8 subject_type value that
// makes a client's "sub" a per-sector pseudonym rather than the
// OP-internal identifier. Mirrors the literal the issuance-side
// subject projector dispatches on.
const pairwiseSubjectType = "pairwise"

// verifyIDTokenHint runs the CIBA Core 1.0 §7.1 verification the OP
// owes an inbound id_token_hint and returns the value the resolver
// should see. For every other hint kind the raw parameter passes
// through untouched.
//
// On the id_token_hint branch the returned value is the OP-verified
// sub claim, not the JWT: the token's signature is checked against the
// OP keyset, its iss must be this issuer, and its audience must
// identify the client that authenticated on this very request. Without
// that last binding any CIBA-registered client could present an ID
// Token minted for a different client and have the ceremony addressed
// to a subject it was never entitled to name.
//
// Pairwise clients are refused outright. A client registered with
// subject_type=pairwise receives per-sector pseudonyms (OIDC Core 1.0
// §8.1), which are SHA-256 outputs the OP keeps no reverse index for;
// the one place the library recovers a raw subject from a projected
// one pivots through an access token's grant lineage, and an ID Token
// carries no such lineage. Handing the resolver a pseudonym it cannot
// map would either fail confusingly or invite the embedder to guess,
// so the request is rejected with a description that names the
// supported alternative.
//
// The bool is false when the function wrote the response.
func verifyIDTokenHint(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	kind ciba.HintKind,
	value string,
	client *store.Client,
) (string, bool) {
	if kind != ciba.HintIDTokenHint {
		return value, true
	}
	if client.SubjectType == pairwiseSubjectType {
		emitHintRejected(ctx, deps, client.ID, "id_token_hint_pairwise_unsupported")
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"id_token_hint is not accepted from a client using pairwise subject identifiers; "+
				"use login_hint or login_hint_token")
		return "", false
	}
	subject, err := ciba.VerifyIDTokenHint(ctx, deps.Keys, deps.Issuer, client.ID, value)
	if err != nil {
		if errors.Is(err, ciba.ErrIDTokenHintUnverifiable) {
			emitHintRejected(ctx, deps, client.ID, "id_token_hint_unverifiable")
			writeError(w, http.StatusInternalServerError, errServerError,
				"id_token_hint verification is not configured")
			return "", false
		}
		// Every client-facing cause collapses onto one code and one
		// description so the wire surface cannot be probed to learn
		// which check rejected the token.
		emitHintRejected(ctx, deps, client.ID, "id_token_hint_invalid")
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"id_token_hint is not an id_token this OP issued to this client")
		return "", false
	}
	return subject, true
}

// emitHintRejected records a hint-verification rejection on the audit
// stream. reason is a stable code string; the wire response carries
// less detail on purpose, so the audit event is where an operator
// learns which gate closed.
func emitHintRejected(ctx context.Context, deps Deps, clientID, reason string) {
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     ciba.AuditAuthorizationRejected,
		Level:    audit.LevelWarn,
		Message:  "backchannel-authentication rejected: id_token_hint not accepted",
		ClientID: clientID,
		Extras: map[string]any{
			"reason": reason,
		},
	})
}

// resolveHint runs the OP-side id_token_hint verification and then
// invokes the embedder's [HintResolver], mapping the outcome onto the
// wire response. A nil resolver collapses onto login_required so a
// misconfigured deployment never silently resolves every hint to the
// empty subject.
//
// The verification runs here rather than at the call site so no future
// edit can reorder the two: on the [ciba.HintIDTokenHint] branch the
// resolver receives the OP-verified sub produced by
// [verifyIDTokenHint], never the JWT.
func resolveHint(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	kind ciba.HintKind,
	value string,
	client *store.Client,
) (string, bool) {
	clientID := client.ID
	value, ok := verifyIDTokenHint(ctx, w, deps, kind, value, client)
	if !ok {
		return "", false
	}
	if deps.HintResolver == nil {
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: no hint resolver configured",
			ClientID: clientID,
			Extras: map[string]any{
				"reason": "hint_resolution_failed",
			},
		})
		writeError(w, http.StatusBadRequest, errLoginRequired,
			"end-user authentication is required to resolve the hint")
		return "", false
	}
	subject, err := deps.HintResolver.Resolve(ctx, kind, value)
	if err != nil {
		if errors.Is(err, ErrUnknownUser) {
			deps.auditEmitter().Emit(ctx, audit.Event{
				Name:     ciba.AuditAuthorizationRejected,
				Level:    audit.LevelWarn,
				Message:  "backchannel-authentication rejected: unknown user",
				ClientID: clientID,
				Extras: map[string]any{
					"reason": "unknown_user_id",
				},
			})
			writeError(w, http.StatusBadRequest, errUnknownUserID,
				"the hint did not resolve to a known end-user")
			return "", false
		}
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: hint resolution failed",
			ClientID: clientID,
			Extras: map[string]any{
				"reason": "hint_resolution_failed",
			},
		})
		writeError(w, http.StatusBadRequest, errLoginRequired,
			"end-user authentication is required to resolve the hint")
		return "", false
	}
	if subject == "" {
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: resolver returned empty subject",
			ClientID: clientID,
			Extras: map[string]any{
				"reason": "hint_resolution_failed",
			},
		})
		writeError(w, http.StatusBadRequest, errLoginRequired,
			"end-user authentication is required to resolve the hint")
		return "", false
	}
	return subject, true
}
