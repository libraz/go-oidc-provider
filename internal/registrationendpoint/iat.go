package registrationendpoint

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/op/store"
)

// iatVerification is the result of a successful IAT verification. The
// handler threads the resolved token through to the registration path
// so the AllowedScopes allowlist can be enforced and the token can be
// consumed atomically once the persistence step is about to commit.
type iatVerification struct {
	// Token is the resolved IAT record. The caller MUST consume it
	// (via [store.InitialAccessTokenStore.IncrementUses]) before the
	// registration is committed.
	Token *store.InitialAccessToken

	// Open reports whether the verification was skipped because
	// [Deps.Open] was true. When Open is true the rest of the struct
	// is the zero value and the caller MUST NOT consume any IAT.
	Open bool
}

// verifyIAT extracts the Bearer credential from the Authorization
// header, hashes it with sha256, and looks the IAT up in the store.
// On any failure the function writes the 401 response and returns
// ok=false so the caller stops processing.
// When [Deps.Open] is true the function returns an [iatVerification]
// with Open=true and ok=true so the caller can skip consumption.
func verifyIAT(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
) (iatVerification, bool) {
	if deps.Open {
		// Audit the open registration path so operators can see the
		// degraded posture in their logs. The caller may emit a
		// stronger WARN once the registration succeeds; the audit
		// event here records the configuration choice.
		deps.audit().Emit(ctx, audit.Event{
			Name:    auditDCROpenRegistrationUsed,
			Level:   audit.LevelWarn,
			Message: "open registration accepted without IAT",
		})
		return iatVerification{Open: true}, true
	}
	bearer, ok := bearerFromHeader(r.Header.Get("Authorization"))
	if !ok {
		writeInvalidToken(w, deps.Issuer, "Initial Access Token is required")
		return iatVerification{}, false
	}
	rec, err := deps.InitialAccessTokens.GetByHash(ctx, hashSecret(bearer))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			deps.logger().Warn("dcr.iat.invalid", "reason", "not_found")
			deps.audit().Emit(ctx, audit.Event{
				Name:    auditDCRIATInvalid,
				Level:   audit.LevelInfo,
				Message: "Initial Access Token not found",
			})
			writeInvalidToken(w, deps.Issuer, "Initial Access Token is invalid")
			return iatVerification{}, false
		}
		deps.logger().Error("dcr.iat.lookup_failed", "err", err)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return iatVerification{}, false
	}
	if expired := rec.ExpiresAt.Before(deps.now()); expired {
		deps.audit().Emit(ctx, audit.Event{
			Name:    auditDCRIATExpired,
			Level:   audit.LevelInfo,
			Message: "Initial Access Token expired",
			Tag:     rec.Tag,
		})
		writeInvalidToken(w, deps.Issuer, "Initial Access Token has expired")
		return iatVerification{}, false
	}
	ceiling := rec.MaxUses
	if ceiling == 0 {
		ceiling = 1
	}
	if rec.Uses >= ceiling {
		// Pre-flight check before IncrementUses; the atomic ceiling
		// enforcement still happens in IncrementUses to defend against
		// the read-modify-write race. We surface the WARN here so the
		// audit trail flags repeated reuse attempts.
		deps.logger().Warn("dcr.iat.consumed", "tag", rec.Tag)
		deps.audit().Emit(ctx, audit.Event{
			Name:    auditDCRIATConsumed,
			Level:   audit.LevelWarn,
			Message: "Initial Access Token already consumed",
			Tag:     rec.Tag,
		})
		writeInvalidToken(w, deps.Issuer, "Initial Access Token has been consumed")
		return iatVerification{}, false
	}
	return iatVerification{Token: rec}, true
}

// consumeIAT atomically increments the IAT's Uses counter. It is
// called after structural validation has passed but before the client
// is persisted; a [store.ErrConflict] surfaces as a 400 invalid_token
// race02-product-design.md §A.6.2.2.
// On success the function returns ok=true; on any failure it writes
// the response envelope and returns ok=false.
func consumeIAT(ctx context.Context, w http.ResponseWriter, deps Deps, ver iatVerification) bool {
	if ver.Open {
		return true
	}
	if ver.Token == nil {
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return false
	}
	if _, err := deps.InitialAccessTokens.IncrementUses(ctx, ver.Token.ID); err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			deps.logger().Warn("dcr.iat.consumed", "tag", ver.Token.Tag, "reason", "race")
			deps.audit().Emit(ctx, audit.Event{
				Name:    auditDCRIATConsumed,
				Level:   audit.LevelInfo,
				Message: "Initial Access Token race lost",
				Tag:     ver.Token.Tag,
			})
			writeInvalidToken(w, deps.Issuer, "Initial Access Token race")
		case errors.Is(err, store.ErrNotFound):
			writeInvalidToken(w, deps.Issuer, "Initial Access Token revoked")
		default:
			deps.logger().Error("dcr.iat.increment_failed", "err", err)
			writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		}
		return false
	}
	return true
}

// bearerFromHeader extracts the Bearer credential from the
// Authorization header value, case-insensitively matching the scheme
// per RFC 6750 §2.1. The second return reports whether a Bearer
// credential was present at all.
func bearerFromHeader(value string) (string, bool) {
	const prefix = "Bearer "
	if len(value) <= len(prefix) {
		return "", false
	}
	if !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(value[len(prefix):])
	if tok == "" {
		return "", false
	}
	return tok, true
}
