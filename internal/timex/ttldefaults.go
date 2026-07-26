package timex

import "time"

// This file is the single canonical home for the library-wide default
// TTL durations. Every package that needs a TTL fall-back imports the
// constant from here rather than re-declaring its own value, so a
// change to the operational posture moves through one diff and the pin
// test in [ttldefaults_test.go] catches a silent regression.
//
// Each constant documents the spec or operational rationale it
// inherits. The values are intentionally small, well-known
// durations (24 h, 14 days, 30 days) chosen so an operator who reads
// the boot log can map a TTL back to its source without consulting
// the source tree.

// RefreshTokenTTLDefault is the absolute lifetime applied to issued
// refresh tokens when the embedder does not override the value through
// [op.WithRefreshTokenTTL]. Thirty days mirrors the typical
// "long-lived but bounded" posture for authorization-code-derived
// refresh tokens; embedders facing stricter risk profiles shorten the
// value through the public option.
const RefreshTokenTTLDefault = 30 * 24 * time.Hour

// AccessTokenTTLMax is the implementation-defined upper bound the
// option layer enforces on [op.WithAccessTokenTTL]. The value (24
// hours) is generous enough that an embedder running an internal API
// behind the OP can pick a TTL aligned with their session lifetime
// while still rejecting obviously-wrong inputs (multi-day or
// multi-year) that produce tokens whose practical invalidation
// requires the per-grant revocation pathway. The bound composes with
// profile-supplied caps: a configured FAPI profile pulls the bound
// down to its 10-minute limit ([op/profile.MaxAccessTokenTTL]) and
// the more-restrictive value wins.
const AccessTokenTTLMax = 24 * time.Hour

// RegistrationIATTTLDefault is the validity window applied to an
// Initial Access Token (RFC 7591) when the embedder leaves
// [op.RegistrationOption.IATTTL] at its zero value. Twenty-four hours
// is short enough that an exfiltrated IAT cannot be replayed for long
// while still spanning a typical onboarding window.
const RegistrationIATTTLDefault = 24 * time.Hour

// SectorURICacheTTLDefault is the cache TTL applied to a successful
// sector_identifier_uri fetch (OIDC Core 1.0 §5). Twenty-four hours
// matches the OIDC informative recommendation; the SHA-256 hash check
// on refresh catches mid-day changes so a longer TTL does not mask a
// rotation.
const SectorURICacheTTLDefault = 24 * time.Hour

// SessionIdleTTLDefault is the default idle window applied to the
// __Host-oidc_session cookie when no override is configured. Fourteen
// days matches the library's operational baseline; activity refreshes
// the expiry up to [SessionAbsoluteTTLDefault].
const SessionIdleTTLDefault = 14 * 24 * time.Hour

// SessionAbsoluteTTLDefault caps the total wall-clock lifetime of an
// interactive session regardless of idle refreshes. Once
// CreatedAt+SessionAbsoluteTTLDefault is in the past the session is
// torn down so a hijacked cookie cannot be kept alive indefinitely by
// a busy client. Thirty days matches the upper bound mass-market RPs
// expect from a stay-signed-in cookie.
const SessionAbsoluteTTLDefault = 30 * 24 * time.Hour
