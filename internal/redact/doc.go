// Package redact wraps a [slog.Handler] so that sensitive attributes
// the OAuth/OIDC stack inevitably names (access_token, refresh_token,
// id_token, code, code_verifier, client_secret, password, state,
// nonce, dpop, authorization, cookie, set-cookie) are replaced with a
// fixed sentinel before they reach the underlying handler.
//
// The wrapper operates on attribute keys, not on values, so a
// well-behaved caller that uses [slog.String]("access_token", v) is
// covered automatically. Free-form messages and URLs that embed
// sensitive query parameters can be passed through [Mask] before
// logging; the helper rewrites the recognised key=value pairs in
// place.
//
// The redactor intentionally errs toward over-masking: false
// positives (a benign field accidentally named "code") merely lose
// observability, while a false negative could expose a token to log
// pipelines that v1.0 cannot recall. New keys go through the
// [Sensitive] catalogue so the audit boundary stays auditable.
package redact
