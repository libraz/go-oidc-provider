// Package discovery serves the OpenID Connect Discovery 1.0 metadata
// document at /.well-known/openid-configuration. The document is built once
// at startup from the validated [op.Provider] configuration; it is fully
// static for the lifetime of the process so the handler can hand back a
// pre-marshalled byte slice on every request.
//
// Rotation of fields that depend on runtime state (newly-published keys,
// dynamically-registered scopes) lives in higher-level layers; the document
// here tracks only the configuration handed to op.New.
package discovery
