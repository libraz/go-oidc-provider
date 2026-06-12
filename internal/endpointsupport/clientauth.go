// Package endpointsupport collects helpers that the OP's HTTP endpoints
// share. The package exists to deduplicate the near-identical client
// authentication, bearer extraction, audit-emit, and error-response code
// paths that the introspect / revoke / registration / userinfo handlers
// were each carrying their own copies of. The helpers stay deliberately
// orthogonal: each endpoint composes them the way its wire contract
// requires, rather than calling a single "do everything" function whose
// behaviour depends on a half-dozen flags.
//
// The package only depends on net/http, internal/audit, internal/clientauth,
// internal/httpx, and op/store so it can be imported from any endpoint
// package without an import cycle.
package endpointsupport

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
)

// AuthenticateOpts bundles the configuration the [AuthenticateClient]
// helper needs. Each endpoint supplies its own value once at startup;
// the helper is otherwise stateless.
type AuthenticateOpts struct {
	// Clients is the read-only client registry consulted to resolve the
	// id carried by the credentials. A nil value collapses every request
	// onto the "client not found" path so a misconfigured handler never
	// silently accepts a request.
	Clients store.ClientStore

	// SecretVerifier verifies confidential-client secrets. A nil value
	// installs the library default ([clientauth.Argon2id]).
	SecretVerifier clientauth.SecretVerifier

	// AssertionVerifier verifies private_key_jwt assertions. A nil value
	// disables private_key_jwt support: requests that arrive with a
	// "client_assertion" parameter are rejected as invalid_client.
	AssertionVerifier clientauth.AssertionVerifier

	// AllowedMethods optionally restricts which client authentication
	// methods the endpoint accepts. An empty slice admits every method
	// the parser supports.
	AllowedMethods []clientauth.Method
}

// AuthenticateClient resolves the client credentials carried by the
// request, looks the client up in opts.Clients, and verifies the
// credentials. The function is the consolidated form of the
// authenticate() helpers that introspect / revoke each carried — the
// caller layers in audit hooks (via [EmitAuthnFailure]) according to
// its own audit contract.
//
// On every failure path the helper writes the response envelope (via
// [WriteAuthnError]) and returns ok=false so the caller only checks
// the bool. On success the resolved [*store.Client] and [*clientauth.Credentials]
// are returned and the caller proceeds.
//
// usedBasic mirrors the value the handler computes from
// r.Header.Get("Authorization"); it is hoisted here because the caller
// typically needs it for its own audit reasoning before invoking the
// helper.
func AuthenticateClient(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	opts AuthenticateOpts,
	onFailure func(creds *clientauth.Credentials, err error),
) (*store.Client, *clientauth.Credentials, bool) {
	creds, err := clientauth.Parse(r)
	usedBasic := usedBasicAuth(r)
	if err != nil {
		if onFailure != nil {
			onFailure(nil, err)
		}
		WriteAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	if creds.Method == clientauth.MethodPrivateKeyJWT && opts.AssertionVerifier == nil {
		if onFailure != nil {
			onFailure(creds, errPrivateKeyJWTDisabled)
		}
		WriteInvalidClient(w, usedBasic, "private_key_jwt is not enabled")
		return nil, nil, false
	}
	client, err := LookupClient(ctx, opts.Clients, creds.ClientID)
	if err != nil {
		if onFailure != nil {
			onFailure(creds, err)
		}
		WriteAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	verifier := opts.SecretVerifier
	if verifier == nil {
		verifier = &clientauth.Argon2id{}
	}
	if _, err := clientauth.VerifyClient(ctx, creds, client, clientauth.VerifyOpts{
		SecretVerifier:    verifier,
		AssertionVerifier: opts.AssertionVerifier,
		AllowedMethods:    opts.AllowedMethods,
	}); err != nil {
		if onFailure != nil {
			onFailure(creds, err)
		}
		WriteAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	return client, creds, true
}

func usedBasicAuth(r *http.Request) bool {
	if r == nil {
		return false
	}
	scheme, _, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	return ok && strings.EqualFold(scheme, "Basic")
}

// errPrivateKeyJWTDisabled is the sentinel surfaced via the audit hook
// when a request presents a private_key_jwt assertion at an endpoint
// whose [AuthenticateOpts.AssertionVerifier] is nil. The wire response
// stays at the canonical invalid_client envelope; the audit reason
// string lets SOC tooling distinguish "disabled" from "malformed".
var errPrivateKeyJWTDisabled = errors.New("private_key_jwt is not enabled")

// IsPrivateKeyJWTDisabled reports whether err is the sentinel
// [AuthenticateClient] passes to onFailure when private_key_jwt is not
// configured. Callers that translate the failure into an audit reason
// code use this rather than comparing the error string directly.
func IsPrivateKeyJWTDisabled(err error) bool {
	return errors.Is(err, errPrivateKeyJWTDisabled)
}

// LookupClient resolves the registered client for id, mapping
// [store.ErrNotFound] to [clientauth.ErrCredentialsInvalid] so the
// caller cannot tell "unknown client" apart from "wrong secret"
// through the error surface.
//
// An empty id collapses onto ErrCredentialsInvalid for the same reason:
// a probe that omits the id should look identical to a probe that
// supplies a wrong one.
func LookupClient(ctx context.Context, clients store.ClientStore, id string) (*store.Client, error) {
	if id == "" || clients == nil {
		return nil, clientauth.ErrCredentialsInvalid
	}
	c, err := clients.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, clientauth.ErrCredentialsInvalid
		}
		return nil, err
	}
	return c, nil
}

// ReasonForAuthnError maps a clientauth sentinel onto the short reason
// code endpoints emit on audit events. The codes match the clientauth
// error names so a reader can grep from an audit line back to the
// failing branch in the verifier. The catalogue is closed; an unknown
// error collapses onto "server_error".
func ReasonForAuthnError(err error) string {
	switch {
	case errors.Is(err, clientauth.ErrNoCredentials):
		return "no_credentials"
	case errors.Is(err, clientauth.ErrAmbiguousCredentials):
		return "ambiguous_credentials"
	case errors.Is(err, clientauth.ErrUnsupportedMethod):
		return "unsupported_method"
	case errors.Is(err, clientauth.ErrClientMismatch):
		return "client_mismatch"
	case errors.Is(err, clientauth.ErrCredentialsInvalid):
		return "invalid_client_credentials"
	case errors.Is(err, clientauth.ErrAssertionMalformed):
		return "assertion_malformed"
	case errors.Is(err, clientauth.ErrAssertionReplayed):
		return "assertion_replayed"
	case IsPrivateKeyJWTDisabled(err):
		return "private_key_jwt_disabled"
	default:
		return "server_error"
	}
}

// EmitAuthnFailure raises an audit event for a pre-authentication
// failure. The helper is the consolidated form of the per-endpoint
// emit functions: callers pass their event name, the resolved
// client_id (when known), and the underlying error. A nil sink
// collapses onto [audit.Discard] so handlers can call the helper
// unconditionally without a nil-check.
//
// The wire response stays at the RFC 6749 §5.2 canonical shape; the
// audit event surfaces the attempted client_id and a short reason
// code for SOC tooling.
func EmitAuthnFailure(
	ctx context.Context,
	emitter audit.Emitter,
	eventName, message, clientID string,
	err error,
	method ...string,
) {
	if emitter == nil {
		emitter = audit.Discard()
	}
	extras := map[string]any{"reason": ReasonForAuthnError(err)}
	if len(method) > 0 && method[0] != "" {
		extras["method"] = method[0]
	}
	emitter.Emit(ctx, audit.Event{
		Name:     eventName,
		Level:    audit.LevelWarn,
		Message:  message,
		ClientID: clientID,
		Extras:   extras,
	})
}
