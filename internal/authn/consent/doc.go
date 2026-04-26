// Package consent implements the OP's built-in consent screen as an
// [authn.Interaction]. The interaction runs at [authn.TriggerAfterAuthn],
// once the chain has bound a subject, and asks the user to approve a
// subset of the relying party's requested scope set.
//
// # Wiring
//
// The interaction is auto-registered by [op.New]: when the configured
// orchestrator is non-nil, the OP prepends a [*Interaction] built from
// the registered scope catalogue to the user-supplied
// [op.WithInteractions] slice. The HTTP layer pre-marks
// [authn.State.InteractionsRun] for the consent name when an existing
// grant already covers the requested scope, which lets the orchestrator
// skip the screen without re-running the catalogue lookup.
//
// # Result shape
//
// On a successful Continue, the interaction returns
// [interaction.Result.Scope] populated with the user-approved subset.
// The orchestrator records the slice on [authn.State.ApprovedScopes];
// the terminal [authn.Tick] result echoes the value so the
// authorize-endpoint terminate path can mint the authorization code
// against the approved subset rather than the full request set.
//
// # Wire format
//
// The Continue submission carries the approved scopes as a
// space-delimited string under the [ApprovedScopesField] key. The format
// mirrors the OAuth scope-string convention so the SPA can re-emit the
// same separator the request used; an empty value approves no optional
// scopes (required scopes still gate the chain).
package consent
