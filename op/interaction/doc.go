// Package interaction defines the contract between the [op.Provider] and the
// caller-supplied UI that drives login, consent, and account-selection
// prompts. The library performs every protocol-visible decision; the Driver
// implementation only owns the user-facing surface.
//
// The contract is intentionally narrow: the library owns every decision and
// hands the [Driver] one [Prompt] at a time to render, then takes the reply
// back as a [FormSubmission]. It learns nothing about the rendering
// technology. Two layouts ship:
//
//   - SPA ([op.SPAUI]): the OP serves the front end's shell and the
//     JSON endpoint LoginMount + "/state/{uid}". GET returns the current
//     [Prompt] as JSON (snake_case members; [FieldKind] as text); POST
//     submits a [FormSubmission] and returns the next prompt or a terminal
//     envelope.
//   - HTML ([HTMLDriver], the default): the OP renders each prompt as a
//     server-side form at /interaction/{uid} and parses the form-encoded
//     reply, with no script on the page.
//
// Stable since v1.5.
package interaction
