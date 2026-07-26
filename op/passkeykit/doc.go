// Package passkeykit is the embedder-facing facade for WebAuthn
// passkey enrolment. It complements [op.PrimaryPasskey], which drives
// the assertion during login, with the registration ceremony: turning a
// navigator.credentials.create() response into a
// [store.PasskeyRecord] the embedder persists through
// [store.PasskeyStore.Put].
//
// # When to use this package
//
// Use passkeykit when an embedder builds an "add a passkey" screen.
// The package owns the challenge, the exclude list that stops a device
// registering twice, the attestation checks, and the projection onto
// the persistent record. It does NOT own the login path — that lives in
// [op.PrimaryPasskey] and the orchestrator's login-flow dispatcher.
//
// The package stays out of the HTTP surface. An embedder who wants a
// "Register this device" button composes their own two handlers; the
// package supplies the challenge to send and the record to store.
//
// # One configuration, both ceremonies
//
// [New] takes the very [op.PrimaryPasskey] value the embedder installs
// on its [op.LoginFlow]. That is the whole point of the signature: a
// credential is bound to the Relying Party identity it was registered
// under, so an enrolment configured with a different RPID or a
// different origin list produces credentials the login step will never
// accept — and it fails silently, at first login, long after the
// registration screen reported success. Sharing one value makes the
// drift unrepresentable:
//
//	passkeys := op.PrimaryPasskey{
//	    Store:                 st.Passkeys(),
//	    RPID:                  "id.example.com",
//	    RPDisplayName:         "Example Identity",
//	    RPOrigins:             []string{"https://id.example.com"},
//	    CloneDetectionHandler: myHandler{},
//	}
//	registrar, err := passkeykit.New(passkeys) // enrolment
//	flow := op.LoginFlow{Primary: passkeys}    // login
//
// [op.PrimaryPasskey.CloneDetectionHandler] is the one field passkeykit
// ignores: a clone warning is a sign-counter comparison against a prior
// assertion, and a credential being registered has no prior assertion.
//
// # Lifecycle
//
//  1. The user reaches the embedder's account page and has already
//     authenticated. passkeykit does not authenticate anyone; a
//     registration handler reachable without a session lets an attacker
//     add their own authenticator to someone else's account.
//  2. The embedder calls [Registrar.Begin] with the [User] being
//     enrolled. It returns the [CreationOptions] to hand the SPA and a
//     [Session] to keep.
//  3. The embedder ferries the Session to the finish request — an
//     encrypted cookie or a server-side row keyed by a short-lived
//     identifier. It MUST be integrity-protected; see below.
//  4. The SPA calls navigator.credentials.create() with the options and
//     posts the resulting credential's toJSON() form back.
//  5. The embedder calls [Registrar.Register] with the same Session and
//     User plus the posted bytes. On success the credential is stored
//     and usable at the next login.
//
// [Registrar.Finish] is the variant that verifies without persisting,
// for a caller that writes the record inside a transaction it owns.
//
// # Session handling
//
// The [Session] is opaque and carries the challenge, the user handle,
// and an expiry. Two properties matter:
//
//   - It MUST NOT be sent to the browser as part of the creation
//     options. [Registrar.Begin] returns the two separately so that a
//     handler which marshals its result wholesale cannot leak one into
//     the other.
//   - It MUST be integrity-protected in transit. A caller that lets the
//     browser hand back an arbitrary session lets it choose the user
//     handle the ceremony binds. [Registrar.Finish] refuses a session
//     whose handle disagrees with the [User.Subject] it was given, so
//     the attack needs both halves; that check is a backstop, not a
//     licence to ferry the session unprotected.
//
// A Session is single-use. Drop it as soon as the finish call returns,
// whether it succeeded or not: replaying one replays its challenge,
// which is the defence WebAuthn spends the round trip to establish.
//
// # Concurrency
//
// A [Registrar] is immutable after construction and safe for concurrent
// use; build one at startup and share it. A [Session] belongs to one
// enrolment and MUST NOT be shared across requests.
//
// Stable since v1.0.
package passkeykit
