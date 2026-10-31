// Package ssf implements the transmitter side of the Shared Signals
// Framework 1.0: CAEP and RISC security events and the SSF control
// events, carried as Security Event Tokens (RFC 8417) to receivers that
// are OAuth clients of this OP.
//
// The queue holds unsigned claims, not signed tokens. [Transmitter]
// builds the claims and enqueues them; delivery (push or poll) signs
// them with the key that is active at that moment through [Sign], so a
// retry keeps its jti while a key rotation never strands a queued SET
// under a retired kid.
//
// An event reaches a receiver when the subject holds a grant for the
// receiver's client and the receiver's stream delivers that event type.
// The subject in sub_id is projected per client with the same projector
// back-channel logout uses, so pairwise deployments never leak one
// client's subject to another. No session member is emitted.
package ssf
