package argon2id

import (
	"runtime"

	"golang.org/x/crypto/argon2"
)

// Key derives an Argon2id key, admitting at most
// [MaxConcurrentDerivations] callers at a time. It is the only place in
// the module that invokes the underlying derivation; a depguard rule
// keeps golang.org/x/crypto/argon2 unimportable outside this package so
// a future call site cannot acquire the cost without the gate.
//
// # Why a gate exists
//
// Argon2id is memory-hard on purpose: at the library's parameters
// (m=64 MiB, t=3) one derivation allocates 64 MiB and holds it for the
// ~90 ms it runs. Offline, that is the cost an attacker pays per guess,
// and it is the feature. Online, it is a cost the server pays per
// request — and the constant-time posture that makes credential
// rejection safe guarantees a caller holding no valid credential pays
// exactly what a legitimate one does. Both properties are correct and
// neither is negotiable, but together they mean an unauthenticated
// request can commit the process to 64 MiB.
//
// Ungated, peak memory is therefore (requests in flight) × 64 MiB, a
// figure the caller sets rather than the operator. Gated, it is
// (slots) × 64 MiB, a constant fixed at start-up. That is the whole of
// the change: the derivation cost is not reduced, and no request is
// refused. Work that would have thrashed is queued instead.
//
// # Why the capacity is GOMAXPROCS
//
// A p=1 derivation is one CPU-bound goroutine, so admitting more of
// them than there are threads to run them cannot raise throughput.
// BenchmarkDerivationConcurrency measures the curve and finds exactly
// that — it rises to GOMAXPROCS and flattens, while peak heap keeps
// climbing — so GOMAXPROCS is the smallest capacity that gives up no
// throughput. Deriving it from the runtime rather than a constant also
// makes it track a container's CPU limit, which is the same budget the
// memory limit is usually sized against.
//
// The value is read once at start-up. A program that reshapes
// [runtime.GOMAXPROCS] afterwards keeps the original capacity; nothing
// in the library does, and re-reading it per derivation would let one
// misconfigured call widen the bound the gate exists to hold.
//
// # Why callers wait rather than fail
//
// Refusing over capacity would make server load an outcome the caller
// can observe and steer, and there is no wire code that honestly says
// "your credentials might be fine, the OP is busy" — every candidate
// would report a credential problem and teach clients to retry against
// the wrong axis. Waiting reorders the work instead of adding to it:
// the queued goroutine costs kilobytes against the 64 MiB it is waiting
// to allocate, and the CPU it is waiting for is already committed to a
// derivation, so the total time to serve a burst is unchanged.
//
// The wait is not cancellable. A gate that released some callers early
// would hand back a fast, distinguishable rejection on a path whose
// entire purpose is to be indistinguishable, and it would do so
// precisely under the load an attacker can create. Bounding how many
// requests may be in flight at all is a different control, and one the
// library deliberately leaves to the embedder's proxy or gateway along
// with the rest of the HTTP request lifecycle.
//
// # Why the timing shims are gated too
//
// The dummy derivations that equalise rejection cost run through this
// function like everything else, and must. Gating only the real verify
// would mean that under contention a real verify waits for a slot while
// an unknown-client rejection does not — which is the client-existence
// timing oracle again, rebuilt out of the fix for it and readable
// whenever the OP is busy.
func Key(password, salt []byte, iterations, memory uint32, parallelism uint8, keyLength uint32) []byte {
	derivationSlots <- struct{}{}
	defer func() { <-derivationSlots }()
	return argon2.IDKey(password, salt, iterations, memory, parallelism, keyLength)
}

// Version is the Argon2 version number the underlying implementation
// derives under, re-exported so the packages that render a PHC encoding
// can name it without importing the derivation library the depguard
// rule keeps behind this package.
const Version = argon2.Version

// MaxConcurrentDerivations reports how many [Key] calls may run at
// once. Multiplied by the configured memory cost it is the process's
// ceiling on Argon2id working memory, so operators sizing a memory
// limit and tests asserting the bound read the same number.
func MaxConcurrentDerivations() int { return cap(derivationSlots) }

// derivationSlots is the gate [Key] acquires. A buffered channel is the
// whole mechanism: a send blocks once the buffer is full, and the
// deferred receive releases the slot even if the derivation panics.
//
//nolint:gochecknoglobals // process-wide by definition: the bound is on the process, not a call tree.
var derivationSlots = make(chan struct{}, defaultDerivationCapacity())

// defaultDerivationCapacity returns the gate's capacity: one slot per
// schedulable thread, and never fewer than one — a zero-capacity
// channel would block the first caller forever, turning a bound meant
// to protect availability into a total loss of it.
func defaultDerivationCapacity() int {
	if n := runtime.GOMAXPROCS(0); n > 1 {
		return n
	}
	return 1
}
