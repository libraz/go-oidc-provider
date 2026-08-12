// Package oidcdynamo is the DynamoDB storage adapter for
// go-oidc-provider. It implements every substore in
// [github.com/libraz/go-oidc-provider/op/store], including
// [store.Transactional], so a deployment can run the OP — browser
// authorization-code flow included — on DynamoDB alone.
//
// Experimental: the adapter's construction and option surface has had
// no production exposure and may change in a minor release. The substore
// behaviour itself is pinned by the same op/store/contract harness the
// SQL and in-memory adapters run against, so it is not provisional.
//
// # Construction
//
// The embedder owns the AWS client, its credentials, and its region;
// the adapter only issues requests through it:
//
//	cfg, err := config.LoadDefaultConfig(ctx)
//	store, err := oidcdynamo.New(dynamodb.NewFromConfig(cfg))
//
// [Store.CreateTables] provisions the tables for development and tests.
// Production deployments are expected to drive table creation through
// their own infrastructure tooling; [Store.TableDefinitions] returns the
// same definitions so they can be translated into CloudFormation, CDK,
// or Terraform without guessing at key schemas.
//
// # Item layout
//
// Each substore owns one table. An item carries its key attributes, the
// attributes any index or condition expression needs, a TTL attribute,
// and the record itself as a JSON document under a single attribute.
// Projecting only the queried attributes keeps the mapping readable and
// keeps a record-shape change from requiring a table migration. Most
// transitions use projected attributes; the MFA tables additionally bind
// the opaque document in their CAS predicates so legacy rows and
// delete/recreate ABA lifecycles cannot pass an old snapshot.
//
// # Expiry
//
// The TTL attribute lets DynamoDB reclaim storage, but expiry is always
// enforced on read against the injected clock. DynamoDB deletes expired
// items asynchronously — AWS documents "typically within 48 hours" —
// so an expired authorization code is routinely still present in the
// table, and treating TTL as the enforcement point would leave it
// redeemable.
//
// Refresh-token items carry a TTL at their own expiry, which means the
// oldest record of an actively rotating chain is reclaimed while its
// descendants are still redeemable. That is safe because the OP's
// replay-revocation walk stops at the deepest record it can resolve and
// cascades from there: records go oldest-first, so every token a replay
// could still spend hangs below the boundary. The adapter deliberately
// does not extend the TTL to cover the chain — a chain a client keeps
// refreshing has no bound, so the only retention that would always
// suffice is no retention limit at all.
//
// # Consistency
//
// Every read that feeds a security decision is a strongly consistent
// GetItem. Index queries cannot be strongly consistent, so enumeration
// paths re-read each item consistently before acting on it.
//
// # Atomicity
//
// No unguarded write in the adapter is a "read, decide, put back": every
// decision a record encodes is guarded by a conditional write. A bounded
// read followed by a conditional replacement is used where the predicate
// needs the complete MFA document, and a stale reader still loses.
//
// The brute-force counters — device-code user_code strikes and the
// poll-violation counters of the device and CIBA flows — are projected
// beside the document and incremented with a single conditional ADD, so
// a burst of parallel guesses is recorded as a burst rather than as one
// attempt. State transitions on those records update the attributes
// they change instead of replacing the item, so a transition in flight
// cannot roll a counter back.
//
// A refresh rotation that carries a retry response (RFC 9700's delivery
// grace window) writes the successor and the cached response as one
// TransactWriteItems. A successor that survived a failed cache write
// would send the client's legitimate retry down the replay path.
//
// A grant tombstone widens under two guarded updates, one per horizon,
// so parallel revocation cascades against one grant converge on the
// latest revocation instant and the longest retention rather than on
// whichever cascade happened to write last. A narrowed window would
// restore access tokens the other cascade had just killed.
//
// A grant record carries a version. Grants are amended rather than
// replaced — a repeat authorization adds to what the grant already
// held — so a write staged inside a transaction asserts that the
// version it amended is still stored, and a transaction that lost the
// race fails with [github.com/libraz/go-oidc-provider/op/store.ErrConflict]
// instead of dropping the other authorization's additions. Every direct
// write advances the version through the service's own increment.
//
// # Transactions
//
// DynamoDB has no interactive transaction, so a substore handle obtained
// from [Store.BeginTx] buffers its writes and Commit replays them as one
// TransactWriteItems; reads through the handle consult the buffer first,
// which is what makes a handler observe its own staged work. Nothing a
// transaction stages reaches the table before Commit, so a Rollback —
// or a request that simply fails — leaves no trace.
//
// The buffer inherits the call's ceiling of 100 actions. Ordinary
// transactions stay far below it, but a revocation cascade stages one
// action per record it retires, so a rotation chain or a grant with more
// stored tokens than the ceiling reports [ErrTransactionTooLarge] from
// the call that overflowed the buffer, having written nothing. The same
// cascade outside a transaction has no ceiling: it issues one guarded
// update per record and converges, at the cost of no longer being
// undoable.
//
// A cascade enumerates its targets through a secondary index, which
// cannot see staged writes, so it covers the records committed when it
// runs. A descendant written afterwards is caught by the parent-alive
// re-check every rotation makes.
//
// # Uniqueness
//
// DynamoDB enforces uniqueness on the primary key and nowhere else: a
// secondary index cannot be a constraint, and checking one before
// writing leaves a window in which two writers both find a value free.
// Where the library needs a second unique identifier, the value is
// therefore claimed as a reservation item under its own key, written in
// the same transaction as the record it points at.
//
// Device-code records claim their user_code under "uc#<user_code>", and
// the user-facing device flow resolves through the reservation, so an
// approval always lands on exactly one record. A reservation expires
// with the record it belongs to, which is what releases a user code for
// re-issue.
//
// [Store.PutUserWithPassword] claims a username under
// "username#<username>", pointing at the subject that holds it, and
// reports [github.com/libraz/go-oidc-provider/op/store.ErrAlreadyExists]
// when another subject already has it. A directory populated by the
// embedder's own tooling carries no reservations: FindByUsername falls
// back to the username index for those entries, and their uniqueness is
// the writer's to enforce. Subjects must not begin with the reservation
// prefix; the seed helpers reject one that does.
package oidcdynamo
