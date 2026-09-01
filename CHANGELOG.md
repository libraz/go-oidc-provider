# Changelog

`v0.9.0` is the initial public release of go-oidc-provider. Notable changes
in subsequent releases are tracked here in
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Read the `Changed` / `Removed` sections of each release for the migration
notes before upgrading: pre-v1.0 minor releases (including the `v0.9.x`
series) carry breaking changes, and `v1.1.0` carries several on the stable
surface as well — chiefly the `op/store` interfaces a bring-your-own store
implements. An embedder on `op.New` plus a bundled storage adapter compiles
unchanged; one that implements its own `store.*`, `op.HintResolver`,
`op.SubjectGenerator` or `op.CaptchaVerifier` does not.

The main module and the storage-adapter sub-modules
(`op/storeadapter/sql`, `op/storeadapter/redis`, and from `v1.0.0`
`op/storeadapter/dynamodb`) share the same release tag. Embedders pull
each sub-module independently:

```
# v1.1.0 (latest)
go get github.com/libraz/go-oidc-provider@v1.1.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v1.1.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v1.1.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb@v1.1.0

# v1.0.0
go get github.com/libraz/go-oidc-provider@v1.0.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v1.0.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v1.0.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb@v1.0.0

# v0.9.5
go get github.com/libraz/go-oidc-provider@v0.9.5
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.5
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.5

# v0.9.4
go get github.com/libraz/go-oidc-provider@v0.9.4
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.4
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.4

# v0.9.3
go get github.com/libraz/go-oidc-provider@v0.9.3
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.3
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.3

# v0.9.2
go get github.com/libraz/go-oidc-provider@v0.9.2
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.2
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.2

# v0.9.1
go get github.com/libraz/go-oidc-provider@v0.9.1
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.1
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.1

# v0.9.0 (initial public release)
go get github.com/libraz/go-oidc-provider@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.0
```

## [Unreleased]

A security and correctness pass across the whole surface. Most of what changed
closes a path on which the OP answered without saying it had answered wrongly:
a consent screen skipped because somebody else had consented earlier, a refresh
chain that kept minting scopes the client's registration no longer names, a
storage adapter reporting a sign-out it had not performed.

Deployments that need to do something before upgrading: existing bundled-SQL
installations (three indexes and, on MySQL, a username collation change),
existing DynamoDB installations (an index leaves `TableDefinitions`), FAPI 2.0
deployments that configure `op.WithRefreshGracePeriod`, anyone whose
`op.LoginFlow` declares a rule with no `When` predicate, anyone whose
`op.LoginAttemptObserver` switches on the attempt outcome, anyone whose custom
`interaction.Driver` renders the recovery-code prompt's remaining-attempt
count, anyone serving a custom grant that returns a refresh token, and anyone
who implements their own `op/store` backend — the last of these both for the
tightened redemption contract and because `op/store/contract` carries one
signature change, which is the only breaking change in this release.

### Security

- The consent decision an authorization request rides on is re-evaluated
  against the subject the request actually ends on. Consent was marked as
  already covered at the door, from the grant belonging to whichever subject
  the session cookie named at the time, and every branch that re-runs
  authentication can bind a different subject afterwards: `prompt=login`, an
  elapsed `max_age`, an RFC 9470 step-up. So a user who signed in and consented
  to `openid profile email`, followed by a relying party sending
  `prompt=login`, followed by a *different* person authenticating at the
  password screen, handed that second person an authorization code for the
  first person's whole scope set without a consent screen ever being drawn. The
  account chooser already carried a guard against exactly this, on exactly this
  reasoning; the re-authentication branches did not. The coverage predicate now
  re-runs at the terminal against the ending subject's own grant, and a subject
  with no covering grant fails closed. An answered ceremony is authoritative
  for the subject it ran under and is unaffected.

- `acr_values` naming a value outside `op.WithACRValuesSupported` is refused at
  `/authorize` and `/par`, not only at `/bc-authorize`. One option fed one
  discovery array read by three request surfaces, and only one of them enforced
  it, so a caller could ask for an authentication context the OP had never
  advertised and receive an id_token whose `acr` claim asserted it — and the
  fabricated value was persisted on `store.Session.ACR`, where it then answered
  later requests. Values arriving inline, replayed out of a PAR `request_uri`,
  and back-filled from `client.DefaultACRValues` are all covered. An empty
  advertised set keeps the previous verbatim pass-through on every surface, and
  `op.WithACRPolicy` still takes precedence.

- Authorization codes no longer reach the audit stream in redeemable form. The
  silent-issuance and interactive-completion paths wrote the code itself under
  the `code_id` and `completion_id` keys, so for the code's whole lifetime it
  was readable by everyone who can read logs — the aggregation tier, the SIEM,
  whoever is on call — which for a public client using plain PKCE is a direct
  account-takeover path. Both keys now carry `audit.Fingerprint` digests, which
  is what the token endpoint's own `code_id` has always carried, so the
  issued/consumed correlation still works and neither side publishes the
  credential.

- A refresh token's scope set is re-intersected with the client's current
  registration on every rotation. Narrowing a compromised client's registered
  `Scopes` took effect at `/authorize`, `/device_authorization` and
  `client_credentials` but not on the refresh grant, so a live chain kept
  minting access tokens at the original scope indefinitely and the only lever
  left was revoking the grant outright — a much blunter instrument than the
  registration edit the operator had just made. The check runs before the
  presented token is consumed, so a refused rotation spends nothing.

- A custom grant cannot issue a refresh token the same token endpoint would
  refuse to redeem. Issuance consulted only the client's registration, not the
  provider's `op.WithGrants` set, so a deployment that had turned
  `refresh_token` off and a custom grant on handed clients a credential that
  `/token` then rejected with `unsupported_grant_type`, accumulated
  unredeemable rows in the refresh store, and published a response body that
  contradicted its own discovery document. Both gates now run for built-in and
  custom grants alike, on first issuance and on rotation; a dropped refresh
  raises an audit event rather than passing silently.

- Token exchange honours a policy decision of `IssueIDToken: false`. The
  decision was computed and then discarded, because the custom-grant response
  had no field to carry it, so the id_token was emitted whenever `openid`
  survived in the granted scope — and that id_token carried neither the `act`
  chain nor the `cnf` binding of the access token beside it. A delegation
  client could launder an act-chained credential into a clean one and re-enter
  exchange with the `MaxActChainDepth` counter reset. `IssueRefreshToken`
  already had the symmetric field; the decision now travels the same way.

- `require_auth_time` is fail-closed on the custom-grant id_token path, as it
  already was for the four built-in grants. A client that registered the flag
  and gates session freshness on `auth_time` received an id_token with the
  claim silently omitted — `omitempty` turns an unresolved value into an absent
  member rather than a refusal — and absence reads as "fresh" to a relying
  party that expects the claim to always be there.

- A device-code or CIBA record that committed to more than one confirmation
  method is re-verified against all of them. The redemption checked whichever
  binding it found first, so a record carrying both a DPoP thumbprint and an
  mTLS `x5t#S256` was redeemable by a caller holding the DPoP key and a
  different client certificate — and the issued token's `cnf` then named the
  attacker's certificate, misrepresenting what the OP had actually verified.
  Token exchange already evaluated every populated method with a conjunction,
  and its comment says why; the two grant paths now do the same, and the `cnf`
  members stamped on the issued token describe only the methods re-verified on
  that request.

- A request carrying an empty `DPoP` header ahead of a real proof is refused
  rather than served as bearer. `/par`, `/token`, `/device_authorization` and
  `/bc-authorize` tested for a proof with `Header.Get`, which returns the first
  value, so an empty first occurrence read as "no proof presented" and the
  request fell through to the unbound path — a `200` with an unbound access
  token, and at `/par` a pushed record with no `dpop_jkt`, which made the whole
  subsequent `/authorize` → `/token` chain bearer. The verifier underneath had
  always applied the RFC 9449 §4.1 single-proof rule correctly; it was never
  reached. All four endpoints now decide presence by value count and hand every
  such request to the verifier, which rejects the multi-value case as
  `invalid_request`.

- A JAR `jti` replay marker is retained for no longer than an OP-configured
  ceiling. Retention was derived from the request object's own `exp`, so a
  single misbehaving registered relying party could grow the consumed-JTI table
  by one row per authorization request with no expiry an operator could wait
  out — unbounded shared-cache memory on Redis, an unreclaimable table on SQL.
  DPoP proofs and client assertions have always clamped this unconditionally
  and say why; JAR clamped only when a profile was active, and now clamps
  always.

- A JWK a relying party published with `use=enc` is not accepted as a signature
  verification key. Registration validation enforces the RFC 7517 §4.2
  separation, and the JAR request-object and `client_assertion` verifiers
  ignored it, so a client whose inline JWKS held one RSA encryption key could
  sign request objects and `private_key_jwt` assertions with it — the OP
  verifying against a key its owner had declared encryption-only, which made
  the registration-time check meaningless at runtime. Three sibling paths in
  the same codebase already applied the filter.

- `op.New` refuses a signing keyset whose active entry has already reached its
  `NotAfter`. An embedder who rotates by stamping the deadline at the rotation
  moment got a provider that constructed successfully and then failed to
  verify every token it had just signed, at `/userinfo`, `/introspect`,
  `/revoke`, token exchange and `/end_session` — a self-inflicted outage of the
  entire JWT access-token surface with no configuration error anywhere.
  `op/keyset.go` documented this hazard precisely; nothing enforced it.

- `RequireUserVerification` reaches the passkey registration ceremony, not only
  the login one. Registration ran at "preferred" regardless, so a roaming
  authenticator with no PIN was never asked for a user-verification gesture,
  registered successfully, and then failed every subsequent login because the
  assertion's UV flag was clear — enrolling a user in a credential they could
  not sign in with. The registration and login ceremonies now build from one
  configuration value, which is what `op/passkeykit` documents.

- `/end_session` does not report a sign-out it could not perform. The
  fail-secure reasoning already applied to a session *lookup* that failed did
  not apply to a *deletion* that failed: the OP cleared the cookie, rendered
  the signed-out page or redirected to `post_logout_redirect_uri`, and left the
  session row alive to its natural expiry, so an attacker holding a stolen
  cookie kept access across the victim's deliberate logout and only the audit
  stream recorded the truth. Such a request now answers 503 and keeps the
  cookie, so a retry can still name the session. Token and back-channel
  cascades stay non-blocking as before; only a failed session-row deletion
  changes the response.

- The `/end_session` HTML pages cannot be framed. The confirmation page carries
  a one-click sign-out that revokes the session, the grants and the tokens
  behind it, and it shipped without `X-Frame-Options: DENY` or
  `frame-ancestors 'none'` — so a same-site framer could redress the button and
  force the whole cascade, with the `SameSite=Lax` session cookie and the CSRF
  token both present inside the frame. Every other HTML surface the library
  renders already carried both headers, on a rule the project had written down
  itself.

- On MySQL, two conditional inserts report success only when they actually
  installed the caller's row. Both statements are structurally no-op updates on
  conflict, and a driver configured with `clientFoundRows=true` — a supported
  mode with its own regression coverage — reports matched rows rather than
  changed rows, so both read as won. For email OTP the effect was a functional
  break with an amplification tail: creation returned nil while the stale row
  stayed, so the code that was mailed could never verify and `send_count` never
  advanced, leaving an unbounded mail path against any known subject. For the
  cross-factor lockout it was an undercount: two racing failures each reported
  success and the counter advanced once.

- MySQL matches usernames byte for byte, as SQLite and PostgreSQL already did
  and as the adapter's own godoc has always promised. MySQL's default collation
  is case- and accent-insensitive, so `FindByUsername("ALICE")` resolved
  `alice` there and nowhere else, and two usernames differing only in case
  could not both exist. See **Changed** for the migration this needs.

- Grant management answers 5xx when the store could not tell it whether a grant
  exists. A transport failure resolving the grant was reported as
  `404 grant not found`, and a client revoking a grant for incident containment
  reads that as idempotent success and stops retrying — so the grant, its
  refresh chain and its access tokens survived the containment step. 404 is now
  reserved for a store that positively reported absence and for a grant owned
  by another client. The delete path's existing rule is unchanged: 204 only
  when the whole cascade completed.

- `SaveRotationWithRetry` keeps the rotation when the parent record has been
  reclaimed, which is what plain `Save` has always done. On the SQL and
  DynamoDB adapters the missing parent failed the whole call, so a deployment
  using `store.RefreshRetryResponseStore` lost the rotation — and returned a
  storage error to the client — whenever garbage collection removed the parent
  between `Consume` and the write. An absent parent is proof that no revocation
  happened; the retry-response cache is structurally optional and its absence
  is now treated as such.

- A large `max_age` is evaluated rather than overflowed. The freshness
  predicate converted the parameter to a `time.Duration`, and the wrap makes
  the comparison non-monotonic in both directions: some values force
  re-authentication on every request (a permanent `login_required` under
  `prompt=none`), and others — `max_age=99999999999`, for instance — make the
  freshness and step-up checks pass unconditionally, so an arbitrarily old
  session sails through. `max_age` is a query parameter, so the caller picks
  which band they land in. The entry check and the chooser's terminal re-check
  both compare instants in seconds now, and they were changed together.

### Fixed

- A silently issued authorization code reflects the `claims` parameter of the
  request that produced it. Two of the three grant-resolution paths already
  wrote the OIDC Core 1.0 §5.5 payload onto the grant and the third did not, so
  an RP that authorized once without `claims` and then asked for a specific
  projection got a `200` and a code whose grant still carried the older
  request — `/token` and `/userinfo` then returned no projection at all and
  nothing reported why. Discovery advertises `claims_parameter_supported` by
  default, which is what makes this a promise rather than a preference.

- A numeric `value` / `values` constraint in a `claims` request matches a claim
  the user store returned as `int64`. The comparison only ran when both sides
  were `json.Number`, and the request side always is while the store side is
  whatever the embedder's `store.User.Claims` holds, so
  `{"updated_at":{"essential":true,"value":1699999999}}` never matched and the
  essential claim vanished from the id_token with no error. Both sides are now
  normalised before comparison, which is what `ClaimSpec.Allows` documented.

- A chooser selection whose subject no longer matches the terminal subject ends
  the interaction instead of looping. The mismatch is permanent — that grant's
  subject will never match — but it fell into the retryable arm, so the user
  met a 500 that reproduced on every reload, with the ceremony cookie alive and
  the completed chain still on disk, escapable only by deleting the record by
  hand. It is now a terminal failure that claims the record and clears the
  cookie, alongside the two sentinels already wired that way. A genuine store
  fault stays retryable.

- One resource-indicator normalisation decides every surface. Two copies had
  been made for the custom-grant paths and neither stripped default ports or
  refused fragments and userinfo, so a client registered for
  `https://api.example.com:443/v1/` was accepted at `client_credentials` and
  refused with `invalid_target` at token exchange, for the same string. The
  canonical package says in its own header that every endpoint taking
  `resource` must go through it; the copies are gone.

- An authorization-code exchange that fails after minting retires only the
  opaque access token it just minted. It called `RevokeByGrant`, and grants are
  reused per (subject, client), so a relying party whose id_token encryption
  JWKS was briefly unreachable — refreshing with `prompt=none`, failing at the
  JWE step — took down the still-valid access tokens from its *previous*
  successful exchange, and every in-flight API call with them. The device-code
  and CIBA paths already used `RevokeByID`. The tombstone-refusal branch keeps
  its grant-wide revocation, which is the case it exists for.

- A custom grant that returns an empty `Scope` with `IssueRefreshToken: true`
  answers with its access token instead of `500`. Three sibling conditions —
  ineligible client, empty subject, multi-resource audience — already dropped
  the refresh token and raised an audit event, on the documented rule that
  asking for a refresh token on an ineligible grant is not an error; the fourth
  structural precondition of the refresh issuer was missing, so the whole
  response was discarded over something the client had done nothing wrong to
  cause.

- A replayed TOTP submission does not spend the cross-factor lockout budget. The
  verifier separates a replay from a wrong guess and says in its own comment
  that a replay must not punish a legitimate user, but the result it returned
  could not express the distinction, so the authenticator recorded a failure
  either way — a double-submitted form or a browser retry on a flaky connection
  walked the user toward the lockout the guard exists to avoid. The sibling
  email-OTP factor had already separated the two.

- RFC 7592 client management is reachable under an issuer that carries a path.
  The handler classified management requests against the mount prefix without
  the issuer's path component, so on a multi-tenant deployment every `GET` /
  `PUT` / `DELETE` an RP made against the `registration_client_uri` the OP
  itself had advertised answered 405 — and a `POST` to that URL created a
  duplicate registration instead of failing. Both the routing decision and the
  advertised URL now derive from the base the router actually mounted on.

- Back-channel logout fans out once per subject, not once per session. A
  chooser group holding several browser sessions for one account produced one
  fan-out each, so every registered RP received several logout tokens that
  differed only by `jti`, and the in-flight fan-out cap was consumed several
  times over — under load the shedding then fired and some RPs were never
  notified at all. The sibling loop in the same function already deduplicated
  on subject.

- The `claims` parameter's `updated_at` is projected into the id_token, not
  only into `/userinfo`. The two surfaces resolved claim names against
  different effective sources, so an RP using the claim to invalidate a
  locally mirrored profile saw it absent from the id_token, with no error, and
  had to fall back to a `/userinfo` round trip it had not planned for. One
  projection now serves both, on the authorization-code and refresh id_token
  paths alike.

- `composite.New` refuses a `Kind` outside the enumerated set with
  `composite.ErrInvalidKind`. The sentinel was documented as the guard against
  a future Kind whose routing table entry someone forgot, and no code path
  returned it: an unrecognised key was absorbed silently and the traffic it was
  meant to route fell through to `WithDefault`, so hot volatile traffic could
  land on the durable backend, or the reverse, with nothing said at
  construction.

- `composite.New` returns an error rather than panicking when a store's dynamic
  type is not comparable. A value-receiver `store.Store` with an incomparable
  field crashed the process at start-up with a message naming neither composite
  nor the configuration, where the constructor's own godoc lists its failure
  modes as returned errors.

- The SQL adapter reports an expired refresh token as expired even when it was
  also already redeemed. The expiry check ran after the consumed check, against
  the `op/store` contract's explicit ordering rule and against the in-memory
  and DynamoDB adapters, so an old token from a device that had been offline or
  from a restored backup was reported as a replay — which by default runs the
  chain cascade and revokes every live refresh token that client holds. A false
  positive here is not a SOC nuisance, it is an outage.

- `RefreshTokenStore.Consume` returns the record alongside
  `store.ErrAlreadyConsumed` on the SQL adapter. The interface requires it so a
  caller can recover the chain root for replay revocation; without it the
  cascade degraded from chain-scoped to a grant-wide fallback, or to nothing.

- The SQLite serialisation gate covers the transactions the substores open on
  the caller's behalf, not only the one `Store.BeginTx` opens. Five
  read-amend-write paths — passkey login, recovery, refresh rotation and the
  replay cascade, static-client sync — opened their own transactions around the
  gate, and SQLite refuses the second writer outright rather than making it
  wait, so a valid passkey login failed intermittently under concurrency with a
  raw driver error that matched no store sentinel and reached the embedder as a
  bare 500.

- `sessions.Touch` and `interactions.CompareAndSwap` do not misreport under
  MySQL's changed-rows accounting. Both are shaped so that a write can leave
  every column at its existing value — a coarse clock is enough — and MySQL
  then reports zero affected rows, which the adapter read as "no such row" and
  "somebody else won". A live session became `ErrCurrentSessionExpired`, and an
  idempotent state transition became `ErrConflict`. Four sibling call sites in
  the same package already commented on this hazard and resolved it with a
  follow-up read.

- The DynamoDB adapter's `FindBySubjectClient` returns the most recently updated
  grant. It returned whichever the index scan reached first, so on a Grant
  Management deployment a narrower re-authorization could be answered from an
  older, wider grant: the consent prompt skipped, token exchange bound to
  consent that should have been superseded, and a new `/authorize` amending the
  stale grant instead of creating one. The SQL and in-memory adapters select on
  `max(UpdatedAt)`, and the shared contract suite already expected it.

- Deleting a DynamoDB recovery-code batch is all-or-nothing. The delete walked
  slot positions in a loop, so an interruption part-way left the remaining
  slots in place — and because `DeleteItem` is silent on an absent key, the
  retry deleted the already-gone positions and returned nil while the survivors
  stayed redeemable, with the account UI still reporting recovery codes as
  active. Keys are now derived from each item's own stored slot index and
  issued as one transaction, matching what `Put` already did.

- `SessionStore.Touch` changes `ExpiresAt` and `UpdatedAt` and nothing else on
  the Redis and DynamoDB adapters. It read the whole record and wrote it back,
  so a `Touch` racing an out-of-band `Save` restored the snapshot it had read:
  a session moved between chooser groups reappeared in the group it had left,
  including in that group's secondary index, and a concurrent step-up's ACR,
  AMR, `auth_time` and subject were rolled back silently. Where the write
  cannot be proven to be against the record that was read, it now fails rather
  than overwriting with a stale snapshot.

- A `Save` carrying an already-elapsed `ExpiresAt` removes the record on Redis
  instead of being dropped. The write returned nil and did nothing, so an
  embedder terminating a session out of band was told it had succeeded while
  the authenticated session stayed live and the next `prompt=none` request
  quietly succeeded for a subject the operator believed was signed out. The
  other three adapters always replace and filter on read. The same shape
  affected `InteractionStore.Save`.

- The DynamoDB `ListClientIDsBySubject` bounds its backend work at `limit+1`
  rows. It materialised every grant the subject held and sliced the result in
  memory — the exact implementation the interface documentation forbids, for
  the exact reason it gives — and the back-channel logout coordinator calls it
  on every session termination, so a long-lived account paid its whole grant
  history in reads and latency on every sign-out. The sibling lister in the same
  file already paged natively.

- `op.New` does not panic on a store whose `Grants()` is nil. Configuration
  validation explicitly permits it for a `client_credentials`-only deployment,
  and the Redis adapter's godoc says the same, but the subject-mode probe
  dereferenced the accessor unconditionally — so a machine-to-machine
  deployment crashed on first start-up and the only workaround was implementing
  a substore it would never use. The probe reads a missing grant substore as
  "no grants", which is what the surrounding validation already concluded.

- `op.ErrPairwiseSectorUnresolved` and `op.ErrSubjectInputEmpty` match with
  `errors.Is`. The error catalog documents both as coming back from the pairwise
  `SubjectGenerator`, and nothing wrapped them, so the actionable diagnostic —
  configure `sector_identifier_uri` — was unreachable from the public API, and
  `op.IsServerError` returned false for it too. `Provider.SubjectGenerator` is a
  stable public method whose godoc invites exactly this call from an
  administrative tool.

- A failure on `/interaction/{uid}` is rendered by the configured driver when
  the caller asked for HTML. The endpoint wrote the RFC 6749 §5.2 JSON envelope
  on every failure branch, on the assumption that its callers are SPA fetches —
  which is false for the bundled `interaction.HTMLDriver`, the zero-config
  surface `op.New` falls back to. So the routine paths (back-then-resubmit,
  a CSRF failure from a second tab, an expired form, a double submit, a store
  fault) showed the user a blob of JSON as page text. The content negotiation
  and the `interaction.ErrorRenderer` delegation already existed and were not
  being called; requests that do not prefer `text/html` receive the same JSON
  envelope byte for byte.

- A consent or chooser template that fails to execute produces a 5xx, not an
  empty 200. A misspelled field or an undefined template reference fails at
  execution rather than at parse, so it survives `op.New` and appears as a blank
  page at the embedder's first browser login, reproducing on every reload with
  no log line and no audit event. The overlay driver already buffers precisely
  so the endpoint can react; the endpoint now tracks whether anything was
  committed and, when nothing was, commits a definite error response and raises
  an audit event. A driver that may have already written stays untouched.

- A `Content-Type` differing only in case does not turn into a 403. CSRF
  extraction matched the media type case-sensitively while the driver's own
  form predicate did not, and the CSRF gate runs first, so the stricter of the
  two gated the looser: a custom driver or a proxy using a different spelling
  produced an unexplainable 403 that retrying never cleared. HTTP media types
  are case-insensitive (RFC 9110 §8.3).

- The consent page renders in one language. `consent.subtitle` is a seeded
  message in both bundled locales and nothing read it — the client line was a
  hard-coded English string — so with the default HTML driver a Japanese
  speaker saw a consent screen whose title, heading and Allow button were
  Japanese and whose client line was not, with no way to fix it through
  `op.WithLocale`.

- Discovery advertises only the request-object encryption algorithms the
  configured keyset can actually decrypt with. The
  `request_object_encryption_alg_values_supported` array was published from the
  deployment's allow-list without
  consulting the keys, so an RP selecting an advertised algorithm found no
  matching recipient key in the OP's JWKS, and a request object built anyway
  was refused as `invalid_request_object` with nothing naming the cause. The
  array is now filtered by the key families present, using the same predicate
  the decrypt path applies.

- A published `use=enc` JWK carries an `alg` the deployment will actually
  accept. The narrowing from `op.WithSupportedEncryptionAlgs` is documented as
  reaching every JWE surface at once and reached all of them except the
  published key metadata, so an operator who restricted the algorithm set had
  the OP publishing keys marked with an algorithm it would refuse — locking out
  any RP that trusts the key's `alg` over the discovery array.

- Every authorization code the OP hands a relying party raises exactly one
  `code.issued`. The interactive completion path raised none, so the
  `code.issued` ↔ `code.consumed` correlation that code-injection detection
  rests on had no counterpart for any user who had seen a consent screen, and
  an operator counting issued codes missed the interactive population entirely.

- A custom grant that mints the root of a refresh chain raises `token.issued`.
  The series was permanently absent, so delegation and token-exchange chains
  were missing from refresh-chain dashboards and the audit stream had no record
  of when a long-lived chain had been created — a hole in the forensic
  question the event exists to answer, exactly the size of the delegation
  grants.

- A panicking custom-grant handler raises one `custom_grant.failed`, not two.
  The recover path emitted its own record and then returned an error that made
  the caller emit a second, so the panic-class failure rate read as double the
  real one and threshold alerts fired at half the configured level — and the
  two records disagreed with each other on level and on reason.

- `custom_grant.requested` fires at dispatch entry, for every attempt. It fired
  only on success, so the natural failure-rate expression divides by the
  success count and can exceed one. The sibling `token_exchange.requested`
  already fired at entry.

- `token_exchange.requested` fires for a request rejected during structural
  validation. Several gates — an unusable `subject_token_type`, an id_token
  whose audience does not name the client, a sender-constraint mismatch —
  rejected before the event was raised or with no audit signal at all, so a
  class of refusals was invisible and an operator could not tell "nobody tried"
  from "rejected upstream of the instrumentation".

- Audit records are timestamped from `op.WithClock`. The option's godoc has
  always listed audit timestamps among what the injected clock governs, and the
  emitter let the logging runtime read the wall clock instead: a test pinning
  the clock could not relate an audit record to the `iat` of the token it
  describes, and a deployment running a corrected clock had its audit trail
  skewed from its tokens by exactly the correction — the correspondence
  forensic reconstruction depends on.

- `testkit.ErrSignerMismatch` is returned for the case it documents. The only
  guard was a nil check, so a non-ECDSA signer assigned to the provider's
  exported `SigningKey` field produced a wrapped library error that matched
  nothing, which is the only reason the sentinel is exported.

- Public godoc that described behaviour the code does not have has been
  corrected where the code is right and the text was not:
  `op.WithCORSOrigins` states that a ceremony origin must be same-site with the
  issuer, because the ceremony cookies are `__Host-` and same-site by design —
  following the previous wording produced a login UI that passed CORS preflight
  and then met 404 on every `/interaction/{uid}`; `op.WithAccessTokenFormat`
  states that it governs the built-in grants and that a custom grant's
  `BoundAccessToken` is always a JWT, resolving two public comments that
  contradicted each other; `store.Store` states that the composite adapter
  requires a transactional anchor and refuses a composition without one, rather
  than promising a conditional capability Go cannot express;
  `EmailOTPStore.CompareAndSwap` and `TOTPStore.CompareAndSwap` state the
  whole-record precondition the reference and SQL implementations enforce
  rather than a weaker version-only summary; `DeviceCodeStore.FindByUserCode`
  states that the returned record's `ID` must be blank, which is what keeps a
  malicious verification page from polling on the device's behalf;
  `Driver.ParseSubmission` states that for a form-encoded body the endpoint may
  already have parsed it, so an implementation should read `r.PostForm` rather
  than `r.Body`; the `op.AuditAccount*` block states that the library never
  raises any of those events, matching the other reserved-vocabulary blocks, so
  an operator building an account-security dashboard does not read silence as
  "no enrolments are happening"; the `op.AuditTokenExchange*` block is a
  complete sentence again and describes the current single-registry
  arrangement; the in-memory adapter's reclamation section accounts for every
  substore whose records carry an expiry; and `testkit.AutoConsentDriver` says
  that it does not auto-approve anything and points at the call that submits
  consent.

- Documentation and examples that instructed the reader into a dead end have
  been corrected: the back-channel-logout example points at the authorization
  endpoint the OP actually mounts and shares one cookie jar across its steps,
  so the logout it demonstrates now delivers a Logout Token instead of
  answering 200 and delivering nothing; the same example describes
  `op.WithAllowInsecureBackchannelLogoutForDev` as narrowing the SSRF gate to
  loopback rather than disabling it; the table-renaming example renames every
  logical table `WithNaming` accepts, including the authentication-factor
  tables it had left on the bundled prefix; the hot/cold composite example no
  longer claims its routing is identical to its sibling's, which routes
  sessions differently on purpose; the custom-consent-UI example no longer
  lists i18n among what its template seam controls; the risk-based-MFA example
  no longer suggests its rules are mutually exclusive; the demo binary points
  at the `op.DPoPNonceSource` seam an embedder implements instead of naming a
  constructor that does not exist; and the install instructions in the examples
  tree, each example's `go.mod`, and the README status line all name one
  release.

### Changed

- **BREAKING (BYO stores using the contract harness).**
  `contract.TOTPFactory` now returns a `contract.TOTPBackend` rather than a
  bare `store.TOTPStore`, matching the shape `contract.EmailOTPFactory` and
  `contract.Factory` already had. The struct carries the store alongside an
  optional `Diverge` hook, which the harness uses to write a record out of
  band and then assert that `CompareAndSwap` refuses a snapshot whose
  `Version` still matches but whose other fields no longer do — the
  field-for-field precondition the interface documents. A backend that does
  not supply the hook skips that case, as it already does for `Advance`.
  Adapt the factory to `func(t *testing.T) contract.TOTPBackend{Store: …}`;
  the case bodies are unchanged.

- **Existing SQL installations: apply three indexes.** The client-deletion
  cascade revokes with `UPDATE`s filtered on `client_id` alone against
  `oidc_refresh_tokens`, `oidc_access_tokens` and `oidc_opaque_access_tokens`,
  and none of the three had an index leading with that column, so deleting one
  dynamically registered client scanned the token tables — and on MySQL, where
  InnoDB locks every row it examines rather than every row it changes, that is
  a whole-table lock blocking concurrent refreshes and introspections until the
  deletion commits. The statements are in
  `op/storeadapter/sql/schema/MIGRATIONS.md`; SQLite and PostgreSQL acquire
  them from `Migrate()`, and on MySQL applying them by hand is the only way.
  The schema guard test now recognises `UPDATE` cascades as well as `DELETE`
  ones, which is why these three were missed.

- **Existing MySQL installations: apply the username collation change.**
  `oidc_users.username` is declared `utf8mb4_bin` so the lookup matches bytes.
  Apply it before provisioning usernames that differ only in case; on a
  database that already holds rows the `MODIFY` fails if two existing usernames
  collide under the binary collation, which names the accounts to reconcile
  first. The statement is in the same document.

- **DynamoDB schema.** The refresh table's `by_handle` index is gone from
  `TableDefinitions`, and the attribute that existed only to key it is no
  longer written. No query path ever read the index: it was a full-projection
  duplicate of the most write-heavy table in the deployment, doubling its
  storage and spending an extra write unit on every rotation — permanently
  about double on on-demand billing, and on provisioned capacity a source of
  intermittent `ProvisionedThroughputExceededException` during token refresh.
  `ReconcileIndexes` only adds indexes, so an existing table keeps it until an
  operator drops it by hand.

- **FAPI 2.0 deployments configuring `op.WithRefreshGracePeriod`.** The profile
  gate now caps the window at the library default instead of refusing every
  non-zero value. It had been refusing configurations *stricter* than the one
  the OP applies: a FAPI 2.0 deployment that configures nothing already runs
  the default grace window, so an embedder who asked for five seconds was
  pushed back onto sixty, and the option godoc and the error string described a
  zero-grace posture the audit event contradicted. A value at or below the
  default is accepted and applied; a larger one is refused, and the error names
  the cap. Pass zero for a strict no-replay posture.

- **`op.Rule` with no `When` predicate.** A nil `When` is the constant-true
  predicate, as `op.Rule` documents. The compiler read an unset predicate as
  "never fires", so
  `op.LoginFlow{Primary: pw, Rules: []op.Rule{{Then: op.StepTOTP{…}}}}`
  compiled, passed `op.New`, and authenticated every user on the password
  alone — a declared second factor that no `LoginContext` could reach. Two
  godoc comments in the same file had described the two opposite behaviours.
  **A deployment carrying such a rule will now run that step.**

- **Custom `interaction.Driver` implementations rendering the recovery
  prompt.** `interaction.RecoveryCodePromptData.AttemptsRemaining` now carries
  the remaining failed-submission budget, which is what the field's godoc says
  and what the TOTP prompt beside it has always carried. It carried the number
  of unconsumed codes in the batch: a user with a fresh batch was told "10
  attempts left" when the real budget was the cross-factor thirty, and told "1
  left" after spending nine while thirty guesses were still available — and it
  disclosed how many recovery codes an account has left to anyone who had
  cleared the first factor.

- **`op.LoginAttemptObserver` implementations.** `op.AttemptLocked` is now
  reachable: an attempt ended by the brute-force gate rather than by the
  credential is reported with that outcome, where previously the value existed
  in the orchestrator's vocabulary and no code path produced it. An observer
  switching on `Outcome` will see a third value.

- **BYO `op/store` backends.** The contract suite drives redemption as a
  generated state matrix — every combination of already-redeemed and expired,
  against every substore that declares an id-keyed `Consume` — rather than a
  hand-maintained list, so the "expired and also redeemed" cell is exercised
  everywhere it exists. `AuthorizationCodeStore.Consume` now states the same
  precedence rule `RefreshTokenStore.Consume` always has: expiry wins, so a
  code that is both expired and redeemed reads as `ErrNotFound`. The
  distinction is not cosmetic — the token endpoint treats `ErrAlreadyConsumed`
  as replay evidence and runs the RFC 6749 §4.1.2 cascade over the user's
  grant, refresh chain and access tokens. All bundled adapters already
  complied; a third-party backend written from the previous godoc may not.

- A custom-grant failure the dispatcher does not attribute to the client
  answers `500 server_error` rather than `400 invalid_grant`. A handler
  returning `ExtraClaims["scope"]`, or any failure in the OP's own response
  construction, was reported as a defect in the grant the client presented, so
  the embedder debugged their credentials instead of their handler. The
  id_token path already answered 500 for the same collision; 4xx is now
  reserved for the errors the dispatcher classifies as the client's.

- Dynamic registration refuses `tls_client_certificate_bound_access_tokens:
  true` with `invalid_client_metadata`. It was parsed and discarded, so an RP
  received `201 Created` and believed its access tokens would be
  certificate-bound while no per-client enforcement existed — and on a
  deployment that has not set `RequireSenderConstrainedTokens`, it silently
  received bearer tokens. This follows the rule the registration validator
  already applies to `dpop_bound_access_tokens`: an enforcement flag the OP
  will not honour per client is refused rather than accepted and dropped.

- The pinned Go toolchain moves to `go1.27.0` across the root module, the
  storage-adapter sub-modules, the examples, the dev-tool module, the example
  container images and CI. The declared minimum is unchanged — every module
  still carries `go 1.25.0`, so an embedder building on Go 1.25 or Go 1.26
  compiles as before and nothing is required on upgrade.

- Dependencies are raised to their current releases: `go-webauthn/webauthn` to
  `v0.18.0` (with `go-webauthn/x` `v0.3.0`), `fxamacker/cbor/v2` to `v2.9.3`,
  and the `prometheus/client_model`, `prometheus/common` and
  `prometheus/procfs` chain behind `op.WithPrometheus`. The bundled SQL adapter
  moves to `modernc.org/sqlite` `v1.57.0`, and the DynamoDB adapter to
  `aws-sdk-go-v2` `v1.45.1` with `service/dynamodb` `v1.66.0`, `credentials`
  `v1.20.2` and `smithy-go` `v1.28.1`. No call site changed; the passkey,
  JOSE and adapter suites pass unmodified on the new versions.

### Added

- `op.AttemptLocked`, completing the `op.AttemptOutcome` re-export so an
  embedder can write an exhaustive switch using public identifiers alone.
  `internal/authn` is not importable from outside the module, so the third
  value previously had to be spelled as an untyped constant.

- `op.MaxKidlessEncryptionTrialKeys`, the number of same-family keys a
  `op.EncryptionKeyset` may hold before a ciphertext arriving without a `kid`
  is refused rather than trial-decrypted. The limit lived in an internal
  package while the public godoc promised trial decryption across the whole
  slice, so an embedder staging a long HSM rotation past it had every kid-less
  encrypted request object refused as `invalid_request_object` with no signal
  at start-up and no way to find the cause from the public API. `op.New` now
  warns when a keyset exceeds it. The shape is legitimate — an OP whose
  relying parties all send `kid`, which is every RP that reads its JWKS, runs
  on such a keyset with no failures — so it is reported rather than refused.

## [v1.1.0] — 2026-08-13

A security and correctness pass. Several of the fixes close paths on which the
OP returned a wrong answer silently: a consent ceremony that never ran, a
revoked token that kept introspecting as active, an authentication context that
described an older login than the one being served.

Eleven deployment classes need to read the Changed section before upgrading:
anyone running a BYO `store.PasskeyStore`, MFA store or CIBA request store, an
existing SQL or DynamoDB adapter installation, anyone whose OP serves only
machine-to-machine grants, anyone whose relying parties reconcile their
registration through `PUT /register/{client_id}`, anyone serving the
device-code or CIBA grant, anyone serving RP-initiated logout to browsers that
hold more than one account, anyone introspecting from a public client, and
anyone with dashboards or alerts on the OP's Prometheus metrics.

### Security

- A JWT access token with no `jti` is no longer treated as unrevoked by any of
  the four surfaces that verify one — `/userinfo`, `/introspect`, `/revoke` and
  the token-exchange `subject_token` lookup. Under a revocation strategy that
  keys on `jti` (registry or denylist) the OP cannot tell a revoked token from
  a fresh one without that claim, so accepting it bypassed revocation
  altogether. All four now derive the requirement from the configured strategy
  through one predicate rather than each spelling it out.

- The clock tolerance applied to an access token is the same at all four of
  those surfaces. Token exchange applied none, so a deployment with clock skew
  saw one token accepted at `/userinfo` and refused at exchange — under exactly
  the condition the tolerance exists to absorb. The three surfaces that did
  agree agreed by coincidence: each defined its own 30-second literal, and two
  of them documented themselves as mirroring a third with no mechanism doing
  the mirroring. There is now one source. The wider tolerance applied to client
  assertions is deliberately separate and unchanged: an assertion is minted by
  a peer whose clock this OP neither controls nor corrects, which is a
  different question from one it minted itself.

- An unresolvable client address no longer reaches a policy or an audit record
  as the string `"invalid IP"`. That is `netip.Addr`'s rendering of its zero
  value — a plausible-looking but meaningless address — where `op.LoginContext`
  and `audit.Event.IP` both document the absence of an address as empty. A
  policy comparing against it, or an operator reading it in an audit trail,
  was being shown a value that never belonged to anyone.

- Replay revocation no longer gives up when a rotation chain has lost its
  oldest records. Detecting a replayed refresh token makes the OP walk the
  chain to a node it can cascade from (RFC 9700 §2.2.2), and that walk
  abandoned the whole cascade if any ancestor was missing — so a chain whose
  earliest rotation record had been reclaimed kept every live descendant usable
  after the OP had already concluded it was compromised. Records are reclaimed
  oldest-first, so a long-lived chain — the kind an attacker has had the most
  time to work with — was the first to lose the cascade. The DynamoDB adapter
  reached this state on its own: it stamps each refresh record with a TTL at
  that record's own expiry, and the oldest record in an active chain expires
  while its descendants are still redeemable. The walk now stops at the deepest
  node it can resolve and cascades from there, which retires exactly the tokens
  a replay could still spend. A presented token that resolves to nothing, and a
  chain whose records name different clients, remain hard failures.

- Client authentication takes the same wall-clock whether the presented
  `client_id` is registered or not. Every endpoint that authenticates a client
  resolves it first, and an unresolvable id used to answer immediately while a
  registered id with a wrong secret paid the full Argon2id verification — about
  0.7 ms against 91 ms on a current laptop. The constant-time shim written to
  close exactly this gap sat behind the credential check and was therefore
  never reached from a served request, so any caller able to POST to `/token`,
  `/introspect` or `/revoke` could enumerate registered `client_id` values with
  a stopwatch and no credential of any kind. Registration-issued identifiers
  are the ones that matter here: they are unguessable by design, and the timing
  answer turned enumerating them into a single request each.
- Argon2id derivations are capped at `GOMAXPROCS` running at once, so peak
  working memory is a constant fixed at start-up instead of a figure the caller
  sets. One derivation reserves 64 MiB for the ~90 ms it runs, and because a
  wrong secret deliberately costs what a right one does, an unauthenticated
  request could commit that memory: peak heap grew linearly with concurrency,
  measured at 4.6 GiB for 72 simultaneous rejections. The cap admits no fewer
  derivations than the host has threads to run, so measured throughput is
  unchanged; callers past the cap wait rather than fail, and the timing shims
  queue with everything else so a busy OP does not answer an unknown client
  faster than a known one. Password and recovery-code verification derive
  through the same gate.
- `/bc-authorize` verifies an inbound `id_token_hint` itself before any
  `HintResolver` runs: the signature against the OP's own keyset, `iss` equal to
  the issuer, and an audience naming the client that authenticated on the same
  request (CIBA Core 1.0 §7.1). The parameter was previously handed to the
  resolver verbatim, so an implementation that read `sub` out of the payload —
  the obvious reading of the old godoc — let any CIBA-registered client address
  the authentication ceremony to a subject it was never entitled to name.
  See the note under **Changed** for what a resolver now receives.
- A detected refresh-token replay retires the whole rotation chain regardless of
  how the surrounding storage transaction settles, and regardless of how long
  the chain is. The RFC 9700 §2.2.2 cascade previously ran on transaction-bound
  substore handles, which bounded it by whatever action limit the backend's
  transaction imposes; a chain past that limit was retired only in part, and
  because the walk is breadth-first from the root, the surviving node was the
  newest one — the one an attacker presenting a stolen token holds.
- The reference relying-party implementations validate the RFC 9207 `iss`
  authorization-response parameter and fail the callback on a mismatch. The OP
  has always advertised and emitted it, but no bundled RP checked it, so the
  FAPI 2.0 example shipped without the mix-up defence the profile mandates.
- `/authorize` no longer skips the consent ceremony when the request carries
  `prompt=consent` or `authorization_details` the cached grant does not cover.
  A covering grant previously marked consent as already run before the prompt
  matrix was consulted, so an RP that asked for re-consent received an
  authorization code without the user seeing a screen, and RFC 9396 rich
  authorizations (payment amount, payee) were never displayed.
- Verifying a recovery code costs one Argon2id derivation regardless of how many
  codes the batch holds. Every unconsumed slot previously carried its own salt,
  so the only way to answer a submitted string was to derive once per slot: a
  ten-code batch turned a single short input into ten sequential 64 MiB
  derivations, letting one client drive the memory and CPU of ten at a tenth the
  request rate. Batches minted before this release keep their layout and keep
  verifying at the old cost — the OP stores only hashes, so it cannot re-derive
  a batch whose plaintext it never held, and refusing them would void every
  recovery sheet already in a user's hands at the moment they needed it. The
  affected population shrinks as users regenerate through
  `recoverykit.Replace`; the residual cost stays bounded by the batch-size cap
  and sits behind the cross-factor lockout counter. Which layout a batch has is
  a property of the batch as a whole, not of any one row: an operator who wants
  to size the remaining population compares the salt — the fifth `$`-separated
  field of the stored hash — across the slots of one subject, and finds more
  than one distinct value on the older layout. Batches minted after upgrading
  are on the new one, so the mint timestamp already on each batch is the
  cheaper filter.
- A successful recovery-code verify no longer runs faster the earlier the
  matched code sits in the batch. The scan stopped at the matching slot, so the
  elapsed time reported the slot's position — and a recovery sheet is printed in
  order, which makes that position useful to someone holding part of the list.
  Every candidate is now compared and the winner selected without a branch, on
  both batch layouts.
- A recovery slot whose stored encoding declares work-factor parameters outside
  the range the generator emits is refused before any derivation runs. A
  corrupted or tampered row could otherwise name an arbitrary memory cost and
  have the verifier honour it.
- A JARM response whose signing fails no longer falls back to delivering the
  authorization code in plain form. `response_mode=form_post.jwt` was compared
  against the string `form_post`, which never matches, so the failure path
  reached the plain-redirect branch and put the code in a URL — in browser
  history, in the `Referer` of whatever the page loaded next, and in every
  proxy log along the way. The code is now withheld entirely and the OP returns
  an endpoint-local HTTP 500 with no redirect, state, code, or OAuth error
  fields; the unredeemed code lapses at its TTL.
- A DPoP proof presented on a request that then fails client authentication is
  no longer consumed, at `/token` (every grant), `/par`, `/bc-authorize` and
  `/device_authorization` — every endpoint that requires a credential and
  accepts a proof. Proof verification
  runs before client authentication by design — RFC 9449 §8's nonce challenge
  has to be issuable before a `client_assertion`'s own `jti` is spent — but it
  also performed the replay-marking write there, which made it the only durable
  write an unauthenticated caller could drive, at their own request rate. The
  observable effect beyond the storage: a client that retried the same proof
  with corrected credentials was told the proof had been replayed. Verification
  is now split so the stateless checks stay ahead of authentication and the
  marking happens after it.
- The `Origin` allowlist enforced on state-changing `/interaction` requests no
  longer includes the origin of every registered client's `redirect_uri`. That
  list is the CORS allowlist, and reusing it here let an origin registered by
  one client post to another client's consent ceremony. The interaction gate now
  admits the issuer origin and whatever `op.WithCORSOrigins` names explicitly;
  the CORS layer is unchanged.
- The audit event raised when a JWS presents a retired key id carries the
  context of the request that presented it, so it reaches the embedder's sink
  correlated with a request id and an active trace span. It was emitted on a
  detached background context, which left the OP's highest-signal key-rotation
  event unattributable: an operator could see that a retired kid had been
  presented and not which caller did it.
- `/end_session` requires the `id_token_hint` to name the subject the session
  cookie authenticates before it skips the confirmation interstitial. Holding a
  valid hint proves possession of an OP-signed token, not ownership of the
  browser making the request, so any account holder at the same OP could
  previously force every visitor to be logged out and have their access tokens
  revoked from an `<img>` tag.
- Revoking a JWT access token now closes `/introspect` and `/userinfo` even
  when the token carries no grant id. `client_credentials` tokens have none by
  construction, so an M2M credential stayed usable for its full lifetime after
  `/revoke` (RFC 7009 §2.1).
- A passkey registration is refused when the credential ID is already held by a
  different subject, at both the library and the storage layer. The duplicate
  check previously covered only the registering subject's own credentials while
  the write was a credential-ID-keyed upsert, so a credential ID could be moved
  onto another account and unlink the authenticator of whoever held it
  (WebAuthn L3 §7.1 step 27).
- A failed WebAuthn assertion now retires the challenge it was made against.
  The orchestrator cleared the challenge on the failure path but the HTTP layer
  discarded the updated state, leaving it replayable for the rest of the
  interaction's lifetime — with no signature counter to catch the replay on the
  platform authenticators that report none.
- The brute-force counters of the DynamoDB adapter are incremented atomically.
  A read-modify-write recorded a burst of parallel `user_code` guesses as a
  single attempt, so the lockout never fired against a parallel attack.
- The credential-stuffing path can no longer be used to amplify database load:
  the lockout counter's compare-and-swap loop is bounded and honours context
  cancellation. It previously retried without limit, turning the brute-force
  defence into an O(N²) write amplifier under contention.
- Back-channel logout will not deliver to a private-network destination unless
  the deployment opts in with `op.WithBackchannelAllowPrivateNetwork`. Loopback,
  link-local, RFC 1918 and IPv6 ULA targets are refused by default, so a
  registered `backchannel_logout_uri` can no longer aim the OP's signed logout
  token at a service inside the deployment's own network.
- A panicking `LoginAttemptObserver` no longer fails the login or silently
  truncates the fan-out. Each observer is isolated, the panic is reported to the
  provider's configured logger, and the remaining observers still run — which
  matters because one of them supplies the brute-force counter. The log record
  names only the factor, so a broken observer cannot turn the operational log
  into an enumeration surface.
- Grant management refuses a client registered with
  `token_endpoint_auth_method=none`. A public client presents no credential
  beyond declaring its own `client_id`, which left the `grant_id` in the
  request path as the only thing standing between a caller and the endpoint —
  and a path segment is not a secret: it reaches proxy logs, browser history
  and `Referer` headers. Anyone who read one could enumerate what a user had
  consented to, including RFC 9396 authorization details, and delete every
  grant that subject held with that client. Confidential clients are
  unaffected; the same request from them still needs the secret or assertion.
- Fourteen bundled examples configured a provider that could not authenticate
  anyone: they enabled the `authorization_code` grant with no authenticator and
  no login flow, so `/authorize` was unreachable in practice. The interactive
  ones now carry a real password login, and the machine-to-machine ones declare
  only the grants they serve. `11-custom-consent-ui` was the starkest — the
  example is about the consent screen and had no way to reach it, and its own
  instructions told the reader to re-wire the option into a different example to
  see it work.
- `interaction.ErrorPrompt.State` is documented as attacker-controlled. It is
  the `state` parameter exactly as it arrived, unvalidated and unbounded, and on
  the error paths that fire before the client and `redirect_uri` are trusted it
  is not tied to any registered party either. A custom driver that interpolates
  it into markup without escaping turns a rejected authorization request into
  reflected XSS on the OP's own origin. The bundled drivers escape it; nothing
  said so where an embedder writing a driver would read it.
- `op.Deny.Reason` is documented as reaching the log sink unmasked. The godoc
  previously said the value sat on a redaction allow-list and was masked, and
  no such redaction exists — the reason is written verbatim to the operational
  logger under a plain `reason` attribute. **Deployments whose `Decider` puts
  an email address, an account identifier or a raw request input into
  `Deny.Reason` have been logging it in the clear** and should check what they
  put there. No behaviour changed; the guarantee never existed.
- An RP's `jwks_uri` response body is capped at 64 KiB. The previous ceiling was
  large enough that a hostile or misconfigured RP could make each fetch
  materially expensive.
- A custom grant can no longer displace the built-in token exchange.
  `op.WithCustomGrant` accepted a handler named
  `urn:ietf:params:oauth:grant-type:token-exchange` and routed to it in
  preference to the RFC 8693 implementation, so `subject_token` /
  `actor_token` validation, `act` chain construction, audience
  normalisation and `cnf` re-binding were all skipped without a word. The
  reserved set is now derived from the grants the library implements rather
  than transcribed by hand, and a test fails if a natively routed grant_type
  goes missing from it.

- An authorization request that demands fresh authentication gets it. A live
  session cookie made `prompt=login` and `max_age` no-ops on the recommended
  login-flow seam: the orchestrator read the subject the HTTP layer had
  pre-seeded from the cookie, concluded identity was already established, and
  returned a terminal result without a single credential being presented. The
  id_token then carried an `auth_time` of "now" — the moment the interaction
  record was created — with an empty `acr` and no `amr` at all, so an RP using
  `max_age` as a step-up gate before a sensitive operation was told the user had
  just re-authenticated when nobody had. Whether the chain runs is now decided by
  whether this chain bound the subject, the requirement travels from the request
  matrix into the orchestrator state, and the single terminal both surfaces share
  fails closed rather than emitting a result with no factors behind it.

- Picking a different account no longer bypasses the request's freshness and
  authentication-context constraints. The account chooser copies the selected
  session's assurance onto the response, but `max_age` and `acr_values` had been
  evaluated at entry against the *cookie* session — a different session from the
  one the chooser binds — so selecting an older or weaker account yielded an
  authorization code carrying an `auth_time` days in the past and an `acr` below
  what the request required. The constraints are now re-applied to the session
  that actually backs the response, using the dispatcher's own predicates so the
  two gates cannot drift; a stale pick ends in `login_required`, a too-weak one
  in `unmet_authentication_requirements`, and `prompt=login` runs the factor
  chain instead.

- Scopes removed at a re-consent screen are removed from the grant. Unchecking
  a scope narrowed the authorization code but left the stored grant wide, so the
  next request for the same scopes was covered by that grant, skipped the consent
  screen entirely and issued a code including the scope the user had just
  withdrawn. Consent decisions now amend the grant in both directions; silent
  re-stamping and first-party auto-grant stay widen-only. An empty approval is
  recorded as an approval of nothing rather than read as "no ceremony ran".

- `/token` enforces both the Provider's configured grant set and the
  authenticated client's own `GrantTypes`. Neither was consulted: narrowing a
  compromised client's registration left its outstanding authorization codes
  redeemable and its refresh chain rotating indefinitely, and a grant left out of
  `op.WithGrants` was accepted by the endpoint while discovery advertised the
  smaller set. Both gates now run before any credential record is read, so a
  refused request consumes nothing, and the advertised set and the accepted set
  are one projection.

- A DPoP proof cannot carry an `iat` far enough into the future to escape the
  freshness window (RFC 9449 §11.1). The check took the difference between now
  and the claim, and that subtraction saturates: a timestamp beyond the
  representable range produced a "distance" smaller than any window, so a proof
  minted with a year-9999 `iat` was accepted indefinitely. The same unchecked
  value also set how long the replay marker was retained, which on a persistent
  JTI store meant an entry that never expired. The window now compares instants,
  and marker retention is bounded by what the window itself can admit.

- `/userinfo` resolves the OIDC Core 1.0 §5.5 `claims` payload from the grant the
  presented access token descends from, not from whichever grant is currently
  active for the same (subject, client_id) pair. A client holding several grants
  for one user — Grant Management's `create` action mints a new grant per
  authorization — could read claims authorized only on a sibling grant. Applies
  to the JSON and JWT response shapes, to JWT and opaque access tokens, with and
  without pairwise subjects.

- A relying party's `Cache-Control: max-age` on its JWKS may now only shorten how
  long the OP caches that keyset, never extend it. An RP advertising a year meant
  a key it had withdrawn stayed valid for `client_assertion` authentication, and
  stayed in use as an outbound JWE recipient, until the OP process restarted. The
  ceiling is applied where the freshness hint is read and again where the cache
  stores it, so one edit cannot reopen it.

- `PUT /register/{client_id}` no longer fills an omitted `scope` member with the
  OP's entire public scope catalogue. A dynamic client registered for `openid`
  acquired every catalogued scope by submitting one update that simply left the
  member out, and could then obtain tokens for scopes it had never been granted.
  The shared metadata validator can no longer enlarge what was submitted; see
  **Changed** for what an omitted `scope` does now.

- A detected refresh-token replay retires the chain even when the OP cannot
  walk it. Resolving the chain root climbs parent pointers under a limit meant
  as a defence against a corrupted pointer graph, but nothing bounded an honest
  rotation history — refreshing every five minutes reaches the limit in a few
  days — and past it the cascade did nothing at all: the request answered
  `invalid_grant` while every live successor of the compromised chain stayed
  spendable, and the grant tombstone that would have stopped its JWT access
  tokens was skipped along with it. Any outcome in which the chain-scoped
  cascade cannot be shown to have run now escalates to revoking every refresh
  token issued under the grant, and the tombstone is written from the presented
  token's own grant rather than from a root the walk may never reach.

- The Redis session adapter decides chooser-group membership from the session
  record rather than from the secondary index. A session that moved to another
  chooser group was still listed under the group it left whenever the
  cross-group index eviction did not land — and that eviction was a bare command
  whose error was discarded — so another user's account could appear in the
  chooser, and "sign out everywhere" could destroy their session and fire
  back-channel logout for it. Rejected entries are now dropped from the index on
  read, and the eviction is issued inside the same transaction as the new
  group's index write, so a failure is reported instead of ignored.

- Device-code and CIBA redemptions no longer use the redemption secret as the
  grant's identity. `device_code` and `auth_req_id` are bearer credentials the
  store contract requires backends to keep hashed, but the redeemed record's ID
  was passed downstream as the grant identifier — so the raw value landed in the
  `gid` claim of a signed, unencrypted access token, in three storage columns as
  plaintext, and in the audit stream. The value was already consumed and could
  not be replayed, but it reached resource-server logs, APM traces and SIEMs, in
  the exact form the hash-on-store contract exists to prevent.

- A device-code or CIBA record approved without a subject can no longer produce
  a token. Such a record yielded a `200` carrying an id_token with `"sub": ""` —
  which a relying party that checks only signature, issuer and audience accepts,
  then maps to the empty-string key, conflating accounts — while a
  refresh-eligible client on the same record got a `500` instead, so the outcome
  depended on the client's registration. Rejection is now uniform, and the
  signing routines refuse an empty subject regardless of which grant asked, so a
  future grant that skips its own check cannot mint one either.

- A pushed authorization request selecting a JARM `response_mode` on an OP with
  no JARM signer is refused at `/par`, and so is a request that omits
  `response_mode` under FAPI 2.0 Message Signing. Both were previously answered
  with `201` and a `request_uri` that `/authorize` then refused, after the
  browser had already left — the relying party pushed precisely to learn this
  synchronously (RFC 9126 §2.3). The two endpoints now read one shared policy
  rather than each holding its own flag.

- The interaction ceremony routes answer cross-origin requests only for the
  OP's own issuer origin and origins passed to `op.WithCORSOrigins`. State
  changes on those routes were already guarded by that narrow list, but the CORS
  layer wrapping the same routes used the widest one — every registered
  redirect_uri origin — and returned `Access-Control-Allow-Credentials: true`,
  so a client registered on a sibling subdomain could make a credentialed fetch
  to another client's in-flight ceremony and read its CSRF token and account
  list. `SameSite=Lax` does not stop a same-site cross-origin read. The token,
  userinfo, introspection, revocation and PAR endpoints keep the wide list.

- `/end_session` no longer reports a sign-out it never performed. When the
  session store could not answer the lookup, the failure was indistinguishable
  from "this browser has no session": the OP cleared the cookie, rendered the
  signed-out page or redirected to `post_logout_redirect_uri`, raised no audit
  event, and — on a request carrying an `id_token_hint` — skipped the CSRF gate
  on the strength of having nothing to terminate. The session row and the
  subject's tokens survived behind a successful-looking logout. Such a request
  now answers 503, records `session.destroy_failed`, and keeps the cookie so a
  retry can still name the session.

- An authenticator failing because its backend is down is no longer recorded as
  a rejected credential. A store timeout or a misconfigured codec reached the
  same path as a wrong password, so `login.failed` / `mfa.failed` fired and the
  attempt was published to `op.LoginAttemptObserver` — during an outage a
  deployment driving lockout from that feed locked its users out, and the audit
  stream read as credential stuffing. Only a credential the OP actually judged
  is reported; a fault is logged and surfaced unchanged.

- The DynamoDB adapter decides replay-marker and backchannel-request ownership
  in a single conditional write. Taking over an expired marker was a read, a
  decision and an unconditional put, so two concurrent callers seeing the same
  expired record were both told they had succeeded — accepting one DPoP proof,
  or one `private_key_jwt` / `client_secret_jwt` assertion, twice. At most one
  caller now succeeds; the rest get `ErrAlreadyConsumed` / `ErrAlreadyExists`.

- A sealed refresh retry response stops being readable once the predecessor
  refresh token's own expiry has passed. The response is the token payload the
  OP replays inside the rotation grace window, and the store contract requires
  it to be retained no longer than the token it was cached against — but the
  in-memory adapter had no reclamation path for a committed entry at all, so a
  long-running process accumulated one encrypted token response per rotation
  forever, and the SQL adapter kept serving one for as long as any sibling
  chain under the same grant stayed live. A client presenting a predecessor
  that expired during the window now takes the ordinary expired-token path.

- The refresh-token replay event reaches the log with the field that identifies
  which rotation chain was replayed. The value is an irreversible fingerprint,
  but its key name contained "token", so key-name redaction replaced it with the
  sentinel and the OP's most security-relevant event arrived with nothing to
  correlate on. The same collision blanked the device-code revocation record's
  cascade tallies. Separately, the URL masker did not treat `#` as a pair
  boundary, so the first — and most sensitive — parameter of every
  fragment-mode redirect survived masking verbatim.

- `op.WithAllowInsecureBackchannelLogoutForDev` reaches loopback and nothing
  else. The option is documented as flipping both the registration rule and the
  delivery gate for `127.0.0.1`, `[::1]` and `localhost` only, but it lifted the
  deliverer's deny-list outright, so a client registered with
  `backchannel_logout_uri = "https://10.0.5.12/logout"` had a signed Logout
  Token POSTed into RFC 1918 space — a dev convenience that handed anyone able
  to register a client an SSRF probe against the OP's internal network. Link-
  local, RFC 1918, IPv6 ULA and the unspecified address are now refused under
  this option at the URL check, the DNS lookup, the dial and every redirect hop,
  and a registered `localhost` is admitted only while it resolves to a loopback
  address. Reaching a relying party on a private network remains available, as
  before, through `op.WithBackchannelAllowPrivateNetwork`; deployments that were
  relying on the dev option for that reach must name it explicitly.
- A recovery code that `store.RecoveryStore.Consume` reports as spent is
  actually spent. The bundled SQL, in-memory and DynamoDB implementations used
  the caller-supplied `ConsumedAt` as both the "still unconsumed" predicate and
  the value written, so a batch reaching `Consume` without a stamp left the slot
  redeemable while the caller was told it had been used — the same single-use
  code kept working for anyone holding it. The engines did not even agree on
  the answer: SQLite and PostgreSQL returned success and left the slot open,
  MySQL reported `store.ErrAlreadyConsumed` against a slot nobody had ever
  consumed, and DynamoDB's conditional write stored the zero its own condition
  required the slot to already hold. The same shape reached
  `store.EmailOTPStore.Consume`, which carries the same post-condition: a
  challenge written back unstamped still read as pending, and the generation the
  write advanced did not stop the next reader from redeeming it again. Each
  implementation now stamps the record itself, honouring a caller-supplied
  reading and falling back to its own clock, which also removes the dependency
  on whether a backend counts matched or changed rows. Both `Consume` contracts
  state the guarantee: a nil return means the stored record carries a non-zero
  `ConsumedAt`.

- A risk assessor's `RiskRequire` directive demands its named factors on the
  `op.WithLoginFlow` surface. Only `Decision` and `Score` were read there, so
  `RequiredFactors` was dropped without a warning: an assessor that answered a
  suspicious sign-in by demanding a second factor got a session issued on the
  password alone, at exactly the assurance it had refused. The legacy
  `op.WithAuthenticators` chain has always honoured the directive, which made
  this a silent loss of step-up for anyone who migrated to the recommended
  seam. The demand is now recorded when the assessor is consulted and
  discharged at the single point every LoginFlow grant passes through, so an
  embedder `Decider` answering `Allow` cannot release a chain that still owes a
  factor. When no declared step can produce a demanded factor type the attempt
  fails closed with `authn.ErrNoEligibleAuthenticator`. `RiskOutcome.MinAAL`
  remains non-applicable on this surface and its godoc says so.

- `/introspect` requires a confidential client, and refuses one that is public
  or registered with `token_endpoint_auth_method=none` with
  `401 invalid_client` before the `token` parameter is read. A public client
  authenticates by naming its own `client_id`, so the endpoint was answering
  RFC 7662's active/inactive question to any caller who could spell one — a
  token-status oracle over every token whose audience the deployment let a
  public client reach, and a storage lookup an unauthenticated caller could
  drive at their own request rate. The gate runs ahead of the token lookup, so
  a refused request reads nothing. See **Changed** for the migration note.

- Refresh rotation revalidates the RFC 9396 `authorization_details` selection
  inside the transaction that writes the successor token. The selection was
  computed from a read taken before that transaction, so a grant amended
  between the two — a re-consent that narrowed it, a concurrent
  grant-management action — yielded an access token stamped with rich
  authorizations the live grant no longer covered. The grant is now re-read
  after `Consume` and a divergence rolls the transaction back, leaving the
  predecessor redeemable so the client can retry. Moving the preflight read
  ahead of the transaction also removes the stale SQLite WAL snapshot it
  established, which had been failing the later `Consume` with
  `SQLITE_BUSY_SNAPSHOT`.

- Outbound relying-party JWKS loads are capped at 64 distinct URLs in flight
  across the process, with a per-component share that can only narrow that
  ceiling and never widen it. A deployment running open dynamic registration
  accepts a `jwks_uri` from anyone, and nothing bounded the fan-out: a burst of
  `private_key_jwt`, JAR or `self_signed_tls_client_auth` requests naming
  distinct unfetched URLs turned one inbound request each into an outbound
  socket and goroutine, aimed at a host the registrant chose. The gate is
  non-blocking and fails closed — a refusal surfaces as a transient error, is
  kept out of the negative cache, and releases the forced-refresh marker, so
  the next caller retries as soon as a slot frees rather than inheriting a
  cached failure.

### Fixed

- `op/storeadapter/sql/schema/MIGRATIONS.md` names every index the current
  schema carries. Nine added since `v1.0.0` — seven on `expires_at` columns
  and two on `oidc_grants`, keyed on `client_id` and on
  `(client_id, subject, updated_at)` — were only ever created by a fresh
  install. SQLite and PostgreSQL declare their indexes as separate
  `CREATE INDEX IF NOT EXISTS` statements and so acquire them on the next
  `Migrate()`, but MySQL declares them inline in `CREATE TABLE`, which
  `CREATE TABLE IF NOT EXISTS` skips outright: an existing MySQL installation
  never acquired them and had no self-healing path, leaving the retention
  sweeps and the client-scoped grant lookups running without an index. The
  document now carries the dialect-specific statement for each, and states
  that on MySQL it is the only path.

- A remote fetch collapsed behind the shared cache outlives the caller that
  abandoned it. The loader ran on the context of whichever caller won the
  race, so that caller navigating away cancelled the fetch for every other
  request waiting on the same result — they all received `context.Canceled`
  for work none of them had abandoned. The cache detaches cancellation itself
  now rather than leaving it to each caller to remember, which is what the
  sector resolver had not: the JWKS fetcher carried its own detachment and the
  sector fetcher did not. Both keep their own request timeouts.

- `/authorize` requests carrying a `request_uri` share one HTTP client. The JAR
  fetcher built a client, transport and connection pool inside the request
  path, so every such request opened a fresh connection to the relying party
  and discarded the pool afterwards. It now runs through the same guarded fetch
  envelope the JWKS and sector fetchers use, built once when the handler is
  mounted. Every gate is unchanged — SSRF checks at URL and dial time,
  HTTPS-only, no redirects, 2xx only, and the body cap — and the media-type
  rule stays at the call site because this endpoint must admit a response with
  no `Content-Type` at all, which an allow-list cannot express.

- Dynamic client registration parses the request body once. A second full
  decode into a generic map ran on every registration and update to answer a
  question nothing read, so an unauthenticated caller could charge the OP one
  allocation per member of a body they sized themselves.

- `patterns.Paginate` returns a page that does not alias the caller's slice.
  Sorting or otherwise writing to a returned page reordered the input it was
  taken from.

- The account chooser renders as a usable page on the zero-configuration HTML
  surface. `prompt=select_account` reaches an interaction the default
  `op/interaction.HTMLDriver` had no branch for, so the RP's user was served a
  page listing no accounts at all and asking them to type an opaque
  `session_id` they have never seen, labelled with a raw message key because
  the shipped locale bundles had no entry for it, under a heading that was the
  raw prompt identifier. `AddAccountURL` was not rendered, leaving an account
  outside the group unreachable. The page now emits one submit control per
  account carrying that account's session identifier, an add-account link when
  the OP would honour one, and an explanatory line instead of an empty form
  when the chooser group has no members. `ChooserAccount.DisplayName` is
  resolved from the `name` claim on the matching `store.User` — the same claim
  the `profile` scope releases at `/userinfo` — so the label a user picks by
  matches the one the RP will see; a row whose label cannot be resolved is
  still listed. The bundled `en` and `ja` catalogues gained the chooser and
  consent entries they were missing, and the captcha field key they carried
  under a name no field emits was corrected to the emitted one.

- `op.New` warns when `WithMTLSProxy` or `WithMTLSRootCAs` is set without
  `feature.MTLS`. Neither option is read in that combination, so the OP issues
  plain bearer tokens while the configuration reads as certificate-bound. The
  godoc on both options now names the dependency; the constants
  `op.AuthTLSClientAuth` and `op.AuthSelfSignedTLSClientAuth` now say they
  cannot be selected in this release and point at `op.AuthPrivateKeyJWT`.
  `AuthMethod.Valid()` is unchanged — it reports whether a name is one this
  type enumerates, which is a different question from whether this OP can
  negotiate it.

- `op.WithClaimsParameterSupported(false)` now stops the OIDC Core §5.5
  projection it always said it stopped. Discovery and the request parsers
  honoured the flag, but a grant established while the parameter was enabled
  kept releasing the claims it had recorded — into `/userinfo` and into every
  id_token, through refresh rotation, indefinitely. An operator turning the
  parameter off after an incident therefore changed nothing for the
  authorizations that already existed, which is the case the switch is for.
  The gate is on the read path: the claims stay on the grant as the record of
  what the user consented to, and turning the option back on restores the
  projection. Claims released because a scope grants them are unaffected.

- `/token` rejects a repeated `authorization_details` with `invalid_request`
  instead of resolving it to the first occurrence. RFC 6749 §3.1 forbids
  sending a parameter more than once, and the endpoint enforced that through a
  list the parameter was missing from, so a request carrying two payloads was
  answered with an access token stamped from one of them — the differential an
  intermediary reading the other occurrence relies on. `/authorize` and pushed
  authorization requests were never affected; they parse through a shared
  table that already covered it. `resource` stays repeatable, as RFC 8707 §2
  requires.

- The godoc on ten catalogued audit events no longer claims they fire. Beyond
  the four now wired above, `op.AuditMFARequired`, `op.AuditStepUpRequired`,
  `op.AuditStepUpSuccess`, `op.AuditConsentGrantedDelta`,
  `op.AuditConsentSkippedExisting`, `op.AuditConsentRevoked`,
  `op.AuditLogoutRPInitiated`, `op.AuditPKCEViolation`,
  `op.AuditRedirectURIMismatch` and `op.AuditAlgLegacyUsed` are catalogued
  vocabulary the OP does not emit, and each now says so along with the signal
  to use instead where one exists. An absent event among them means "not
  instrumented", not "did not happen" — the previous wording made the opposite
  reading reasonable, which is the worse way for an alert to be wrong.

  `op.AuditCIBAAuthDeviceApproved` and `op.AuditCIBAAuthDeviceDenied` are
  corrected the same way: the authentication device calls
  `store.CIBARequestStore.Approve` / `Deny` directly and no library code sits
  between that call and the store, so the OP has nowhere to observe the
  decision. The names stay catalogued so a deployment raising them from its
  own authentication device lands in the same vocabulary.

  A test now enforces the distinction mechanically — every catalogued name
  must either be reached by an in-tree emitter or be declared unemitted with a
  reason, and a declaration that goes stale because the emitter later lands
  fails just as loudly as a missing one.

  Step-up is the clearest case: the OP has no step-up state machine at all.
  `op.StepUpChallenge` builds the RFC 9470 challenge value and the resource
  server that sends it owns the decision, so the events belong to the
  embedder's pipeline rather than the OP's.

- A JAR failure gets the same description at every endpoint that consumes a
  signed request object. `/authorize`, `/par` and `/bc-authorize` each carried
  their own copy of the sentinel-to-description table, and the copies had
  already drifted: only one described a request object missing `iat`, and none
  described a rejected `typ` header, so those failures reached operators as a
  bare "request object verification failed" with the actual cause discarded.
  The catalogue now lives beside the sentinels it describes and a test fails
  when a sentinel has no entry. The wire code is still each endpoint's own —
  CIBA Core §13 has no `invalid_request_object` to return.
- `/authorize` and `/par` are handed one request-validation policy rather than
  each assembling its own from eight separate flags. The two are consecutive
  gates on a single request, so a requirement honoured at only one of them
  lets `/par` mint a `request_uri` whose one-time value the client then spends
  on a request `/authorize` refuses, stranding the user with no way forward.
  The endpoints had not diverged, but nothing prevented it: adding a policy
  bit meant editing five places and any four of them was a silent partial fix.
- The SQL adapter preserves integer fidelity when reading claim maps back out
  of the database. `decodeObjectArray` used `json.Decoder`+`UseNumber` for the
  `authorization_details` column, but `decodeMap` — which reads user claims,
  grant claims and refresh-token extras — decoded with the default settings,
  widening every JSON number to `float64`. Anything past the float64
  integer-exact range came back rounded: an upstream account id or order
  number carried as a custom claim reached the ID token and `/userinfo` as a
  different value than the one stored. The rounding was deterministic, so
  every read agreed with every other read and nothing downstream could notice.
  The DynamoDB adapter already decoded its whole document this way.
- The SQL adapter recognises a unique-constraint violation on a MySQL or
  PostgreSQL server that does not speak English. The classifier matched only
  the server's message text (`duplicate entry`, `duplicate key value`), which
  both engines translate under `lc_messages`, so on a localized server a
  duplicate insert surfaced as a generic storage error instead of
  `store.ErrAlreadyExists` — a replayed JTI or a colliding client registration
  reported the wrong reason and the wrong audit signal. The check now leads
  with the identity each driver renders itself in Go and cannot translate:
  go-sql-driver's `Error <number>` prefix and pgx's `(SQLSTATE ...)` suffix.
  The English phrases remain as a fall-back.
- The reference SQL schema indexes every column its retention sweeps and
  cascades filter on: `expires_at` on authorization codes, PAR records,
  interactions, sessions, access tokens and consumed JTIs, and `client_id` on
  grants. The grants table carried a composite index leading with `subject`,
  which cannot serve the client-scoped cascade a client deletion runs. Without
  these the sweep scans, and on MySQL an unindexed `DELETE` locks the rows it
  examines rather than the rows it removes, so the reclamation job contends
  with live traffic in proportion to the backlog it exists to clear. Existing
  databases do not gain the indexes automatically: re-running the SQLite or
  PostgreSQL schema adds them, while MySQL declares indexes inside
  `CREATE TABLE` and needs an explicit `ALTER TABLE`.
- Deleting a dynamically registered client on the DynamoDB backend leaves
  nothing live bound to it. The adapter implemented `store.RevokeByClient` on
  refresh tokens only, and the endpoint runs the cascade by probing each
  client-keyed substore for that extension — so the grant rows and the JWT
  access-token registry rows were skipped without a word. The grants table is
  the one table with no TTL, so those rows outlived the client indefinitely and
  kept a deleted application listed in every "applications you have authorized"
  view built on `store.GrantStore.ListBySubject`. Grants and both access-token
  registries now implement the extension. `CreateTables` adds the secondary
  index the new access-token cascade queries to a table that predates it, so an
  existing deployment converges by re-running it rather than by provisioning the
  index by hand. The shared contract suite now fails a backend that implements
  the extension on some of its client-keyed substores and not others, instead of
  skipping the substores it cannot reach.
- The DynamoDB adapter returns an expired Initial Access Token from
  `GetByHash` instead of reporting it absent. Its lookup went through the
  adapter's expiry-filtering read, so a lapsed IAT was indistinguishable from
  one that never existed — the registration endpoint told the client
  "invalid" rather than "expired" and emitted the wrong audit event, on that
  backend only. The library owns this expiry gate; the store contract now says
  so, and the shared contract suite checks it.
- `store.PushedAuthRequestStore.Consume` returns a nil record alongside
  `ErrAlreadyConsumed` on every backend. DynamoDB returned the record, so a
  replayed `request_uri` handed back the entire pushed authorization request
  on one backend and nothing on the others. A failed consume should not yield
  a usable request; the contract now requires the nil and the shared suite
  checks it. `AuthorizationCodeStore.Consume` still returns its record on
  replay, deliberately — RFC 9700 requires identifying the grant to revoke.
- Every `response_mode=form_post.jwt` fallback is delivered as a self-posting
  form rather than a 302. The signing-failure, encryption-failure and
  `unsupported_response_mode` paths all redirected, which contradicts the
  response mode the RP asked for and puts the parameters in a URL.
  `query.jwt`, `fragment.jwt` and bare `jwt` still redirect, as they should.
- The SPA shell serves `Referrer-Policy: same-origin` and `Pragma: no-cache`.
  Its own documentation said it mirrored the HTML driver's hardening and it
  omitted both; the shell URL carries the interaction id, which is exactly the
  value a `Referer` must not leak. The policy is `same-origin` rather than
  `no-referrer` because the shell's own fetches would otherwise present
  `Origin: null` and be refused by the CSRF gate.
- A JAR failure at `/authorize` renders through `interaction.Driver.RenderError`
  when the caller prefers HTML, instead of always returning raw JSON. Under a
  FAPI deployment every request is a JAR request, so this was the one error
  class a browser user met as an unstyled JSON body. Status codes and error
  codes are unchanged, and a non-browser caller receives the same bytes as
  before.
- `/jwks` honours a weak entity-tag in `If-None-Match`, as RFC 9110 §8.8.3.2
  requires for that header. Weak validators were treated as non-matching, so a
  client or intermediary that returned the OP's own ETag in weakened form was
  answered with the full key set instead of a 304. The response ETag is still a
  strong validator; only the comparison changed.
- `/jwks` no longer re-serialises and re-hashes the key set on every request.
  The rendering is memoised and re-derived when the published document changes,
  which for the encryption half happens on the wall clock rather than on a
  rotation event: entries past their `NotAfter` drop out of the document, and a
  cache that missed that would keep advertising a recipient key the OP has
  stopped decrypting for.
- A captcha-enabled deployment is usable. The token the challenge collects was
  never read from the submission and the prompt advertised no field to carry
  it, so crossing the failure threshold locked the user into a challenge loop
  with no exit. The challenge now also interposes on the failure that crosses
  the threshold rather than only on a fresh dispatcher entry, which previously
  made it reachable only by reloading the interaction.
- A silent re-authorization stamps the current session's `auth_time`, `acr` and
  `amr` on the grant. The request was validated against the session while the
  id_token reported whatever an older ceremony had recorded, producing login
  loops under `max_age` and overstating assurance under `acr_values`.
- An RP whose `jwks_uri` publishes a key type go-jose does not support (X25519,
  Ed448) is no longer locked out entirely. The set is parsed key by key and
  unusable members are skipped, per RFC 7517 §5. Applies to `private_key_jwt`,
  JAR, dynamic client registration and `self_signed_tls_client_auth`.
- A cancelled request can no longer poison the JWKS cache. `context.Canceled`
  and `context.DeadlineExceeded` are no longer cached as fetch failures, and
  the fetch runs on a context detached from the caller's, so an unauthenticated
  client could previously keep an RP's JAR and `private_key_jwt` authentication
  failing by disconnecting mid-fetch.
- `/end_session` carries `client_id` through its confirmation form. Logout
  failed with a 400 for every RP using the `client_id` +
  `post_logout_redirect_uri` form of the request — the most common one.
- Grant management accepts `private_key_jwt`. Its GET and DELETE operations
  read the assertion from the query string, which is the only channel a
  bodyless request has; `client_secret` in a query string is refused outright.
  The endpoint previously returned 401 for every request under the FAPI 2.0
  profiles that mandate `private_key_jwt`.
- A request object stays valid for the window the FAPI 2.0 profiles grant it.
  The profile sets a 60-minute lifetime while the request-object verifier capped
  `iat` age at a fixed 10 minutes and checked that first, so an object that was
  conformant by the profile's own arithmetic was refused with
  `invalid_request_object` part-way through its declared lifetime.
- `/authorize` and `/par` refuse a `dpop_jkt` commitment when DPoP is not
  enabled, instead of answering with a code or a `request_uri` whose only
  possible outcome at `/token` is `invalid_grant` (RFC 9449 §10.1). The check
  runs after request-object merging, so a value carried inside a signed JAR is
  covered too.
- The DynamoDB store adapter honours its own transaction contract on the
  revocation paths. `RevokeChain`, `RevokeByGrant`, `RevokeByJTI`, `RevokeByID`,
  `RevokeByClient` and the retry-response read reached the table directly even
  through a transaction handle, so a rollback could not take them back and a
  read could not see what the same transaction had just written.
- The Redis store adapter's plaintext-link warning reaches an operator in the
  bundled sample and demo binaries. Both passed a no-op sink to
  `oidcredis.WithDevModeAllowPlaintext`, so the one signal the adapter makes a
  required argument was discarded by the two files an embedder is most likely to
  copy. `cmd/op-demo` additionally now admits a plaintext `redis://` DSN only for
  a loopback engine and refuses to start otherwise, with the DSN redacted in the
  message.
- `op.WithOpenIDScopeOptional` reaches the token endpoint, so a pure OAuth 2.0
  deployment receives refresh tokens from the authorization-code, device-code
  and CIBA grants instead of only from custom grants.
- A `composite.Store` can be combined with dynamic client registration. Both
  capability checks now consult the store's accessor before falling back to a
  bare type assertion, so the documented hot/cold layout and RFC 7591/7592 are
  no longer mutually exclusive.
- The DynamoDB adapter's refresh rotation writes the successor token and its
  retry-cache entry as one transaction. A partial write made the client's
  legitimate retry look like a replay and revoked the whole chain.
- Concurrent revocation cascades against one grant converge on the widest
  window on DynamoDB. Both tombstone horizons widen under guarded updates
  instead of being replaced, so a cascade can no longer narrow another's.
- Concurrent authorizations against one grant no longer lose each other's
  amendments on DynamoDB. Grants carry a version and a losing write reports
  `store.ErrConflict` rather than dropping the other's `authorization_details`,
  `ACR` or `AuthTime`.
- `X-Forwarded-Proto` and `X-Forwarded-Host` are read as the header chains they
  are. A two-proxy deployment produced a scheme of `"https, https"`, which
  corrupted every issuer-relative URL and the DPoP `htu` comparison.
- The CORS preflight advertises `X-CSRF-Token`, the header the interaction
  handler actually reads. The documented cross-origin SPA pattern was silently
  blocked by the browser. `Access-Control-Allow-Origin` also echoes the
  canonical origin the allowlist matched rather than the raw request header.
- `op.WithCIBAMaxExpiresIn` bounds the lifetime applied when the client omits
  `requested_expiry`; a larger explicitly configured default is rejected at
  construction.
- A custom grant handler that sets only `CustomGrantResponse.Subject` and
  returns a `BoundAccessToken` no longer fails with `server_error`. The
  documented fallback chain was not the one the code took, so the field the
  godoc told handlers to use was the one path that did not work.
- A custom grant handler that omits the access-token TTL gets the provider's
  default rather than `expires_in: 0`. The response was a 200 carrying a token
  the client discarded on arrival, which fails without a symptom to search for.
- A device or CIBA client polling exactly as instructed is no longer driven to
  `access_denied`. On `slow_down` the OP raised its own interval by doubling it
  while RFC 8628 §3.5 and CIBA Core §11 tell the client to add five seconds, so
  the two diverged within a few rounds and the abuse counter fired on a client
  that had done nothing wrong. The OP now adds the same five seconds. It also
  allows a one-second undershoot before counting a violation, because the OP
  measures the gap between arrivals while the client measures the gap between
  sends — jitter alone put roughly half of an on-time client's polls marginally
  early. The absolute floor that catches a tight polling loop is unchanged.
- `verification_uri_complete` is assembled as a URL rather than by string
  concatenation. A `verification_uri` carrying a query produced
  `…?tenant=acme?user_code=…`, so a device that only renders a QR code showed a
  link the user code never reached, with nothing reporting an error.
- RFC 8693 token exchange accepts an OP-issued `id_token` as the
  `subject_token`. Every path through it previously failed: the code read the
  scope from a `scope` claim, which this OP's id_tokens do not carry, so the
  derived scope was always empty and no request could satisfy the subset check.
  The scope now comes from the durable grant the id_token resolves to, which
  also means the exchange stops working the moment consent is withdrawn and can
  never yield more than a refresh of that grant would. An id_token issued to a
  client enrolled for pairwise subjects still cannot be exchanged — its `sub` is
  the projected value while the grant holds the OP-internal one — and is refused
  rather than exchanged on rights the provider cannot establish.
- The refresh grace window no longer returns 500 on a deployment without
  retry-response encryption keys. Those keys are only mandatory when the
  authorization-code grant is enabled, so a CIBA-only, device-code-only or
  custom-grant-only OP failed on every grace retry. A missing cache now answers
  the same `invalid_grant` a retry past the window gets — indistinguishable on
  the wire, and with no chain revocation, since the successor is live and the
  client did nothing wrong.
- Discovery no longer advertises encryption support the OP cannot provide.
  `id_token_encryption_*`, `userinfo_encryption_*`, `authorization_encryption_*`
  and `introspection_encryption_*` were published whether or not an encryption
  keyset was configured, so an RP could register encrypted-response metadata
  against an OP with no key to satisfy it.
- `op.WithSupportedEncryptionAlgs` is enforced rather than merely advertised. The
  allowlist now gates inbound decryption, outbound encryption and the algorithms
  dynamic client registration will accept, so narrowing it actually narrows what
  the OP will do.
- `op.WithJWKSHTTPTransport` reaches the encryption-key fetcher. A deployment
  that supplied a pinned or proxied transport had it applied to signing-key
  fetches only, and encryption-key fetches quietly used the default transport.
- Deleting a client now stops the JWT access tokens already issued to it.
  `/userinfo`, `/introspect` and token exchange require the client named by the
  token's `client_id` claim still to be registered. The deletion cascade could
  not reach these tokens: a grant tombstone is keyed on `grant_id` and a
  deletion produces no list of grants to write tombstones for, and a
  `client_credentials` token carries no grant at all, so it stayed usable until
  `exp` — including at `/userinfo`, which needs no client authentication and so
  kept releasing the user's claims to a deleted client's bearer. Deployments on
  `store.RevocationStrategyNone` are unaffected, as that strategy declares that
  no per-token state is consulted. Embedders that mint access tokens outside the
  client registry are also unaffected: an absent `client_id` claim, or a
  deployment with no client registry wired, skips the check rather than failing
  closed.
- `api/experimental.txt` now records exemptions declared on a package doc.
  `op/interaction` and `op/storeadapter/dynamodb` have each carried an
  "Experimental:" marker on the package comment since before `v1.0.0`, but the
  generator only read declarations, so neither appeared in the file — and the
  file's contract is that anything absent from it is stable. Embedders reading
  the manifest rather than the package documentation were told the `Driver`
  seam was covered by the SemVer promise. Both packages are listed now, as a
  `*` row meaning the marker covers everything the package declares.
- Three "Stable since" godoc markers named the wrong release.
  `recoverykit.Kit` and `recoverykit.Clock` were added after `v1.0.0` and
  claimed to have been stable since it; `op.WithBackchannelAllowPrivateNetwork`
  shipped in `v1.0.0` and had been changed to claim a later one. The marker is
  what an embedder reads to decide whether a symbol can be depended on at a
  given release, so naming the wrong one answers that question wrongly in both
  directions — it invites a dependency that cannot be satisfied, and it hides
  one that can.
- `api/stability.txt` records every "Stable since" marker together with its
  version, and the build now rejects two things it previously accepted: a
  version that differs from the one recorded for that symbol in an earlier
  release, and a newly marked symbol claiming a release the report already
  enumerates in full. The report is also derived from struct fields, which the
  generator did not read before; several documented fields carry markers.

- Submissions are validated against the outstanding prompt's declared fields
  before any authenticator or interaction sees them. `FieldSpec`'s `Required`,
  `MinLen`, `MaxLen` and `Pattern` were documented as orchestrator-enforced in
  six places and enforced nowhere, so a custom authenticator — written against
  that promise — received whatever fitted inside the driver's 32 KiB body cap.
  The check runs from the field list persisted with the issued prompt rather
  than from anything the client sends, at one point ahead of all four dispatch
  routes.

- An issuer that carries a path serves its discovery document at
  `<issuer>/.well-known/openid-configuration` as well as at
  `/.well-known/openid-configuration/<issuer-path>`. Only the second form was
  mounted, so a relying-party library or conformance suite that appends the
  well-known suffix to the issuer — which is what OpenID Connect Discovery 1.0
  §4 specifies — received a 404 from every multi-tenant path-issuer
  deployment, with no way around it through the public option surface. Both
  forms serve one cached document. Bare-host issuers are unchanged.

- `oidc_token_issued_total` labels each issuance with the grant that actually
  produced it. A refresh token minted through the device-code or CIBA grant was
  counted as `grant_type="authorization_code"`, which the metric's own Help text
  and the bridge's comment both asserted was impossible. The label is now
  derived from the chain origin the OP persists, through a closed projection —
  a value of any other shape, including anything a request could supply, maps to
  `unknown` rather than falling back to a grant name.

- The counter inventory in the Prometheus example lists every metric the library
  registers. Two were missing — `oidc_custom_grant_events_total` and
  `oidc_logout_failures_total` — and that inventory is the only place an
  operator can discover them, so nobody could alert on custom-grant outcomes or
  on logout persistence failures. The example's list, the public boundary test
  and the registered set are now held equal by a test rather than by hand.

- A cross-factor lock that has expired stops being re-applied. After the
  24-hour failure window rolled over, the transition wrote back a lock stamp
  that had lapsed hours or days earlier, and the factors read that field with a
  zero test rather than a time test — so a user whose lock had long expired was
  told the account was locked on the next mistyped second-factor code, and
  stayed told until they entered a correct one. A lock still running is
  unaffected: it is preserved across a rollover and never shortened.

- A sender-constrained refresh retried inside the rotation grace window retires
  the opaque access tokens already issued under the grant before minting the
  re-bound one. The first rotation did this; the grace re-mint did not, so two
  live opaque access tokens could exist under one grant — against the stated
  property that a stolen token's window collapses to clock skew. A failed
  cascade now ends the request rather than answering 200 with both credentials
  live.

- The refresh-chain revocation cascade starts from the deepest node it could
  resolve whenever an ancestor lookup fails, not only when the record was
  reclaimed. A store timeout on any hop discarded the whole walk, and the
  cascade is armed once at replay detection and never retried — so a momentary
  outage dropped the revocation permanently.

- An authorization code minted without an interaction retries a lost
  optimistic-lock conflict on the grant record from a fresh read. Only the
  interactive completion path did, so on a backend that versions grants, two
  tabs opening the same first-party application raced and one received
  `server_error`. One code is persisted per request and a `request_uri` is still
  redeemed at most once.

- A grant-management DELETE revokes the grant its `grant_id` names, and nothing
  else. It enumerated every grant the same subject held with the same client and
  revoked and deleted all of them — including grants created deliberately with
  `grant_management_action=create`, whose whole purpose is to be managed
  independently — while answering 204 as though it had removed one. A repeat
  authorization that widens scope now amends the grant the consent screen shows
  instead of minting a second record, so the superseded row and its live refresh
  chain no longer accumulate out of the user's reach.

- `/end_session` enforces the same Origin allowlist as the interaction ceremony
  — the issuer origin plus whatever `op.WithCORSOrigins` names — and its CORS
  layer is narrowed to match. The confirmation page returns HTML carrying a
  double-submit token, so admitting a client's `redirect_uri` origin to read it
  cross-origin hands out the one secret that scheme protects; a sibling
  subdomain is cross-origin and same-site, which `SameSite` does not stop. The
  two gates now reach the same verdict for the same origin, where the CORS layer
  previously admitted origins the CSRF gate then refused with 400.

- A session cookie rebound to a sibling account carries a `Max-Age` no longer
  than the session's remaining server-side lifetime, and is cleared rather than
  rebound when that lifetime has elapsed. The rebind stamped the profile default
  — up to 14 days — regardless of when the session itself expires.

- An authorization request that only reads the session no longer writes the
  account selection back on every pass. It re-sealed the cookie from the payload
  it read at entry, so a tab that switched accounts in between was silently
  reverted and the next `prompt=none` request minted for the subject the user
  had left. The cookie is re-sealed once its browser lifetime has aged enough to
  be worth extending; the server-side idle touch is unchanged.

- Every store adapter fails a call made through a committed or rolled-back
  `store.Tx` with an error satisfying `errors.Is(err, store.ErrTxRequired)`,
  lookups included. The DynamoDB adapter answered such a lookup from the live
  table with a nil error, so a caller holding a leaked handle believed it was
  still inside its transaction, and its index-backed grant enumerations
  (`FindBySubjectClient`, `ListBySubject`, `HasAny`, `ListClientIDsBySubject`,
  `ListSubjectsByClient`) reported an empty result with a nil error —
  indistinguishable, to a consent-management screen, from a subject who has
  authorised nothing. Its bulk revocations resolve their targets the same way,
  through an index that cannot see staged writes, so `RevokeChain`,
  `RevokeByGrant` and `RevokeByClient` answered a leaked handle with a completed
  revocation whenever the index matched nothing. The SQL adapter surfaced
  `database/sql.ErrTxDone` verbatim, which a caller could not tell from a
  transport fault and would therefore retry forever. Adapters are held to this
  by the shared contract suite. Error strings on that path now name the backend;
  the sentinel callers match on is unchanged.

- `/interaction/{uid}` and the pre-redirect `/authorize` error page carry
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: same-origin` whatever Driver is configured. Only the bundled
  HTML driver set them, so a custom Driver or the SPA path served the consent
  ceremony — one click from a grant, holding the CSRF token and the continuation
  reference — with no framing or referrer protection, and so did the endpoint's
  own 404 / 403 / 409 / 500 responses, which no Driver ever sees. `Driver.Render`
  now states that implementations must not weaken them; Content-Security-Policy
  stays the Driver's obligation, since only it knows its asset origins.

- The built-in HTML interaction surface renders a required hidden field as a
  labelled text input. That driver ships no script, so nothing on the page could
  populate such a field, while the orchestrator rejects a submission that omits
  a required one — wiring `op.WithCaptchaVerifier` behind it therefore locked
  out every user who reached the challenge, with the chain aborting once the
  attempts ran out. A start-up warning now covers the case the library cannot
  decide: a captcha whose token only a browser widget can mint, and a passkey
  ceremony, neither of which a user can type.

- Wrapping a Driver with `op.WithConsentUI` or `op.WithChooserUI` no longer
  turns pre-redirect authorization errors into a raw JSON envelope. The
  library's own overlay did not carry `ErrorRenderer` through, so adding one
  branding template silently cost an OP the HTML or SPA error page its Driver
  already rendered.

- The in-memory PAR substore keeps a pushed request redeemable through a slow
  interactive login. Its sweep reclaimed records on expiry, but the store
  contract requires `Consume` to enforce single use only — expiry is judged at
  presentation — so a login that took longer than the `request_uri` lifetime
  turned into `access_denied` once enough unrelated pushes had accumulated to
  trigger a sweep. A load-dependent, intermittent failure. Reclamation now runs
  on a retention window past expiry, through one predicate every reclamation
  path shares.

- The SQL adapter reports `ErrNotFound` from `UpdateClient` only when no row
  carries the client ID. It had read that verdict off the affected-row count, so
  on MySQL and MariaDB — which report zero rows changed when an update writes
  the values already stored — a client re-submitting its current metadata, the
  normal behaviour of a configuration reconcile loop, got `ErrNotFound` and a
  `401 invalid_token` from `PUT /register/{client_id}`. PostgreSQL and SQLite
  returned 200 for the same request.

- The shipped example SPA renders the consent screen. It read the scope list
  under member names the JSON driver does not emit, so the dialogue appeared
  empty, and submitting it approved nothing while the server read the empty
  approval as "no ceremony ran". The account chooser had no renderer at all and
  fell through to the generic field loop, which drew a bare Continue button
  because the chooser's only input is hidden. The server half is covered by the
  consent fix under **Security**.

- The dependency licence gate fails on a dependency it cannot positively
  classify. It matched a list of forbidden families against the whole CSV row,
  which never reached the licence column, left unclassifiable dependencies
  passing, and could not distinguish a pattern that matches nothing from one
  that matches nothing *yet*. Classification is now an allowlist compared
  against the licence column alone, and the published index carries no
  unclassified row.

- A region-qualified locale bundle can be selected. `op.LocaleBundleFromMap`
  registered the tag exactly as written while the resolver folded every
  inbound signal — `ui_locales`, the `__Host-oidc_locale` cookie,
  `Accept-Language`, a `PreferredLocaleStore` answer — to lowercase, so a
  bundle registered as `pt-BR` or `zh-Hant` matched nothing from any route
  and was unreachable however the request spelled it. `Provider.SetLocaleCookie`
  compounded it: passing the tag in its registration casing returned no error
  and wrote the cookie, and the next request discarded that cookie and served
  the default. Registration, the default-locale option, the cookie, the
  matcher and the `ui_locales_supported` advertisement now share one
  canonicalisation, and matching follows the RFC 4647 lookup rule, so
  `zh-Hant-TW` reaches a `zh-Hant` bundle and `pt-BR` reaches a `pt` one.

- A partial locale bundle no longer renders blank UI when it is also the
  configured default. Message lookup ran two tiers — the selected locale, then
  the default — which left the default itself with nothing above it, so every
  key an incomplete default translation omitted resolved to the empty string.
  Lookup now walks the selected tag's own fallback chain, the default's, and
  finally the seed English catalogue.

- An interaction or logout ceremony survives a cookie-key rotation. The CSRF
  double-submit token and the login-flow state reference were signed with a key
  derived from the newest configured cookie key alone, while the cookies
  themselves decrypt across the whole overlap window — so the moment a new key
  was deployed, every ceremony already in a browser failed its next submission
  with a CSRF error, and the user's only route forward was to restart the
  authorization request. Both signers now issue with the current key and verify
  against the full ring, and verification walks the whole ring rather than
  stopping at the key that matched, so the work does not report which one it
  was. A token whose issued-at lies in the future is rejected rather than
  passed through by a check that only bounded age in one direction, and the
  state-reference payload is validated on issue as well as on verify.

- A grant-management `DELETE` that has already removed the grant answers 204
  rather than 404. The handler treated `ErrNotFound` from the final delete as a
  failure, so a client retrying after a timeout — the case a bearer-token API
  with no idempotency key is expected to hit — was told the grant it had just
  removed did not exist. The requested grant is also processed last, so a
  failure on a sibling record leaves the authenticated anchor queryable instead
  of stranding the client with a `grant_id` it can neither read nor retire.

- `introspection_signed_response_alg: "none"` is read as "no signing
  requirement" rather than as a demand for a signed response the OP then had to
  satisfy with an algorithm named `none`. The value is also projected onto the
  public `op.ClientMetadata` view now, which had dropped it — a registration a
  `RegistrationOption.ValidateMetadata` hook was asked to approve did not carry
  the member that decides whether that client's introspection responses arrive
  as JSON or as a JWS, so the one hook that could refuse the combination could
  not see it.

### Changed

- `op.New` rejects a configuration that sets `op.WithRiskAssessor` alongside a
  `LoginFlow.Risk` assessor. The LoginFlow surface consults one assessor per
  chain, and the option-supplied one was never reached, so a deployment that
  named both silently ran only the flow's — losing every `Deny` the other would
  have returned. Setting either alone is unchanged: the option now feeds the
  flow's assessor when `LoginFlow.Risk` is absent.

- **BREAKING (BYO MFA stores).** `store.TOTPRecord` and
  `store.EmailOTPRecord` now carry an opaque, equality-only store-issued
  `Version` token. Backends use a fresh token for every Put and successful
  transition that leaves a record stored, including recreation after deletion,
  so a stale read-modify-write snapshot cannot become valid again across OP
  processes. Callers must retain it unchanged
  from `Get` and re-read after `Put`; they must not infer ordering from it.
  The `json:"-"` tag keeps the token out of the opaque record document, so a
  JSON-backed store must persist it in separate backend state. Update unkeyed
  struct literals to keyed literals before upgrading. Existing bundled SQL
  installations must add both `row_version` columns — and, on the same pass,
  the `oidc_registration_access_tokens.allowed_scopes` column this release also
  reads — from `op/storeadapter/sql/schema/MIGRATIONS.md` before starting the
  new binary.
  Quiesce and upgrade SQL and DynamoDB MFA writers together: an old SQL writer
  does not advance the token, while an old DynamoDB `PutItem` writer removes its
  attribute.
- **BREAKING (configuration).** `op.New` refuses a configuration that enables
  the `authorization_code` grant while registering neither
  `op.WithAuthenticators` nor `op.WithLoginFlow`. There is no way to establish a
  session other than the interaction chain, and the chain runner is only built
  when one of those two is present, so such a provider could never serve an
  authorization request: it constructed successfully and then answered the first
  real `/authorize` with a `server_error`, which reads as an OP fault to the
  relying party and gives the operator nothing to act on. A deployment that
  genuinely runs only non-interactive grants is unaffected and still needs no
  authenticator — remove `authorization_code` from `op.WithGrants` to say so.
- **BREAKING (CIBA embedders).** `op.HintResolver.Resolve` receives the
  OP-verified `sub` claim on the `op.HintIDTokenHint` branch, where it
  previously received the raw `id_token_hint` JWT. `op.HintLoginHint` and
  `op.HintLoginHintToken` are unchanged and still deliver the raw parameter. A
  resolver that parsed the id_token itself should drop that code and look the
  value up as a subject; one that parsed it and did *not* verify it was relying
  on behaviour that is now closed (see **Security**). Requests from a client
  registered with `subject_type=pairwise` are refused with `invalid_request`
  before a resolver is reached, because a per-sector pseudonym (OIDC Core 1.0
  §8.1) has no reverse index the OP could resolve it through; such clients use
  `login_hint` or `login_hint_token`.
- **BREAKING (FAPI seeding).** `profile.AllowedClientAuthMethods` no longer
  returns `tls_client_auth` / `self_signed_tls_client_auth` for the FAPI
  profiles. The library does not implement RFC 8705 §2 mutual-TLS client
  authentication — discovery never advertised it and registration always
  refused it — so a client seeded from the returned list failed `op.New` with a
  configuration error. The list is now directly usable as a seed source, and
  FAPI 2.0 remains satisfiable through `private_key_jwt`. `feature.MTLS` is
  unchanged and still delivers RFC 8705 §3 certificate-bound tokens, which is
  orthogonal to how a client proves its identity; its godoc now says so.
- `/introspect` returns `iss` for opaque access tokens and refresh tokens, not
  only for JWT-formatted access tokens. A resource server that validated the
  issuer of an introspection response — what RFC 7662 §2.2 lists `iss` for —
  broke when a deployment switched `op.WithAccessTokenFormat`, with no change on
  either side. `jti` remains JWT-only on purpose: the only identifier an opaque
  record holds is the credential the client presented, so projecting it would
  echo a live bearer token into a body resource servers routinely log.
- **BREAKING (BYO stores).** `store.PasskeyStore.Put` MUST now leave the stored
  record untouched and return `store.ErrAlreadyExists` when the credential ID
  is held by a different subject, and the comparison and write MUST be one
  atomic operation. Re-writing a record under its own subject is unchanged. The
  bundled inmem, SQL and DynamoDB adapters implement this; a third-party store
  that does not will fail the contract suite's new `PutRefusesCrossSubjectCredential`
  case. The library performs its own ownership check before the write, so the
  takeover is closed even against a store that has not been updated — the
  contract requirement closes the remaining race.
- **BREAKING (DynamoDB schema).** `user_code` uniqueness moved from the
  `by_user_code` GSI to a transactional reservation item, and the index is gone
  from `TableDefinitions`. Existing tables keep an unused index, which can be
  dropped by hand. Device codes issued before the upgrade carry no reservation
  and stop resolving by `user_code`; they expire within minutes. An index
  fallback was deliberately not added, because it would let a new request claim
  a `user_code` a live pre-upgrade record still holds — the defect being fixed.
  Usernames written through `PutUserWithPassword` are reserved the same way;
  directories bulk-imported by the embedder still resolve through the index and
  own their own uniqueness.
- A machine-to-machine OP no longer advertises endpoints it does not mount.
  `authorization_endpoint`, `end_session_endpoint` and
  `backchannel_logout_supported` are omitted, and `response_types_supported` is
  an empty array, when no configured grant uses the authorization endpoint. It
  stays present because RFC 8414 §2 makes it unconditionally required. An RP
  that followed the old document received a bodiless 404; one that registered a
  `backchannel_logout_uri` never received a logout token.
- `op.MaxAccessTokenTTL` and `op.DefaultRefreshTokenTTL` are constants rather
  than variables.
- Dynamic client registration accepts the standard OpenID Connect Dynamic
  Client Registration 1.0 §2 metadata set. Any member the OP did not model was
  rejected outright, including `userinfo_signed_response_alg` — which the OP
  advertises support for in its own discovery document — so a general-purpose
  RP library that fills in the specification's fields could not onboard at all.
  Unmodelled members are now ignored per RFC 7591 §2. Members naming a
  capability the OP will not actually apply are still refused rather than
  accepted and dropped, so a client is never told it has a protection it does
  not have: `dpop_bound_access_tokens: true` and
  `require_pushed_authorization_requests: true` are refused because the OP has
  no per-client enforcement for either.
- A `PUT` to the client-configuration endpoint keeps configuration the
  registration metadata cannot express. The record was rebuilt from the
  submitted document, so an RFC 8707 `Resources` allow-list or an
  `IntrospectionSignedResponseAlg` set out of band was silently discarded the
  first time the RP updated anything.
- `feature.RAR` and `feature.GrantManagement` are rejected at `op.New` when the
  option that configures them is absent, matching how `feature.DynamicRegistration`
  already behaved. Enabling either alone previously did nothing at all, with no
  way for the embedder to discover why.
- The duplicate-declaration check for `feature.DynamicRegistration` no longer
  depends on the order the options were passed in.
- `op.WithCustomGrant` rejects a handler named after a grant the OP implements
  itself, including the CIBA and token-exchange URNs it previously accepted.
  Registering the CIBA URN was already inert — the token endpoint routes that
  grant natively, so the handler was never reached — and registering the
  token-exchange URN silently replaced the built-in implementation. Both now
  fail at `op.New` with `ErrCustomGrantBuiltinCollision`.
- `op.CustomGrantRequest.Subject` and `.AuthTime` are documented as always
  empty. The token endpoint authenticates a client rather than an end user and
  does not interpret an extension grant's parameters, so it has nothing from
  which to resolve a subject; identity resolution belongs to the handler, which
  reports its result back through the response. The fields previously read as
  though the OP would sometimes populate them.
- Every Prometheus metric the OP exports carries a constant `issuer` label. No
  metric is renamed or removed, so existing queries keep resolving; they gain a
  dimension. This is what lets one registry serve several providers — previously
  the second `op.WithPrometheus` against a shared registry failed on duplicate
  collector names. Two providers declaring the *same* issuer still collide,
  which is the intended reading: one issuer is one OP.
- `op.WithPrometheus` registration is all-or-nothing. A failure part-way through
  unregisters what it already registered instead of leaving the registry holding
  a partial metric set.
- `/end_session` no longer waits for back-channel logout delivery. The fan-out is
  detached from the request and runs under an overall 30-second budget, so a slow
  or unresponsive RP cannot hold the user's logout response — previously 256
  targets at a 5-second timeout, 8 at a time, could block it for minutes.
  Deliveries abandoned when the budget expires are recorded per target in the
  audit trail rather than dropped silently. The per-RP timeout is unchanged.
- `op.WithAuditLogger`'s contract is stated rather than implied: the handler runs
  synchronously on the request goroutine, must not block, and must be safe for
  concurrent use. Behaviour is unchanged; the documentation previously suggested
  remote sinks without saying what that costs.
- Dependency updates: `prometheus/client_golang` v1.23.2 → v1.24.1,
  `golang.org/x/crypto` v0.54 → v0.55, `go-webauthn/x` v0.2.6 → v0.2.8. In the
  storage adapters, `modernc.org/sqlite` v1.53 → v1.56, `redis/go-redis/v9`
  v9.21 → v9.22, and `aws/aws-sdk-go-v2/service/dynamodb` v1.62 → v1.63. The
  reference application and the examples move to `coreos/go-oidc/v3` v3.11 →
  v3.20 and `golang.org/x/oauth2` v0.30 → v0.36.

- `client_credentials` must be enabled with `op.WithGrants` to be served. The
  endpoint previously accepted it whether or not it was configured, so a
  deployment relying on that now receives `unsupported_grant_type` until the
  grant is named. Clients must also carry the grant in their own registration.

- An omitted `scope` member on `PUT /register/{client_id}` clears the client's
  scopes, the way RFC 7592 §2.2 treats every other omitted member. A client that
  wants to keep its scopes names them in the update; one that cleared them
  restores them with a later update. `POST /register` defaults are unchanged.

- The refresh-token replay audit event names its correlation field
  `refresh_chain_fingerprint`. Under the previous name the value never reached
  a sink unmasked, so the practical change is that the field becomes readable.

- After a refresh-token replay whose chain root cannot be resolved, or whose
  chain revocation fails, the OP revokes every refresh token issued under the
  grant. A client holding several concurrent refresh chains under one grant may
  see sibling chains retired together on that path; over-revoking is the
  fail-secure direction, and the alternative is leaving a live successor of a
  chain the OP has already concluded is compromised.

- **BREAKING (device-code / CIBA deployments).** The `gid` private claim on
  access tokens issued through the device-code and CIBA grants is now a fresh
  random identifier allocated at redemption, not the raw `device_code` /
  `auth_req_id`. Anything correlating a token's `gid` back to a
  device-authorization or bc-authorize row stops matching, and grant-tombstone
  revocation for those flows must key on the new identifier. Refresh rows issued
  before the upgrade keep their stored value and keep rotating, so live chains
  are unaffected. `gid` is unchanged for `authorization_code`,
  `client_credentials` and custom grants.

- A device-code or CIBA record approved with no subject is refused with
  `400 invalid_grant` on every client shape. The record is not consumed, so an
  embedder that repairs the approval can retry the poll.

- A login or consent UI hosted on a client's `redirect_uri` origin must name
  that origin in `op.WithCORSOrigins` to drive the interaction ceremony
  cross-origin. Being a registered redirect_uri is no longer sufficient for the
  ceremony routes; the ceremony's CSRF gate has always required the same for
  state-changing requests, so such a deployment could not previously complete a
  submission either.

- `/end_session` answers 503 with the static error page when the session store
  cannot answer, where it previously answered 200 or redirected. Deployments
  that treated a logout response as unconditionally successful will see failures
  surface during a session-store outage; deployments that alerted on
  failed-login noise during backend outages will see that noise stop.

- `Store.GC` on the SQL adapter also clears the cached retry response on rows it
  retains for chain resolution. No row is removed by that step, so `GCStats` and
  `Total()` are unchanged. Storage adapters are held to the retention bound by
  the shared contract suite, so a third-party backend that kept the response
  longer will start failing `RefreshTokenStore/RetryResponseDiesWithPredecessor`.

- A configuration whose endpoint override occupies the issuer-relative
  well-known path is rejected at construction with a configuration error naming
  the contested path, instead of silently shadowing the discovery document.

- **Dashboards and alert rules on `oidc_token_issued_total` need updating.**
  Device-code and CIBA redemptions leave the `grant_type="authorization_code"`
  series and appear under `device_code` and `ciba`; an issuance whose origin
  cannot be resolved appears under `unknown`. The existing series drops by that
  volume and the new ones start unwatched. The metric's Help text changed to
  match. The `token.issued` audit record gained a `refresh_origin` field.

- `op/testkit.ApproveAllScopes` is deprecated. Its value is the empty
  approved-scopes payload, which the OP now records as an approval of nothing
  rather than an approval of everything — an embedder test using it approves no
  scope and receives a code without `openid`. `testkit.ApprovedScopesFrom`
  builds the payload that approves what the consent screen actually presented,
  read out of the prompt envelope, and fails the test if the envelope carries
  no scopes.

- A client that relied on one grant-management DELETE clearing a subject's whole
  relationship must now delete each `grant_id` it holds. The
  `grant_management.revoked` audit event no longer carries a `revoked_grant_ids`
  extra; `grant_id` names the single revoked grant.

- An embedder driving `/end_session` cross-origin from a client's
  `redirect_uri` origin must name that origin in `op.WithCORSOrigins`. Being a
  registered redirect_uri is no longer sufficient there, matching the
  interaction ceremony.

- **Dynamic registrations naming a signing algorithm the OP will not use are
  refused.** A `*_signed_response_alg` member may now only name a response shape
  its surface actually puts on the wire for that client; anything else is
  `invalid_client_metadata`. Concretely, registrations that previously returned
  201 and now return 400: `authorization_signed_response_alg` other than
  `ES256` (it was parsed and dropped while every JARM response was ES256-signed);
  `userinfo_signed_response_alg` on a client that registered no UserInfo
  response encryption (the signed shape is requested per call with
  `Accept: application/jwt`, never selected at registration); and
  `userinfo_signed_response_alg: "none"` on a client that did register it (those
  responses are signed before they are encrypted). Accepting a value the OP then
  ignores leaves the relying party's JOSE stack expecting a JWS and receiving
  JSON, which fails every login with nothing to diagnose.

- The in-memory PAR substore returns `ErrAlreadyExists` when a `Save` collides
  with a record still inside its retention window, instead of silently replacing
  it.

- `FieldSpec.Required` means present **and** non-empty, `FieldSpec.Pattern` is
  matched against the whole value rather than any substring of it, and
  `FieldSpec.MaxLen: 0` resolves to a per-`FieldKind` default ceiling instead of
  being unbounded. A pattern that does not compile rejects submissions for that
  field rather than passing them through unchecked. A submission may carry at
  most four entries beyond the declared fields — room for `csrf_token` and
  template-specific hidden markers — and at most 32 KiB of keys and values.
  A field whose empty value is a meaningful answer must not be marked
  `Required`; use `MinLen` for "must send something". The built-in consent
  prompt's `approved_scopes` is no longer advertised as required for exactly
  that reason: approving nothing is an answer.

- `op/devicecodekit.Deps` carries a mutex and is no longer copyable; `go vet`'s
  copylocks check rejects passing it by value. Hold it behind a pointer, which is
  what every helper in the package already takes. The mutex is there for the
  user-code attempt budget the package gained; see **Added**.

- Locale tags are reported in canonical BCP 47 form — lowercase,
  hyphen-separated — wherever the OP names one back to the embedder or the
  wire: `LocaleBundle.Locale`, `Resolver.Available`, `Resolver.Default`,
  `Resolver.Resolve`, the value `Provider.SetLocaleCookie` writes, and
  `ui_locales_supported`. Embedders that compare a resolved locale against a
  literal, or read the cookie themselves, should compare case-insensitively or
  spell their constants in canonical form; a bundle registered as `pt-BR` now
  reports as `pt-br`. Tags are still accepted in any casing and with either
  separator on the way in.

- `WithDiscoveryMetadata` rejects a `UILocalesSupported` entry that no
  registered bundle serves, rather than advertising it. `ui_locales_supported`
  tells relying parties which values `ui_locales` accepts, and an entry the
  resolver cannot match sent every RP that honoured the advertisement to the
  default locale instead. Narrowing the advertised list to a subset of the
  registered locales still works; naming a locale that was never registered is
  now a construction-time configuration error.

- Every error `op.New` can return is now a `*op.Error`, so `op.IsServerError`
  and `op.IsClientError` partition the construction failures between them.
  Several locale-related options and one builder returned a plain error, for
  which both predicates answered false — code branching on them fell through
  every arm and treated a misconfiguration as a success or an unclassified
  crash, depending on which way the caller had written the fallback.

- **BREAKING (RP-initiated logout).** `/end_session` terminates every browser
  account in the active chooser group. A request that wants the previous
  behaviour — end the active session and leave the group's siblings signed in —
  sends the new `logout_scope=current` parameter, which also rebinds the
  session cookie to a surviving sibling when the group still has one. Any other
  value, including an empty or repeated one, is a 400. "Log out" on a browser
  holding several accounts previously left the others live while clearing the
  cookie that named them, which reads as a completed sign-out and is not one.
  The confirmation form binds the scope across its GET → POST round-trip, so a
  forged or stale form cannot widen or narrow what the POST destroys. Group-wide
  logout snapshots the group before deleting it and drives the cascades from
  that snapshot, so access-token, opaque-token and refresh-chain revocation and
  back-channel logout run once per session rather than once per resolved
  subject.

- **BREAKING (dashboards).** `oidc_login_attempts_total` renames its
  `authenticator` label to `factor`, and counts MFA attempts alongside login
  attempts. Queries selecting on `authenticator` stop matching. The rename
  follows what the series now holds: with `mfa.success` / `mfa.failed` reaching
  the same counter, the label names the factor that resolved rather than the
  authenticator that ran, and the two are not the same thing on a chain where
  one authenticator serves several factors.

- **BREAKING (introspection clients).** A resource server that authenticated at
  `/introspect` as a public client, or as one registered with
  `token_endpoint_auth_method=none`, receives `401 invalid_client` and must
  re-register as confidential. See **Security** for why. Deployments introspecting
  from a confidential client are unaffected.

- **BREAKING (BYO CIBA stores).** `store.CIBARequestStore.Approve` MUST return
  `store.ErrConflict` and leave the record untouched when the record already
  carries a subject that differs from the one supplied. Populating an empty
  subject exactly once is unchanged, which is what keeps a deferred-subject
  record approvable. A store that silently overwrote the subject let an
  authentication device move an in-flight request onto a different account.

- Discovery advertises `none` in `token_endpoint_auth_methods_supported`, which
  the token endpoint has always accepted, and adds it to
  `registration_endpoint_auth_methods_supported` when open dynamic registration
  is enabled. The mirrored introspection and revocation lists stay confidential-
  only, so the document no longer implies a public caller is accepted at a
  surface that refuses one.

- `mtls_endpoint_aliases` is validated at construction against the endpoints
  and features actually mounted, and an alias naming an unknown key or an
  unmounted endpoint is a configuration error rather than a published document
  that sends a client to a path returning 404. Declaring any alias without
  `feature.MTLS` is likewise refused.

### Added

- `op.CaptchaWidgetDescriber`, which a `op.CaptchaVerifier` may also implement
  to describe the widget its provider needs bootstrapped. The
  `CaptchaPromptData.Provider` and `.SiteKey` fields a prompt carries were
  never filled by either emission point, so an SPA had nothing to instantiate
  the widget from and the shipped example's guard was a dead branch.
- `op.RiskOutcome.NewDevice`, the verdict `op.RuleNewDevice` reads. The rule is
  the way "step up when the browser is new" is written, and its predicate was
  structurally always false: nothing set the field it tests, so the rule
  matched nothing and the step-up never fired — with no error and no warning.
  A risk assessor now supplies the verdict on its once-per-chain consult, and
  the rule's godoc states that it stays false when no assessor is wired.
- `op.ContinueInput.RemoteIP`, so an embedder driving the interaction loop can
  supply the address for the surfaces that take one.
- An example that configures no interaction driver at all, so login, consent
  and the `prompt=select_account` chooser are all served by the surface
  `op.New` falls back to. Every other example replaces that driver before it
  reaches a chooser, which is how a default surface that could not render one
  stayed shipped: "works with zero configuration" was the one claim nothing
  exercised.

- `devicecodekit.Deps.AuditLogger *slog.Logger` routes the device-code
  verification and revocation audit events to an embedder-supplied slog handler,
  redact-wrapped the same way the provider's own audit stream is. The four
  events had no sink an embedder could configure: the existing `Deps.Audit`
  field is typed with an interface whose method takes a package-internal event
  type, so no code outside this module can implement it, and the events were
  discarded everywhere except the library's own tests.

- The authenticator chain now raises `op.AuditLoginSuccess`,
  `op.AuditLoginFailed`, `op.AuditMFASuccess` and `op.AuditMFAFailed`, one per
  factor as it resolves — the `login.*` pair for the factor that first
  identifies the user, the `mfa.*` pair for every factor after it. The four
  names were catalogued and exported from the first release but nothing ever
  emitted them, which also left `oidc_login_attempts_total` permanently at
  zero for deployments using `op.WithPrometheus`: a dashboard watching for
  brute force showed a flat line whether or not one was under way. Both the
  legacy authenticator chain and the login-flow path reach the same emission
  point, so the count is one per resolved factor on either.

  The event carries the subject as `ActorID` on the failure path as well as
  the success path. The separate `op.LoginAttemptObserver` feed deliberately
  withholds it there — an observer runs inside the attempt and can steer the
  response, so populating it would make the hook an enumeration oracle — but
  the audit stream reaches the deployment's own sink and nothing on the wire.

- `devicecodekit.ApproveUserCode` and `devicecodekit.DenyUserCode` now raise
  `op.AuditDeviceCodeVerificationApproved` /
  `op.AuditDeviceCodeVerificationDenied` once the substore has accepted the
  transition. Only the brute-force lockout emitted before, so the audit stream
  recorded every device authorization the OP refused and none that a user
  granted — the log could not answer who authorised a device. The substore's
  compare-and-swap bounds the emission to one per record, so a resubmitted
  verification page does not double-count.

- `oidcsql.Store.GC` now sweeps the refresh-token table, reported as
  `GCStats.RefreshTokens`. It was the one table the adapter wrote a row to on
  every rotation and never reclaimed. Retention is decided per grant rather
  than per row: a record is deleted only once no refresh token issued under the
  same grant is still live, because a chain's oldest record is the first to
  expire and the OP walks the chain from there when it cascades a replay
  revocation. That is coarser than the chain — one grant can carry several —
  which over-retains and never under-retains. A client that keeps refreshing
  holds its whole rotation history; the history is reclaimed when it stops. The
  condition is a per-grant anti-join rather than a range scan, so it is the
  more expensive of the five sweeps. The bundled DDL gains an
  `expires_at` index on the refresh table; a deployment running the v1.0.0
  schema should add it before scheduling the sweep.

- `op.AuditLockoutStalled`, raised when the cross-factor brute-force counter
  abandons a failed attempt because its compare-and-swap lost every retry. The
  attempt is rejected but not counted, so the subject's failure budget stops
  advancing and the lockout threshold recedes for as long as the contention
  lasts. Only the one caller whose attempt was dropped saw the error, and it
  reads to that caller as an ordinary rejection; nothing downstream could tell
  that the gate had stopped counting. Sustained emissions for one actor are the
  signal — an isolated one is contention under load. The counter is wired to
  the OP's audit chain by `op.WithAuthnLockoutStore`; an authenticator built
  through `op.NewEmailOTPAuthenticator` with its own `LockoutStore` predates
  the provider and stays silent.

- `op.WithHighEntropyClientSecrets`, which verifies `client_secret` with a keyed
  hash instead of Argon2id, together with `op.NewClientSecret`,
  `op.HashHighEntropyClientSecret` and `op.ConfidentialClient.SecretHash` for
  provisioning under it. Argon2id's cost buys resistance to offline guessing of
  a stolen hash, which decides the outcome for a secret a person chose and buys
  nothing for one drawn from 256 bits of randomness — yet the OP paid it on
  every request, including for the secrets it mints itself. A
  `client_credentials` exchange measures 67–73 µs under this option against
  89 ms without it. The declaration is enforced rather than trusted: `op.New`
  refuses a static client still stored under Argon2id, and the provisioning
  helpers refuse a secret short enough to have been typed. It is opt-in and
  OP-wide because the two costs cannot coexist in one deployment — rejections
  are padded to the cost of a verification so an unregistered `client_id`
  cannot be told apart from a wrong secret, and a store holding both formats
  would make the slower clients distinguishable. Re-provision every client
  before enabling it; a record already stored cannot be converted, since the OP
  holds no plaintext to re-hash.
- `op.Provider.SetLocaleCookie` and `op.Provider.ClearLocaleCookie`, which write
  and delete the `__Host-oidc_locale` cookie the locale resolver reads at the
  third step of its priority chain. The chain has always consulted that cookie,
  and `interaction.Prompt.LocalesAvailable` exists so a Driver can build a
  language picker from it, but nothing in the library could write the cookie —
  so a user's pick had no way to survive the prompt it was made on, and the
  chain step was reachable only by an embedder hand-rolling a `__Host-` cookie
  against an undocumented value format. The OP still does not write the cookie
  on its own: a picker is interaction UI, which `interaction.Driver` delegates
  in full, so the OP never observes the choice. The embedder receives the pick
  on an endpoint of its own and persists it here. The stored value is the
  registered tag the input matches — `ja-JP` on an OP registering only `ja`
  stores `ja` — and a locale matching no registered bundle is refused with the
  new `op.ErrLocaleNotRegistered` rather than written, because the resolver
  would otherwise skip the cookie on every later read and leave a picker that
  reports success and never changes the language. Only an explicit choice
  belongs in the cookie: writing back whatever the chain resolved would let one
  RP's `ui_locales` parameter become the user's sticky default at every other
  RP.
- `ConsentUI.ContentSecurityPolicy` and `ChooserUI.ContentSecurityPolicy`, which
  declare the policy sent with a page rendered from an embedder-supplied
  template, plus `interaction.NormalizeCSP` and `interaction.ErrCSPNotPermitted`
  behind them. Both screens previously inherited the policy the built-in driver
  uses, which forbids every subresource — right for markup that loads none, and
  wrong for the templates, whose reason to exist is branding. A stylesheet, logo
  or webfont was dropped by the browser with no server-side signal: the OP
  served 200 and the page rendered unstyled. Leaving the field unset keeps the
  previous policy exactly. Three directives stay with the OP: `frame-ancestors`
  and `base-uri` are appended when absent and accepted only as `'none'`, and
  `form-action` may not be declared at all, because any value blocks the
  cross-origin redirect that completes a successful consent. `'none'` alongside
  another source is refused rather than passed through — browsers ignore it in
  that position, so accepting it would turn "forbid framing" into "allow it".
- `op.WithMTLSRootCAs`, which installs the trust anchors the OP validates a
  client certificate against before using it for RFC 8705 §3 token binding.
  `internal/mtls` supported chain validation but nothing could reach it, so the
  check and its error were unreachable. It matters most behind a reverse proxy,
  where the OP cannot see the validation the proxy performed. A nil pool is
  refused at construction: an empty `x509.CertPool` is how "trust nothing" is
  spelled, and accepting nil would silently mean "trust whatever the transport
  supplied".
- `op.MTLSProxy`, the public name for the value `op.WithMTLSProxy` records and
  `op.MTLSProxyConfig` reads back. The accessor previously returned a type from
  an internal package, so no caller outside the module could declare a variable
  of it or construct one — the symbol's only intended use was unreachable.
- `profile.MaxRequestObjectAge`, the per-profile bound on how old a signed
  request object's `iat` may be.
- `op.EmailOTPConfig.LockoutStore`, which puts a directly constructed
  `op.NewEmailOTPAuthenticator` on the same cross-factor brute-force counter
  `op.WithAuthnLockoutStore` attaches to the built-in `op.StepEmailOTP`. Without
  it such an authenticator is budgeted only by the per-challenge failure count
  on its own record, so an attacker who has burned their TOTP allowance can
  pivot to email OTP for a fresh one. `op.WithAuthnLockoutStore` now says so in
  its own documentation, since the gap is silent rather than an error.
- `recoverykit.Kit` and `recoverykit.Clock`, so recovery-code generation and
  replacement can be driven against an injected clock instead of the system
  one. The package-level `recoverykit.Generate` and `recoverykit.Replace` are
  unchanged and remain the zero-configuration entry points.
- The store contract suite covers the insert-if-absent form of
  `store.EmailOTPStore.CompareAndSwap`, including two first sends racing on the
  same empty key. That call is how the first send for a subject reserves its
  record, and a backend implementing it as an unconditional upsert passes every
  other case in the suite while letting a concurrent send reset the send-rate
  and brute-force windows the reservation exists to hold. The interface
  documentation now states the condition instead of leaving it implied by the
  bundled adapters.
- `op.ProtectedResource.IntrospectionClients`, which names the client_ids that
  authenticate at `/introspect` on that resource server's behalf. A named client
  may introspect an access token issued to any client provided the token's
  audience is that resource — RFC 7662's canonical deployment, and previously
  impossible: a resource server that followed the OP's own protected-resource
  metadata to the introspection endpoint authenticated successfully and received
  `{"active": false}` for every token it would ever see. The delegation is
  scoped to the audience, so registering a gateway for one API never becomes
  blanket visibility over every client's tokens, and it does not cover refresh
  tokens. Naming no client keeps the previous same-client-only posture exactly.
- The store contract suite exercises the transactional path of the substores
  that carry a revocation cascade: refresh-token consume and rotation, chain and
  grant revocation, the retry-response store, and both access-token stores. The
  transactional group previously covered only authorization codes, grants and
  pushed authorization requests, so a backend could ship a broken transactional
  implementation of the machinery RFC 9700 §2.2.2 replay detection runs on and
  still pass the suite clean.
- `make verify-examples-api`, `make verify-examples-browser` and
  `make verify-examples-harness` run the example verification harnesses, which
  boot each example as a real process. They existed but nothing invoked them,
  which is how three examples shipped in a state where `/authorize` returned
  `server_error` from the first step of their documented walkthrough. `make
  verify` states that it compiles examples without booting them; CI runs the
  runtime gate as a separate job.
- The store contract suite gains a concurrency group asserting that consume,
  rotation and increment operations have exactly one winner under parallel
  callers, and that a revocation window converges on the widest horizon.
- `op.Provider.Shutdown(ctx)`, which waits for detached back-channel logout
  fan-outs to finish. Because delivery no longer runs on the request, a SIGTERM
  during a rolling deploy would otherwise end the process with signed Logout
  Tokens still queued and the RPs never told the session ended. It is a drain,
  not a close: the provider keeps serving afterwards, so stop accepting requests
  first and drain second. Safe to call unconditionally — a provider that never
  mounts `/end_session` returns nil — and safe to call repeatedly.
- `op.WithBackchannelFanOutBudget`, which sets the overall deadline for one
  back-channel logout fan-out. The default is 30 seconds.
- `op.WithBackchannelAllowPrivateNetwork`, which permits back-channel logout
  delivery to private-network destinations. Needed for a deployment whose RPs
  genuinely sit on an internal network; see the Security note above for the
  default.
- `op.PrimaryPasskey.RequireUserVerification`, which makes every WebAuthn
  ceremony demand user verification rather than accepting presence alone.
- `oidcsql.Store.GC(ctx, cutoff)` with `oidcsql.GCStats`, reclaiming expired rows
  from the authorization-code, pushed-request, interaction and session tables.
  The SQL adapter previously had no retention path for them, so a deployment
  accumulated one row per authorization request forever. It is a single
  aggregate call on the store's existing pool with no goroutine of its own —
  scheduling is the embedder's, because only they know their maintenance window.
- The in-memory adapter reclaims expired authorization codes, sessions,
  interactions and lockout counters. Without it an unauthenticated `/authorize`
  loop grew the process until it ran out of memory.

- `store.GrantSubjectLister` with `ListSubjectsByClient` and
  `store.GrantSubjectPage`, the keyset-paginated counterpart to the existing
  `ListClientIDsBySubject`, plus `RegistrationOption.OnClientDeletedSnapshot`.
  Deleting a dynamically registered client can now send that client its own
  signed Logout Token: the registration endpoint snapshots the client record
  and a bounded page of its granted subjects *before* the delete, then drives
  the fan-out from the snapshot, which is the only order that works — after the
  delete there is no client left to resolve a `backchannel_logout_uri` from.
  The built-in path engages when the configured grant store exposes both
  bounded grant indexes; a store exposing neither keeps the existing
  `OnClientDeleted` hook and acquires no new start-up requirement. The optional
  interface is bounded on purpose: an implementation must cost `limit+1` rows,
  not a materialised enumeration of every grant the client holds. The bundled
  inmem, SQL and DynamoDB adapters implement it.

- `store.RegistrationAccessToken.AllowedScopes`, the immutable scope ceiling a
  registration access token inherits from the initial access token that minted
  it. Empty means unrestricted, which is what every token issued before this
  release carries. Without it the ceiling an IAT declared applied at `POST
  /register` and then evaporated: the client's own `PUT` could name any
  registered scope, so a constrained onboarding token bought a constraint that
  lasted one request.

- `op.AuditGrantManagementRevokeFailed` (`grant_management.revoke_failed`) and
  `op.AuditRefreshPriorAccessTokenRevokeFailed`
  (`refresh.prior_access_token_revoke_failed`), raised when a revocation that
  ran behind an already-written success response did not complete. Both carry
  the stage that failed and whether the failure is retryable. These are the
  side effects a 200 or a 204 cannot report, so without an event they were
  invisible: the client saw a successful rotation or a successful grant
  deletion while a prior access token stayed live.

- `devicecodekit.VerifyUserCodeByAttemptKey`, which charges a caller-supplied
  opaque ceremony key before it normalizes or looks up the submitted
  `user_code`, together with the `devicecodekit.AttemptLimiter` interface,
  `devicecodekit.ErrAttemptLocked`, `devicecodekit.Deps.AttemptLimiter` and a
  bundled `devicecodekit.InMemoryAttemptLimiter`
  (`NewAttemptLimiter` / `NewAttemptLimiterWithOptions` /
  `AttemptLimiterOptions`). A verification page previously had to budget
  manual entry against the short user code itself, which makes the brute-force
  subject the very value being guessed — a wrong guess spends someone else's
  budget, and a correct one has already succeeded. Charging the ceremony key
  instead bounds the entry attempts of one browser session. A key that has
  spent its budget is refused before any lookup, and `Reset` stays an explicit
  ceremony-owner operation. The bundled limiter is bounded by a fixed key
  ceiling, a ceremony TTL and lazy eviction, so the fallback cannot grow with
  attacker-supplied key material; a multi-process deployment supplies its own
  backed by a shared store.

### Deprecated

- `devicecodekit.Deps.Audit` — its interface type takes a package-internal
  event type, so it cannot be implemented outside this module. Use
  `devicecodekit.Deps.AuditLogger`. The field is still honoured and still takes
  precedence when both are set.

The three below are deprecated on documentation grounds. Nothing listed there
is removed, and none of it changes behaviour: each symbol turned out to do less
than its documentation claimed, and the godoc now says what it actually does.

- `op.AuditDenyReasonKey` — no code path emits it. A denied login is recorded
  under a plain `reason` attribute; match that instead. See the Security note
  above for what this means for anything you put in `op.Deny.Reason`.
- `op.SPAUI.ConsentMount` and `op.SPAUI.LogoutMount` — no handler reads either.
  The consent ceremony is served through the `LoginMount` routes and
  discriminated by the state envelope's prompt type; the logout confirmation is
  the OP's built-in page. Both values are still validated, but reserve no route
  and change no routing.
- `op.Endpoints.Session` — nothing is mounted under this prefix and the
  discovery document does not advertise it. Setting it only changes which paths
  `op.New` reports as colliding. Session state is served under `Interaction`,
  or under `SPAUI.LoginMount` when an SPA owns rendering.

### Removed

Each symbol below could not be set by any caller: no code path in the library
filled it, and the public surface offered no way for an embedder to fill it
either. Nothing that was reachable stops working.

- **BREAKING:** `op.FederatedSubject`, `subject.FederatedSubject` and
  `subject.GeneratorInput.Federated`. A `SubjectGenerator` never saw a
  populated `Federated` value, because the library has no typed federation
  surface to produce one from. The capability itself is unaffected and needs no
  new API: an embedder that authenticates against an upstream returns the
  external identity as the subject (`interaction.Result{Subject:
  "provider:external-id"}`), and it arrives as `GeneratorInput.InternalUserID`.
  Making the identifier say which upstream a user came from is the embedder's
  to do; the generator's guarantee is that identifiers which do differ never
  project onto one `sub` within a sector.
- **BREAKING:** `op.CaptchaInput.Action`. No caller set it, so a
  `CaptchaVerifier` reading it always saw the empty string. Removing it is also
  what makes the two captcha surfaces agree: the `StepCaptcha` path left
  `RemoteIP` empty as well, so the same verifier was handed a different field
  set depending on which surface invoked it. Both now fill `Token` and
  `RemoteIP` identically.
- **BREAKING:** `subject.ErrInputBothSet`, which reported that both
  `InternalUserID` and `Federated` were set. With one field left there is no
  such state; an empty input still returns `subject.ErrInputEmpty`.

The godoc on `SubjectGenerator` described the wrong call contract and has been
corrected: `Generate` is called once per request that releases a `sub` — token
issuance, `/userinfo`, introspection, end-session and back-channel logout —
not once per `(user, client)` pair. A grant records the OP-internal subject and
the value is projected again on each of those surfaces, so a generator whose
work is priced per call pays it per release. Determinism is therefore
load-bearing rather than an optimisation.

## [v1.0.0] — 2026-07-27

The first release under strict Semantic Versioning. From here the public `op`
surface changes only on a major version, with one stated exception: symbols
carrying an experimental stability marker, which are listed in the API surface
manifest and gated mechanically so the exemption cannot grow silently.

The release itself is a hardening and durability pass across the token
endpoint, the storage layer, and construction-time validation. The
authorization-code, refresh, CIBA, and device-code flows stage their fallible
work behind transactions and single-use compare-and-swaps, so an approved
ceremony survives a signing or persistence fault; back-channel logout fans out
through keyset-paginated grant lookups; and `op.New` rejects a far wider class
of misconfiguration up front. No new protocol surface.

Two things do widen: the security posture becomes something a deployment
declares rather than inherits by omission, and the storage layer gains a third
adapter plus durable homes for every authentication factor.

Several store-interface and construction changes are breaking for custom store
implementations — see `Changed` for the migration notes. They are the last such
changes that can land outside a major version.

Signing is ES256 only, permanently for the 1.x line, and the reasoning is
documented rather than left as a gap. Deployments needing RS256 or PS256 should
not adopt this release.

### Added

- `profile.Baseline`, the OAuth 2.1 / RFC 9700 posture, so a deployment can
  state it instead of inheriting the permissive OIDC Core 1.0 shape by leaving
  the profile unset. Its only mandate beyond the library default is PKCE on
  every authorization-code request, including confidential clients — the case
  the OIDC Core shape admits without a `code_challenge`. Declaring a profile was
  already possible; what was missing was a name for the posture most deployments
  actually want, which meant the common case was expressed as an absence and
  read as one.
- `profile.RequiredGrants`, which fails `op.New` when a declared profile names a
  grant the OP was not wired to serve, with the error naming the option that
  activates it. Features a profile demands are switched on for the embedder;
  grants are not, because activating one pulls in collaborators only the
  embedder can supply — FAPI-CIBA needs the CIBA grant and everything behind it.
  Silently serving a profile minus its central grant is the failure this
  replaces.
- A `startup.profile` audit event emitted once per successful `op.New`, carrying
  the declared profiles, features, and grants alongside the policy they resolved
  to: PKCE / PAR / nonce mandates, sender constraint, token TTLs and formats,
  signing algorithm, and the DPoP-nonce requirement. The resolved posture is
  what an operator needs to read, and until now it existed only as the sum of
  the option set.
- `op/storeadapter/dynamodb`, a third storage adapter covering every `op/store`
  substore, published as its own module so the AWS SDK stays out of the main
  module's `go.sum` until an embedder opts in. Each substore gets one table with
  its key, index, and TTL attributes projected alongside the record as a JSON
  document, so a record-shape change needs no table migration. Expiry is
  enforced on read against the injected clock rather than trusting the TTL
  attribute — DynamoDB reclaims expired items asynchronously, so an expired code
  would otherwise stay redeemable for as long as the sweep lags. `store.Transactional`
  is backed by a write buffer that collapses repeated writes per item and commits
  as one `TransactWriteItems`, with each buffered action carrying the condition
  its read justified and reads consulting the buffer first; every security
  decision reads through a strongly consistent `GetItem`. `CreateTables`
  provisions for development while `TableDefinitions` exposes the same key
  schemas to infrastructure tooling. The adapter's `Store` is listed in
  `api/experimental.txt`: its construction and option surface may change in a
  minor release.
- The SQL adapter implements every authentication-factor substore —
  `store.TOTPStore`, `PasskeyStore`, `RecoveryStore`, `EmailOTPStore`, and
  `AuthnLockoutStore`, reached through `TOTPs()`, `Passkeys()`,
  `RecoveryCodes()`, `EmailOTPs()`, and `AuthnLockouts()`. They stay off
  `store.Store`, so a deployment enabling no second factor need not provision
  their tables, and the accessor names mirror the in-memory reference. The
  `totp_secrets`, `passkeys`, `recovery_codes`, `email_otps`, and
  `authn_lockouts` DDL ships for SQLite, MySQL, and PostgreSQL, renameable
  through the same `WithNaming` keys as the rest. PostgreSQL declares the
  boolean-shaped columns as `SMALLINT` because pgx refuses an integer bind
  parameter for OID 16 and one bind shape has to work across all three dialects.
- `examples/00-security-profile`, which boots two OPs from an otherwise
  identical option set — one with no profile, one declaring `profile.Baseline` —
  and sends the same confidential-client authorization request without
  `code_challenge` to each. The OIDC Core shape admits it; the baseline refuses
  it with `error=invalid_request`. Both route through one audit logger, so the
  `startup.profile` records show the resolved posture before the first request.
- `examples/18-dynamodb-store`, the DynamoDB adapter driving a browser
  authorization-code flow with every durable and volatile substore on it. It
  reads `DYNAMODB_ENDPOINT` to choose its wiring — placeholder static
  credentials against an emulator, the ambient AWS configuration otherwise — and
  ships a compose stack that keeps the emulator off the host network. It is its
  own sub-module so the AWS SDK stays out of the main module's `go.sum`.
- `op.WithUserStore`, which points claim reads at an embedder-owned user store
  while leaving every other substore of the `WithStore` backend untouched.
  Projecting an application's existing users table onto OIDC is the ordinary
  way to adopt the library, and until now it required hand-writing a wrapper
  type that shadows `Users()` on the backend store. That wrapper has a trap in
  it: built out of the `store.Store` interface rather than the concrete
  backend, it compiles and silently drops every optional capability the backend
  implements, so features that depend on those capabilities disable themselves.
  The option resolves between two values instead of wrapping anything, so
  nothing can be lost. `examples/24-byo-userstore` now uses it and no longer
  carries a wrapper type at all.
- A construction-time warning when the login flow authenticates against
  different user records than the ones claims are read from. The two wirings
  are separate by design — a `Step` owns its store so a deployment can
  authenticate against something that is not the claim source — but when they
  diverge by accident nothing fails: the login succeeds, a subject is resolved,
  and the ID Token is then assembled from a row in another table. The bundled
  adapters return one value for both `Users()` and `UserPasswords()`, so an
  ordinary single-store setup stays silent.
- `op/recoverykit`, the enrolment half of recovery codes. `StepRecoveryCode`
  could spend a code but nothing public could mint one: the code alphabet, the
  batch size, and the argon2id parameters are fixed by the verifier and live
  behind `internal/`, so an embedder had no way to build a `RecoveryBatch` the
  login flow would accept. `Generate` returns the batch for a caller that wants
  to persist it inside its own transaction; `Replace` writes it and only then
  hands back the plaintext, so a storage failure cannot leave a user holding
  codes that will never verify. The plaintext is returned separately from the
  persisted batch and is display-once.
- `op/passkeykit`, the enrolment half of passkeys. `op.PrimaryPasskey` could
  assert an existing credential but nothing public could create one — the
  registration ceremony, the WebAuthn session, and the credential projection
  all lived behind `internal/`, so a login flow could demand a factor no
  embedder could enrol a user in. `Registrar.Begin` returns the creation
  options and the ceremony session as separate values so a handler cannot leak
  the session to the browser along with the challenge; `Finish` returns the
  record for a caller that owns the transaction, and `Register` persists it and
  only then reports success. `New` takes the very `op.PrimaryPasskey` value the
  login flow installs, so the Relying Party identity a credential is registered
  under and the one it is later checked against cannot drift.
- `examples/29-passkey`, the passkey lifecycle end to end: enrolment on a page
  the example owns, then a login whose second factor appears only once a device
  is registered. It binds `localhost` rather than the `127.0.0.1` every other
  example uses, because a WebAuthn Relying Party ID must be a domain and
  browsers reject an IP literal for it.
- `examples/28-email-otp-recovery`, the two factors that need no hardware and
  no authenticator app: a mailed one-time code with a printed recovery sheet
  behind it. It also shows the `Decider` seam being used for the fallback,
  because the flow has no notion of the *user* asking for a different factor —
  policy decides, and "the user keeps failing the mailed code" is the signal.
- `examples/17-spa-composite-store`, the SPA interaction seam running against
  MySQL durable + Redis volatile storage. Both halves already had examples and
  they are genuinely independent, but the combination is what gets deployed and
  neither example showed it. Ships a `compose.yaml` like `07` and `09`.
- `Provider.LocaleResolver().Message(...)` exposes read-only lookup of the
  merged message catalogue for custom server-rendered pages and out-of-band
  UI. Missing keys fall back to the configured default locale; the returned
  string is plain text, so non-HTML callers retain control of output encoding.
- `op.AuditEventCatalog`, a copy-safe public inventory of every stable audit
  event and its optional Prometheus projection. The same typed registry now
  drives in-tree emitters and the metrics bridge. Logout persistence failures,
  back-channel resolution/overflow, DCR cascade failures, device poll
  observation faults, and custom-grant outcomes are included in the catalog
  and counters.
- `store.StaticClientReconciler`; `WithStaticClients` now applies the entire
  configured set as one atomic, idempotent batch (insert missing, no-op on
  equivalent records, `ErrConflict` on divergent or non-static rows). The
  reconciliation runs only after every other fallible build step, so a failed
  `op.New` never leaves partial client records behind. Implemented in the SQL
  and in-memory adapters.
- `store.DeviceCodeStore.Revoke` and the public `devicecodekit.Revoke` helper.
  `Revoke` atomically transitions pending and approved device-code records to
  denied so a later `/token` poll cannot issue credentials, while the helper
  cascade-revokes every credential surface sharing the device grant lineage
  per the configured `RevocationStrategy` and emits an `AuditDeviceCodeRevoked`
  event. Implemented in the in-memory and SQL adapters.
- `store.RefreshRetryResponseStore` persists an already-sealed refresh response
  against its consumed predecessor so the OP can re-emit the exact response on
  the RFC 9700 grace path instead of branching the token chain; the SQL adapter
  stores it in a new `retry_response` column written atomically with the
  successor.
- `RevokeByClient` cascade on the access-token and opaque-access-token
  substores (with the matching SQL queries), so a client-scoped revocation
  reaches every issued token.
- Redis `store.SessionStore` — session state backed by the Redis adapter and
  bound to the Redis TTL (compose it with a durable backend for grants and
  credentials).
- A strict OFCS release verifier, separate from the historical regression
  diff. It rejects persistent non-PASS results, empty results, module-catalog
  drift, and stale or expired exceptions; the only accepted exceptions are
  exact entries in a clean, checked-in owner/reason/expiry manifest.
- `api/experimental.txt`, the machine-generated inventory of every symbol
  carrying an `Experimental:` marker. The marked set is the SemVer exemption
  list and everything else is stable by default, so the report is regenerated
  and diffed by `make verify`: a change to the exempt surface now arrives as a
  reviewable diff next to the code that caused it. A marker without a
  rationale, or a symbol claiming both `Experimental:` and `Stable since`, is
  rejected rather than resolved silently toward exempt.
- `sample/`, a reference application covering the arc the single-concept
  examples skip: registration owned by the application, Argon2id password
  storage, login and consent through a `interaction.Driver` the application
  implements itself, TOTP enrolment from account settings, and a relying party
  completing the round-trip — on MySQL plus Redis joined by
  `op/storeadapter/composite`, under one `docker compose up`. Its consent page
  is a worked example of granular per-scope consent, which the bundled HTML
  driver declines to offer. It is a demonstration, not a deployment: the schema
  is one embedder's model rather than a recommendation, and the application is
  not meant to be hosted.
- `cmd/op-demo` accepts `-store=composite` with MySQL and Redis DSNs, so an
  OFCS baseline can be captured against the storage shape a deployment runs
  rather than against memory. It became its own Go module in the process, which
  keeps both drivers out of every library consumer's dependency graph.

### Changed

- `WithAllowLocalhostLoopback` now also admits the textual `localhost` host in
  the issuer, not only in redirect URIs. Two rules that are each correct left a
  local WebAuthn deployment nowhere to stand: a Relying Party ID must be a
  domain and browsers reject an IP literal for it, while the issuer rule
  restricted plain http to loopback IP literals — so no local http issuer had a
  usable RP ID to pair with. The default posture is unchanged and still refuses
  `localhost`. As a consequence the issuer is validated during `op.New`'s
  validation pass rather than inside `WithIssuer`, so the carve-out is seen
  whichever order the options are given in; a malformed issuer still fails
  `op.New` with the same error.

- **BREAKING — `op.New` now rejects a configuration where the `refresh_token`
  grant is enabled and cookie keys are set but `Store.RefreshTokens()` does not
  implement `store.RefreshRetryResponseStore`.** The rotation path seals a
  durable retry response whenever it holds encryption keys, and those keys are
  the cookie keys the `authorization_code` grant already makes mandatory, so a
  bring-your-own refresh store without the extension compiled, passed `op.New`,
  served authorization requests, and then failed every rotation at request
  time. *Migration:* implement `RefreshRetryResponseStore`; the bundled
  adapters already do, so only external backends are affected — and those were
  already failing rotation. The store package now states the capability
  placement rule normatively and publishes the requirement matrix it implies,
  covering both the extensions `op.New` demands and the ones that degrade
  silently.
- ES256 is the only supported token-signing algorithm, and that is now a stated
  permanent policy for the 1.x line rather than an unfilled gap. The discovery
  document, the conformance exclusion manifest, and the documentation all say
  so; RS256 and PS256 are not planned.
- **BREAKING — authorization-code stores must now implement
  `store.Transactional`, and their interaction substore must implement
  `store.InteractionStoreCAS` (`CompareAndSwap` and `DeleteIfUnchanged`).**
  Authorization completion persists an immutable retry intent, commits
  Grant / PAR / authorization-code mutations together, establishes the Session
  idempotently, and deletes the interaction last; silent and first-party
  auto-consent mints use the same transaction boundary. *Migration:* BYO stores
  that enable `grant.AuthorizationCode` must add a real `BeginTx`
  implementation and atomic expected-`RawState` interaction transitions; the
  SQL, in-memory, and `examples/26-byo-store-from-scratch` implementations are
  references. Transaction-bound Grant reads must lock rows, use serializable
  isolation, or surface an equivalent optimistic conflict before Save so
  concurrent scope/RAR merges cannot lose updates.
- **BREAKING — `store.GrantStore` now requires
  `ListClientIDsBySubject(ctx, subject, cursor, limit)`.** Back-channel logout
  uses this distinct, keyset-paginated view to bound both grant query results
  and client-registry lookups before target resolution, pulling one bounded
  page per notice and emitting an overflow event with the next cursor instead
  of scanning every grant row; it advertises
  `backchannel_logout_session_supported: false` since grant-based fan-out
  retains no RP-specific session lineage. `ListClientIDsBySubject` lives on a
  new optional `store.GrantClientLister` extension, so machine-to-machine
  backends that never mount the browser `authorize` / `end_session` endpoints
  need not implement it; `op.New` rejects an interactive configuration whose
  `GrantStore` lacks it. *Migration:* implement a stable ascending client-ID
  query returning at most `limit` IDs plus `NextCursor` when another page
  exists — do not delegate to `ListBySubject` and slice its full result. The
  in-memory, SQL, and `examples/26-byo-store-from-scratch` adapters show the
  required semantics.
- **BREAKING — trusted-proxy mTLS certificate headers now accept exactly one
  field containing one raw or percent-encoded `CERTIFICATE` PEM block.**
  Duplicate fields, PEM chains, and trailing non-whitespace data are rejected
  as `ErrCertMalformed` instead of silently selecting the first certificate.
  The forwarded certificate is no longer compared with the handshake leaf: on
  dual-mTLS / mesh hops the handshake leaf identifies the proxy transport, so a
  mismatch is the normal topology, not an attack. *Migration:* configure the
  TLS terminator to strip the inbound header and forward only the verified
  OAuth client leaf.
- **BREAKING — account-lockout state moves to a versioned
  `AuthnLockoutStore.CompareAndSwap` contract keyed on an opaque
  backend-managed `Version`,** replacing the earlier `StampLock` extension.
  Failure increment, window rollover, lock stamping, and success reset apply as
  one transition recomputed from the latest record until it commits, so
  parallel failures across factors cannot lose updates and a concurrently
  committed failure is never erased by a stale reset. *Migration:* BYO lockout
  stores must implement `CompareAndSwap`; the in-memory reference and the
  reusable adapter contract show the semantics.
- **BREAKING — passkey stores must now implement
  `store.PasskeyStore.UpdateAssertion` (`PasskeyAssertionUpdate`),** which
  commits sign-count, clone-flag, and last-used fields as one atomic write
  instead of a whole-record `Put` that could rewind security state. *Migration:*
  BYO passkey stores add `UpdateAssertion`; the in-memory reference implements
  it.
- **BREAKING** — an `EncryptionKey`'s `NotAfter` is now a hard retirement
  deadline: on or after it the OP refuses to decrypt for that `kid` and drops
  the public half from the published JWKS, so RPs are never directed to a
  recipient the OP can no longer decrypt for.
- The zero-configuration `interaction.HTMLDriver` now consumes the same locale
  resolver as `/authorize`: `WithLocale` additions and overlays are reflected
  in password-page titles, labels, and submit buttons; untranslated keys retain
  the built-in English fallback, and all translated output is HTML-escaped at
  emission.
- **BREAKING** — the token-endpoint transaction view (`Tx`) gains
  `AccessTokens`, `OpaqueAccessTokens`, and `GrantRevocations`, and the TOTP
  and email-OTP substores gain `CompareAndSwap` (with an in-memory
  implementation); BYO stores backing these surfaces must implement the new
  members.
- The lax OIDC Core 1.0 §11 reading of `offline_access` (an `openid`-only grant
  may refresh) is the default and is now applied consistently to the
  authorization-code issuance path as well as the refresh exchange;
  `offline_access` is required only under `op.WithStrictOfflineAccess`.
- Endpoints now mount under the issuer URL path: an issuer like
  `https://idp.example.com/tenant` serves the token endpoint at
  `/tenant/oidc/token` and matching paths for every protocol handler, with the
  `.well-known` suffix placed before the issuer path per OpenID Connect
  Discovery 1.0 so advertised and mounted URLs agree. `Endpoints` overrides are
  validated as clean absolute paths at construction (query strings, fragments,
  duplicate slashes, percent-encoding, and wildcard syntax are rejected).
- Back-channel logout deliveries dispatch through a bounded worker pool
  (`DefaultMaxConcurrentDeliveries`) with the deduplicated audience capped at
  `DefaultMaxTargets`; the HTTP deliverer adopts only an embedder client's
  `Transport`, keeping redirect, timeout, and dial-time SSRF policy mandatory.
- `examples/27-durable-mfa-store` reads `storage.TOTPs()` from the SQL adapter
  instead of carrying a hand-written substore with its own DDL and migration
  step, and wires the cross-factor lockout counter to the same database through
  `op.WithAuthnLockoutStore(storage.AuthnLockouts())`, so the guess budget is
  one budget across restarts and replicas. The example existed to fill an
  adapter gap that no longer exists; what it demonstrates now is durable factor
  persistence, with examples 28 and 29 covering the sibling factors. Its test
  narrows to the one claim it still adds — that factors survive a restart —
  since replay rejection, compare-and-swap, and error spellings are pinned by
  the adapter's own contract run.

- **BREAKING — `op.Require` names a step kind instead of carrying a step.**
  The field changes from `Step Step` to `Kind StepKind`. `Require` never
  introduced a step: the orchestrator resolved it by kind against the steps the
  flow declared and read nothing else off the value, so a `Decider` that
  returned a fully-configured `Require{Step: op.StepRecoveryCode{Store: st}}`
  had its store silently ignored, and a kind the flow had not declared failed
  the login at request time. The godoc promised the opposite ("a Decider can
  drive arbitrary step-up chains"), which is how the shipped
  `examples/28-email-otp-recovery` walked into it. Selection-only is the
  intended semantics — it is what keeps the factors a login can demand readable
  off the `LoginFlow` — so the type now says so. *Migration:* replace
  `op.Require{Step: s}` with `op.Require{Kind: s.Kind()}`, and declare the step
  on the flow if it is not there already; a step only the `Decider` schedules
  is declared as a `Rule` whose predicate never fires.

### Removed

- **BREAKING — `profile.IGovHigh`.** The constant named a profile whose
  constraint table was never written: `op.New` rejected it unconditionally, and
  every profile predicate answered it with the permissive arm. An exported
  identifier that cannot be constructed with is not a reservation, it is a
  promise the library was not keeping, and after this release it could not be
  withdrawn without a major version. *Migration:* none — no configuration that
  named it could ever boot. It was the last enumerator, so the values of the
  remaining constants are unchanged.

### Security

- Passkey `AAGUIDAllowlist` is enforced against an authenticated AAGUID.
  Previously `PrimaryPasskey` requested no attestation at all, so the AAGUID the
  allowlist compared was a plain field of the registration response rather than
  something the hardware proved — a software authenticator could register by
  naming an approved model. Configuring an allowlist now switches the ceremony
  to `direct` conveyance, and a registration whose attestation does not identify
  the model (self-attested or unattested) is refused instead of being matched
  against the list. **BREAKING** at the `passkey.Config` level: pairing
  `AAGUIDAllowlist` with any conveyance other than `direct` is now a
  construction error. Embedders using `op.PrimaryPasskey` need no change beyond
  expecting a user-agent attestation prompt during registration; leave
  `AAGUIDAllowlist` empty to keep the previous prompt-free ceremony.
- mTLS proxy header: a payload carrying more than one PEM block is rejected by
  counting block markers before decoding, rather than by checking what the PEM
  decoder reports as remaining input. The decoder skips a block whose base64
  body does not decode and returns the following block with an empty remainder,
  so a chain whose leading certificate was unparseable resolved to the trailing
  one — and a decoding step could produce that state on its own, because form
  decoding rewrites `+`, a base64 alphabet character, to a space and the PEM
  decoder strips spaces out of the body. Whoever composed the header could
  therefore choose which leaf the OP bound. Percent-decoding is now attempted
  before form-decoding so an unescaped payload is not rewritten at all.
- JAR: every URL-indexed JWKS cache is bounded with LRU-style eviction and
  expired-entry pruning, and a document carrying more keys than the parse cap is
  rejected, so hostile client registrations cannot grow process memory without
  bound.
- The remote client-resolver caches (client encryption JWKS and the
  sector-identifier resolver) share one size-bounded TTL/LRU primitive with
  per-key singleflight and negative caching, giving URLs controlled by clients a
  bounded entry count and a negative TTL.
- DPoP: the replay-protection record is namespaced by proof thumbprint
  (`dpop:<jkt>:<jti>`) so two distinct proof keys reusing one `jti` no longer
  collide, while a replay by the same key still surfaces as a replayed proof.
  The thumbprint is computed before the record is marked, preserving the
  malformed-proof-never-advances property.
- Authenticators: TOTP and email-OTP verification uses a `CompareAndSwap` retry
  loop so concurrent wrong-code attempts each advance the brute-force counter
  instead of a stale writer clobbering the winning state; email-OTP resend
  reserves its challenge before invoking the mailer so a racing resend cannot
  reuse a stale rate-limit snapshot.
- Sender-constraint (DPoP / mTLS) checks and revocation checks now run ahead of
  the single-use `Consume` on the refresh exchange and are fail-closed before a
  fresh access token is minted.
- Token exchange enforces the OIDC Core required claim set (`iss`, `sub`, `aud`,
  `exp`, `iat`) with time bounds when a `subject_token` is an ID token — so the
  mandatory source-token TTL cap always has a live `exp` — and decodes `aud` in
  both RFC 7519 shapes, rejecting missing, empty, or malformed values as an
  invalid token.
- Redact MySQL and Redis connection credentials from the storage examples'
  startup diagnostics. The Redis adapter now also returns a generic parse error
  for malformed DSNs, so an invalid percent-encoded credential cannot be copied
  into an error message; `oidcredis.RedactedDSN` provides the same structural,
  fail-closed representation for embedder logs.
- Harden `op.LoadPublicJWKS` into a public-member allowlist normalizer:
  symmetric `oct` and unsupported key types are rejected, while RSA, EC, and
  OKP inputs retain only their key-type public parameters and standard public
  JWK metadata. Private and unknown extension members can no longer survive by
  falling outside a private-parameter denylist.

### Fixed

- Passkey registration could never succeed. The WebAuthn session ferried
  between the two halves of the ceremony dropped the list of credential
  algorithms announced at the start, and the verifier checks the new
  credential's algorithm against that list — an empty list matches nothing, so
  every registration was rejected as an invalid attestation. The list is now
  re-derived when the session is decoded. The gap survived because no test ran
  a registration to completion; the ceremony is now exercised end to end
  against a real ES256 authenticator, including the login that follows it.
- `examples/26-byo-store-from-scratch` did not implement
  `store.RefreshRetryResponseStore`, so the example that exists to teach the
  store contract could not boot against the version of the contract this
  release ships. The store contract suite gained a case for the extension,
  which is what found it: the interface is required whenever the refresh grant
  runs with cookie keys, yet nothing in the suite exercised it, so any backend
  could implement it wrongly — or not at all — and still come up green. The
  case pins the association a retry depends on, that the sealed response is
  reachable by the predecessor the client presents.
- The reference application's container built on a Go release older than the
  module requires, and its build context reached the repository root, where a
  `go.work` naming a member set without `sample/` stops the build outright. The
  base image tracks the toolchain and a `.dockerignore` keeps workspace files
  out of the context — the failure only appeared on a release commit, which is
  where the workspace file is generated.
- `examples/28-email-otp-recovery` required a recovery step the flow had not
  declared, so the fallback it exists to demonstrate ended in HTTP 500 with
  nothing logged. The example now declares the step and its `Decider` ends the
  login itself once the recovery code is accepted; without that last part the
  failure count that opened the fallback keeps re-selecting a completed step
  and the flow asks for the unreachable mailed code again. The browser harness
  gained cases for both paths, which is what surfaced this.
- Documentation and comments across the tree cited internal design notes,
  audit-finding identifiers, and work-phase labels that do not ship with the
  repository, and named other OpenID Connect implementations by project. Each
  now states the constraint or the divergence itself. Stability markers claimed
  the API had been stable since a `v0.x` release — a promise that did not exist
  before this one — or carried an unfilled `v0.x` placeholder; all of them now
  read `v1.0`. `SECURITY.md` states the supported-version window for a 1.x
  line.
- Conformance harness: an authorization response in `form_post` mode with no
  prompt to walk — the second leg of `prompt=none`, `id_token_hint`, and
  `max_age` — left the driver looking for an interaction page that was never
  going to arrive, so four modules stalled without a verdict while the same
  modules passed in redirect mode. The strict release gate now refuses to treat
  a module that reached no verdict as a skip, and reports the two that remain
  genuinely undrivable in a section of their own with the evidence for each.
- Conformance binary: wrapping the store for the FAPI-CIBA profile hid every
  optional capability the concrete store exposes, because the wrapper embedded
  the `store.Store` interface rather than re-declaring them. Dynamic
  registration refused to boot under that profile; static-client reconciliation
  and transaction staging turned themselves off with no error at all.
- Refresh exchange (RFC 9700 grace path): post-preflight mutations are staged
  behind a transaction and the buffered response is forwarded only after commit,
  so a signing, JWE, cache, or write failure rolls `Consume` back instead of
  stranding the predecessor token. With a retry-response cache configured, a
  bearer grace retry re-emits the exact sealed response from the original
  rotation. A sender-constrained (DPoP / mTLS) grace retry re-mints the access
  token bound to the key the retry presents — a confidential client may rotate
  its DPoP key across refreshes (RFC 9449 §5), and replaying the originally
  bound token would hand back one the client can no longer use, failing every
  resource call with a `cnf` thumbprint mismatch — while re-emitting the
  original successor refresh token, so the chain is never rotated twice.
- CIBA and device-code polls assemble the fallible token bundle (signing plus
  opaque/refresh persistence) before the single-use `Consume` CAS; a poll that
  loses the CAS discards its pre-persisted credentials, so an approved ceremony
  is no longer lost to a signing or persistence fault while single-use is
  preserved.
- Preflight RFC 9396 `authorization_details` against the live Grant before the
  refresh `Exchange` consumes the predecessor token (the token snapshot stays
  the fallback for missing or sparse grants). The preflight stays outside the
  write transaction to avoid a stale SQLite WAL snapshot; after `Consume`, the
  transaction re-reads the Grant and rolls back when its details changed, so a
  concurrent grant-management update neither mints stale authorization nor
  strands the predecessor token.
- Project the originating `GrantID` from opaque access-token records into the
  synthetic `/userinfo` claims so pairwise subject configurations recover the
  OP-internal subject; a legacy opaque record without a `GrantID` is rejected
  under pairwise projection instead of serving a wrong subject.
- Client registration rejects a `redirect_uris` or `post_logout_redirect_uris`
  entry carrying a bare trailing `#`. RFC 6749 §3.1.2 forbids a fragment
  component and an empty one is still a fragment; testing the parsed fragment
  admitted it, leaving a registered value a user agent truncates before the OP
  ever sees it, so the stored URI could never equal the one presented at
  `/authorize`. Registrations using that shape now fail with
  `invalid_redirect_uri` instead of succeeding into an unusable state.
- Dynamic client registration: map an explicit JSON `null` in optional metadata
  to the same empty value as an omitted property (RFC 7592 deletion) so
  `jwks: null` never reaches the JWK parser as a malformed set, reject
  `backchannel_logout_session_required` since the grant model retains no
  client-specific session lineage, and emit typed audit events when a
  delete-cascade revocation probe fails instead of dropping the fault.
- Passkey assertion state (sign-count, clone-flag, last-used) commits as one
  atomic write stamped from the exact record the signature was verified
  against, so concurrent assertions keep counters monotonic instead of a
  whole-record `Put` rewinding security state.
- Reject typed-nil login-flow, authentication, interaction, clock, and JWE
  private-key dependencies during `op.New` validation, distinguishing an absent
  nil interface (documented default) from an explicitly supplied typed nil, and
  validate configured endpoint paths for route collisions — configuration
  errors now surface before metrics registration, route construction, store
  writes, or an `http.ServeMux` panic.
- Bound in-memory refresh-token revocation by client or grant to the matching
  token set via client-ID and grant-ID secondary indexes under the refresh
  store's existing lock and transaction boundary, avoiding full token-map scans
  during DCR deletion and grant revocation without changing retained-record or
  replay semantics.
- The end-session handler records session-destroy, token-revoke, and
  back-channel resolution failures as distinct audit events while keeping the
  browser response non-blocking; `RevokeJWTAccessTokensByGrant` now returns
  store errors and the grant-management revoke path treats them fail-closed.
- Origin canonicalisation re-brackets a literal IPv6 host. `url.URL.Hostname`
  strips the brackets, so an issuer or configured origin using an IPv6 literal
  canonicalised to `http://::1:8080` — a form no browser sends — and never
  matched the incoming `Origin` header, rejecting every state-changing
  same-origin request and the CORS allowlist derived from the same value.
- Redis adapter: `WithKeyPrefix` and `WithMaxValueBytes` now surface an option
  error at construction instead of being silently dropped.
- The examples' relying-party kit encoded EC JWK coordinates in the minimal form
  `big.Int.Bytes` returns instead of left-padding to the 32 octets RFC 7518
  §6.2.1.2 requires. A coordinate starting with a zero byte — roughly one
  ephemeral key in 256 — produced a 31-octet value, and a conforming parser
  rejects the resulting JWK as malformed, so a FAPI 2.0 example failed at a rate
  low enough to read as a flake. Fixed-width encoding now applies to the DPoP
  proof header, its thumbprint, and the published JWK set alike, so all three
  agree.
- Corrected the public `grant.RefreshToken` and `ScopeNameOfflineAccess`
  documentation to match the historical issuance default: `openid` plus the
  client's `refresh_token` grant is sufficient, while requiring `offline_access`
  is an explicit `op.WithStrictOfflineAccess` opt-in. Runtime behaviour is
  unchanged.

## [v0.9.5] — 2026-07-13

A security-hardening release: no new protocol surface, but a broad sweep of
abuse-resistance and correctness fixes across PKCE enforcement,
`private_key_jwt` key selection, DPoP token binding, the authenticator chain,
PAR consume semantics, and session-cookie handling, plus a round of dependency
updates. One new option (`WithPARLifetime`) is added and one behaviour change is
breaking (PKCE is now mandatory for public and native clients).

### Added

- `op.WithPARLifetime` — override the lifetime of a `request_uri` issued by the
  PAR endpoint (RFC 9126 §2.2; default 60 seconds). Zero selects the default; a
  negative value is rejected at construction. The lifetime bounds only the
  presentation window at `/authorize` — the `request_uri` stays single-use at
  code emission, so an interactive login that outlives the lifetime still
  completes.
- A runnable durable SQL-backed `store.TOTPStore` example
  (`examples/27-durable-mfa-store`) as a copy-and-adapt template for the
  embedder-owned authentication-factor persistence gap, covered by contract and
  durability tests. Authentication-factor stores (TOTP, passkey, recovery codes,
  email OTP, lockout) are the embedder's responsibility; only the in-memory
  reference ships an implementation.

### Changed

- **BREAKING — PKCE (`code_challenge`) is now mandatory for public and native
  clients at `/authorize`, independent of the active profile.** A public or
  native client that omits `code_challenge` receives `invalid_request` at the
  authorization endpoint and no authorization code is issued; the OP never issues
  a non-PKCE code to these clients. *Migration:* register public and native
  clients with PKCE (S256). The token-endpoint PKCE downgrade guard remains as
  defense in depth.
- The `private_key_jwt` assertion verification key is selected by JWS `kid`
  (RFC 7515 §4.1.4), and trial verifications are capped whether or not a `kid` is
  present. `kid` uniqueness is unenforced, so a client serving many keys —
  including same-`kid`, same-`alg` duplicates — can no longer force one signature
  verify per key, bounding a DoS-amplification vector.
- Dependency updates: `go-webauthn/webauthn` v0.13.4 → v0.17.4,
  `golang-jwt/jwt/v5` v5.2.3 → v5.3.1, `golang.org/x/crypto` v0.53 → v0.54, and
  the SQL drivers (`go-sql-driver/mysql` v1.10.0, `jackc/pgx/v5` v5.10.0,
  `modernc.org/sqlite` v1.53). The unmaintained `mitchellh/mapstructure`
  dependency is replaced by the maintained `go-viper/mapstructure/v2` fork.

### Fixed

- Re-show the email-OTP verify prompt on a wrong code — preserving the delivered
  code — instead of restarting at the send screen, while still yielding to a
  pending captcha challenge.
- Honour the RFC 8252 loopback any-port allowance for `post_logout_redirect_uri`
  on native and public clients, matching `redirect_uri`.
- Surface a retryable, audit-visible error on TOTP and recovery
  compare-and-swap loss instead of silently re-prompting.
- Align the transactional in-memory PAR `Consume` — and the
  byo-store-from-scratch reference store — with the `PushedAuthRequestStore`
  contract: `Consume` enforces single-use only, and expiry is gated at
  presentation by `Find`, so an interactive login that outlives the `request_uri`
  lifetime still redeems exactly once. Pinned with a new transactional contract
  case so the implementations cannot drift.
- Equalise the `private_key_jwt` no-keys rejection timing with the
  wrong-signature path, and memoize the per-request client-store lookup during
  assertion verification (collapsing 2–4 `GetClient` calls into one).

### Security

- Reject DPoP-bound access tokens presented under the `Bearer` scheme at
  `/userinfo`; RFC 9449 §7.1 requires the `DPoP` scheme for sender-constrained
  tokens.
- Clear a tampered or undecodable session cookie at the authorization endpoint
  instead of carrying it forward.
- Reject private and symmetric keys during JWKS parsing; the prior type assertion
  was a no-op that let non-public key material through.
- Revoke the persisted opaque access-token row on every post-mint `server_error`
  path (id_token mint/encrypt failure, refresh-issuance failure, and the
  grant-tombstone mint refusal) via a shared helper, so no orphaned still-valid
  token lingers until TTL or GC.
- Raise the pinned Go toolchain to `go1.26.5` across the root module, the
  storage-adapter sub-modules, and CI to pick up the `crypto/tls` fix for
  GO-2026-5856 (Encrypted Client Hello privacy leak); the previously pinned
  `go1.26.4` is affected.

## [v0.9.4] — 2026-07-02

A security-hardening release: no new protocol surface, but a broad sweep of
correctness and abuse-resistance fixes across token exchange, mTLS binding,
the authenticator chain, refresh-token rotation, and the storage adapters.
Two device-grant options are added and the device-code lifetime is decoupled
from the access-token TTL (see Changed).

### Added

- `op.WithDeviceCodeExpiry` and `op.WithDeviceCodePollInterval` — the
  device-code lifetime and poll interval are now independent, configurable
  options defaulting to the device-grant defaults, instead of being derived
  from the access-token TTL.

### Changed

- **BREAKING — the device-code lifetime is decoupled from the access-token
  TTL.** The device flow previously derived its code lifetime and poll interval
  from the access-token TTL, so a short access-token lifetime made the device
  flow unusable. They now default to the device-grant defaults and are set
  independently via `WithDeviceCodeExpiry` / `WithDeviceCodePollInterval`.
  *Migration:* deployments that relied on a custom access-token TTL to size the
  device-code window must set the new options explicitly.
- **BREAKING — a non-zero refresh grace period is rejected under a FAPI 2.0
  profile at construction.** `op.New` now fails fast instead of silently
  allowing a refresh-token replay window that the FAPI 2.0 contract forbids.
  *Migration:* remove the refresh grace-period option from FAPI-profiled
  providers.
- The CIBA `binding_message` is validated (trim, length bound, control-character
  rejection) and persisted raw instead of HTML-escaped, so the authentication
  device shows the value the consumption device sent; the transaction-confirmation
  interlock is no longer broken for messages containing `& < > " '`.
- Strict-CORS responses now expose `DPoP-Nonce`, `WWW-Authenticate`, and
  `x-fapi-interaction-id` so a browser SPA can complete the DPoP nonce-retry loop.
- The unused `SubjectProjector` field on the authorize endpoint is removed;
  subject projection stays wired at the token, userinfo, and introspection
  endpoints.
- The Go toolchain is pinned to `go1.26.4` across the root module, the
  storeadapter sub-modules, and the examples, and the `golang.org/x/*`
  dependencies (`crypto`, `sync`, `sys`, `mod`, `net`, `text`, `tools`,
  `telemetry`) are bumped to their current patched releases.

### Fixed

- **Refresh replay-revocation race.** A rotation save can no longer outrun a
  concurrent chain revocation: the SQL adapter re-checks the parent under a row
  lock inside the rotation transaction, and the in-memory adapter performs the
  parent-still-alive check inside the same critical section as the insert. A
  replayed stolen refresh token's rotated descendant is now reliably revoked.
- Expired refresh tokens read as not-found on the SQL adapter, matching the
  in-memory adapter, so an expired-token replay no longer produces a false
  `replay_detected` audit and chain-revoke cascade.
- **mTLS token-binding collapse.** With a client-certificate forwarding header
  configured and a trusted proxy peer, the forwarded header certificate is
  authoritative for the `cnf` binding and a handshake/header thumbprint mismatch
  is rejected (`ErrCertSourceConflict`, 400 `invalid_request`) rather than
  silently binding the proxy's own certificate. `writeMTLSError` now maps
  `ErrCertUntrusted` to 401 `invalid_client` instead of falling through to 500.
- **`MinAAL` step-up enforcement** on the legacy authenticator chain:
  `RiskOutcome.MinAAL` is threaded from the risk assessor through the pre-factor
  consult into candidate selection, excluding authenticators below the required
  assurance level.
- The account-chooser (`select_account`) re-entry path seeds `acr` / `amr` /
  auth time from the selected session, so a chooser-only grant no longer
  downgrades to empty `acr` / nil `amr` in the id_token.
- The sector-identifier resolver evicts a stale entry on a content-hash change
  (a legitimately updated sector document recovers without an OP restart) and
  rejects a document with trailing bytes after the JSON array; pairwise
  sector-host derivation uses the URL hostname (port independent).
- The Redis chooser-group index key is given a TTL so abandoned sets no longer
  accumulate and evict live session keys under a volatile `maxmemory` policy.
- SQL table-name overrides are validated to be pairwise-distinct and
  non-colliding at construction, and the schema rewrite uses a single-pass
  exact-name substitution.
- `ConfidentialClient.TokenEndpointAuthSigningAlg` is now persisted by `seed()`;
  `WithMTLSProxy` config is stored on the provider config instead of a
  package-global map (no leak on hot-reload); the custom-grant clock access is
  nil-safe; and the kid-present JWE decrypt path gains the same alg/key-shape
  pre-check as its siblings.
- **RP key rotation for `private_key_jwt` clients that register a `jwks_uri`.**
  When a client-assertion is signed with a key whose `kid` is absent from the
  OP's cached copy of the client's `jwks_uri` keyset — the signal that the RP
  rotated its keys — the OP now performs a single cache-bypassing refetch and
  retries verification, instead of rejecting the assertion until the cache TTL
  lapses. The refetch is throttled per URL so an assertion replayed with random
  unknown `kid`s cannot amplify into unbounded outbound fetches.

### Security

- **Token-exchange down-scope invariant (RFC 8693).** The policy decision is
  re-verified after it is applied: the granted scope must remain a subset of the
  requested (subject-token-bounded) scope and the granted audience a subset of
  the requested audience. A broadening decision is rejected with `invalid_scope`
  / `invalid_target` plus an audit event, closing a privilege-escalation path
  where a policy bug could mint tokens for scopes or audiences the
  `subject_token` never carried. Subject-token audiences are normalised to the
  RFC 8707 canonical form before comparison.
- **2FA brute-force visibility.** TOTP, email-OTP, and recovery wrong-code
  branches route through the shared retry path, so a failure increments the
  counter and fires the observer, letting the captcha gate engage; the email-OTP
  delivery-failure branch is padded to stay constant-time.
- Audit events record a non-reversible fingerprint of the authorization code and
  refresh token instead of the raw secret.

## [v0.9.3] — 2026-06-14

### Highlights

- RFC 9396 Rich Authorization Requests, OAuth 2.0 Grant Management, and
  RFC 9728 protected-resource metadata land together: `authorization_details`
  is validated, persisted on the grant, and echoed on JWT access tokens and
  introspection; grants can be queried and revoked; and each registered
  resource advertises its protecting authorization servers.
- The SQL adapter now implements the device-code and CIBA substores, so
  `WithDeviceCodeGrant` / `WithCIBA` run on mysql / postgres / sqlite —
  previously these grants only worked on the inmem reference store.
- Refresh-token rotation now preserves the original authentication context
  (`auth_time`, `acr`, `amr`, `authorization_details`, and more), so
  refresh-derived id_tokens and JWT access tokens reproduce it faithfully.
- Client-supplied verification keys (`client_assertion` and JAR request
  objects) are now held to the OP key-shape floor — a breaking tightening
  for clients still signing with sub-floor keys (see Changed).

### Added

- **RFC 9396 Rich Authorization Requests.** `authorization_details` is
  accepted and validated against the `op.WithAuthorizationDetailTypes`
  registry at `/authorize`, `/par`, and `/token`, persisted on the grant,
  and echoed on JWT access tokens (RFC 9068 §2.2.3) and introspection
  (RFC 9396 §5, §10). Gated by the `RAR` feature flag; oversize requests are
  rejected as `invalid_request`, other malformed shapes as
  `invalid_authorization_details`.
- **OAuth 2.0 Grant Management** via `op.WithGrantManagement`: the
  `grant_management_action` / `grant_id` authorization parameters, the query
  and revoke endpoint, PAR push-time validation, and discovery advertisement.
- **RFC 9728 protected-resource metadata** via `op.WithProtectedResources`,
  served at the OP root well-known location per registered resource with the
  issuer stamped into `authorization_servers`.
- `op.StepUpChallenge` — builds the value of an RFC 9470 §3
  `WWW-Authenticate: Bearer` challenge (`error="insufficient_user_authentication"`
  plus `realm` / `acr_values` / `max_age`) for an embedder's resource server
  to return. The OP itself never emits the header; it honours the advertised
  `acr_values` / `max_age` when the client re-authorizes.
- `op/storeadapter/sql` device-code and CIBA substores, with new
  `oidc_device_codes` / `oidc_ciba_requests` tables across the three dialects,
  table-name overrides, and contract-harness coverage.
- `AuthnLockoutStamper` optional store extension (`StampLock`) — stamps
  `LockedUntil` atomically without a whole-row `Put`, closing the cross-factor
  lockout lost-update race. Stores that omit it fall back to `Get`+`Put`; the
  inmem reference implements it.
- `RefreshChainResolver` optional store extension — resolves hashed
  refresh-token pointers for the internal replay-cascade chain walk while the
  public `Find` / `Consume` lookups stay hash-only and constant-time.
- `jose.AssertJWEAlgKeyShape` and `jose.ParseJWKSet`, holding outbound JWE to
  the OP RSA floor and EC curve allow-list before encryption.
- `examples/25-byo-table-names` (remap every SQL adapter table to
  embedder-owned names) and `examples/26-byo-store-from-scratch` (implement
  the `Store` interface end to end without the bundled SQL adapter), both
  wired into the apiverify / browserverify harnesses.

### Changed

- **BREAKING — client verification keys held to the OP key-shape floor.**
  `client_assertion` keys (`internal/clientauth`) and JAR request-object keys
  (`internal/jar`) are now gated through `jose.AssertAlgKeyShape`
  (RFC 7518 §3.3 / RFC 8725 §3.2): RSA must be ≥ 2048 bits and the EC curve
  must match the declared `alg`. A sub-floor or curve-mismatched key is
  rejected as `ErrSigInvalid` rather than passed to go-jose under a laxer
  check. *Migration:* clients signing `client_assertion` or request objects
  with sub-2048-bit RSA or a mismatched EC curve must rotate to compliant keys.
- **BREAKING — `RefreshTokenStore.Consume` is now an atomic compare-and-set.**
  It must return the consumed record on `ErrAlreadyConsumed` so a replay
  cascade can revoke the whole chain (RFC 6749 §10.4); a
  `refresh.replay_detected` audit event is emitted before the best-effort
  revoke. *Migration:* custom `RefreshTokenStore` implementations must make
  `Consume` a CAS that yields the prior record on replay.
- **BREAKING — `store.RefreshToken` carries the authentication context.**
  New fields (`auth_time`, `acr`, `amr`, `authorization_details`,
  `subject_public`, `origin`, `access_token_extra`) and `RefreshTokenOrigin`
  thread through the inmem / sql / composite adapters with new
  `oidc_refresh_tokens` columns. *Migration:* SQL-backed stores must apply the
  new column migrations; custom stores must persist the new fields. Rows
  written before the `origin` field stay refreshable (empty origin).
- **BREAKING — static client seeds are validated against the active profile's
  allowed `token_endpoint_auth_method` set at construction.** Under a FAPI
  profile (`FAPI2Baseline` / `FAPI2MessageSigning` / `FAPICIBA`), whose
  conformant methods are `private_key_jwt` / `tls_client_auth` /
  `self_signed_tls_client_auth`, `op.New` now rejects a `WithStaticClients`
  seed that uses `none` or `client_secret_*` instead of accepting it. *Migration:*
  a FAPI deployment must seed only `private_key_jwt` / mTLS clients; move any
  public or `client_secret_*` clients out of the FAPI-profiled provider.
- **BREAKING — refresh-token `id` / `parent_id` are hashed at rest.** Public
  `RefreshTokenStore.Find` / `Consume` are now hash-only constant-time lookups;
  the internal chain walk resolves stored handles through the new optional
  `RefreshChainResolver`, and SQL schema validation rejects legacy (unhashed)
  refresh table shapes. *Migration:* SQL-backed stores must adopt the hashed
  refresh schema; custom stores must persist hashed ids and implement
  `RefreshChainResolver` for replay-cascade revocation.
- **BREAKING — one-time auth factors are single-use via atomic compare-and-set.**
  `emailotp` Consume, `totp` Accept, and `recovery` Consume now return
  `ErrAlreadyConsumed` on replay so a code cannot be accepted twice under
  concurrency. *Migration:* custom factor stores must make these CAS operations
  (the inmem reference shows the shape).
- **BREAKING — terminal factor failures now render HTTP 400, not 500.** Expired
  or consumed one-time codes, lockout, required reset, and too-many-resends are
  wrapped in the new `authn.ErrFactorAbort` sentinel, which the authorize
  endpoint maps to `400`. *Migration:* embedders keying off the prior `500` for
  these cases must handle `400`.
- `op.New` now rejects a nil `SessionStore` at construction when the grant set
  mounts the browser authorize endpoint, using the same predicate the runtime
  enforces (`validateStoreCapabilities`).
- Pre-issuance client authentication is consolidated into `endpointsupport`,
  matching the HTTP Basic scheme case-insensitively per RFC 7617.

### Fixed

- SQL table-name overrides now rename the metadata table in `rewriteSchema`.
  The rename pair was present in `applyOverrides` and `knownNamingKeys` but
  missing from the schema rewrite, so the query builder targeted the renamed
  table while `Migrate` created `op_metadata` under its default name — booting
  an override-configured store broken at the first query.
- Save-time garbage collection for the SQL and inmem device-code / CIBA
  substores, with zero-expiry preservation guards.
- Grant `ListBySubject` no longer collapses distinct rows that share a
  `(subject, client_id)` pair.

### Security

- One-time auth factors (email-OTP, TOTP, recovery codes) can no longer be
  accepted twice under concurrency: single-use is enforced by an atomic store
  compare-and-set returning `ErrAlreadyConsumed` on replay (race tests added).
- Closed a cross-factor account-lockout lost-update race via the atomic
  `StampLock` path, so concurrent failed factors cannot overwrite each other's
  `LockedUntil`.
- Refresh-token `id` / `parent_id` are hashed at rest and looked up in constant
  time, hardening against store-disclosure and timing side channels.
- Hardened the account-chooser add-account path with PAR-aware URL stamping and
  a forgery-resistant marker check.
- Bump `github.com/go-jose/go-jose/v4` to v4.1.4, fixing a JWE-decryption
  panic (GO-2026-4945) reachable wherever the OP decrypts JWE input.

## [v0.9.2] — 2026-05-24

### Highlights

- Refresh-token issuance for custom grants and RFC 8693 token-exchange
  is now wired into the OP's own refresh-token lineage. A handler sets
  `CustomGrantResponse.IssueRefreshToken` (or a `TokenExchangePolicy`
  returns `IssueRefreshToken`); the OP — not the handler — mints and
  persists the token through its `RefreshTokenStore`, sharing the access
  token's grant identity so the credential rides the standard rotation,
  single-use replay-cascade (RFC 9700 §2.2.2), and DPoP / mTLS
  `cnf`-binding machinery.
- Device-authorization revocation now cascades inside the library:
  `devicecodekit.Revoke` revokes every access token issued from the
  revoked `device_code` (its ID is the `GrantID` stamped on each token)
  via `AccessTokenRegistry.RevokeByGrant` when the new
  `devicecodekit.Deps.AccessTokens` registry is wired.
- A broad security-hardening sweep across DPoP, JAR / JARM, JOSE, mTLS,
  refresh rotation, client authentication, i18n input, metrics
  cardinality, and the authorize / userinfo / introspection / end-session
  endpoints (see Fixed).
- Default-driver browser login is unblocked: the interaction HTML pages
  no longer emit the two headers (`Referrer-Policy: no-referrer`,
  CSP `form-action 'self'`) that made a real browser's credential POST
  and post-consent redirect fail.

### Added

- `op.CustomGrantResponse.IssueRefreshToken bool` asks the OP to mint
  and persist a refresh token bound to the issued access token's grant
  identity. The OP owns the credential (RFC 6749 §6); issuance is gated
  on the client being registered for the `refresh_token` grant, and a
  request for refresh on an ineligible grant is honoured (200) with the
  refresh token dropped and a `custom_grant.refresh_dropped` audit event.
- `op.devicecodekit.Deps.AccessTokens` (optional
  `store.AccessTokenRegistry`) enables the `Revoke` cascade described in
  Highlights. The `device_code.revoked` audit event carries the
  `revoked_access_tokens` count when the registry is wired; a nil
  registry skips the cascade for JWT-stateless or out-of-band
  deployments.
- `op.WithDeviceCode(...)` records now lock after repeated poll abuse:
  a device-code that is polled past the slow-down ladder is denied,
  closing a polling-DoS vector.
- `op.WithDiscoveryMetadata(...)` validates that embedder-supplied
  endpoint URLs are well-formed absolute https URLs at `op.New` time
  rather than emitting a malformed discovery document at runtime.
- The example tree gains two automated verification harnesses under
  `examples/internal/` (build-tagged, separate sub-modules):
  `browserverify` (headless-Chrome end-to-end login across the
  default-HTML-driver and SPA examples) and `apiverify` (stdlib-only
  HTTP / boot smoke and grant-level checks for the API-only examples).

### Changed

- **Breaking**: `op.CustomGrantResponse.RefreshToken string` (a reserved
  field that was always rejected) is removed in favour of
  `IssueRefreshToken bool`. The string field let a handler supply a
  refresh-token *value*, which contradicts the RFC 6749 §6 model in
  which the authorization server issues the credential; the flag lets
  the handler signal intent while the OP retains ownership of the value
  and its lineage. No existing call site loses behaviour because the
  string field never produced a usable refresh token.
- `op.New` now enforces per-client scope and projects pairwise subjects
  at token mint (not only at the authorize step), so a client cannot
  widen its scope or observe a non-pairwise `sub` through the token
  endpoint.
- First-party auto-consent is additionally gated on the `Sec-Fetch-Site`
  request header and an `offline_access`-aware check, narrowing the
  silent-consent path to genuine first-party top-level navigations.
- The JARM form-post response now scopes its CSP `form-action` to the
  request's redirect-target origin instead of a broad value.
- The JWKS document's default `Cache-Control` max-age is shortened to one
  hour so key rotation propagates faster.
- `op-demo` defaults its listen address to loopback, and advertises the
  CIBA and refresh-token grants in its FAPI-CIBA profile.

### Fixed

- **DPoP**: the `jti` replay window is widened to twice the `iat`
  acceptance window (closing a gap where a proof replayed near the window
  edge could slip through), the `htu` comparison normalises a trailing
  dot, and the `jti` store expiry is anchored to `iat`.
- **JAR**: the request-object `jti` replay-cache expiry is floored and
  its scope is made type-safe. A request object that declares a `typ`
  header must name the `oauth-authz-req+jwt` media type (matched
  case-insensitively per RFC 2045 §5.1); a request object that omits
  `typ` is accepted, since RFC 9101 §10.8 makes the media type
  RECOMMENDED rather than REQUIRED.
- **JOSE**: kid-less JWE trial decryption is bounded by algorithm and key
  count so a crafted token cannot force unbounded trial work.
- **mTLS**: client certificates are verified against an optional
  `RootCAs` set and multi-valued RDNs are preserved in subject matching.
- **Refresh rotation**: the rotation chain is preserved on a grace-window
  fault, and a refresh token presented with a parent from a different
  client is rejected. `authorization_code` replay errors now surface the
  `GrantID`.
- **token-exchange**: a dual `cnf` (DPoP and mTLS) must AND-match, and
  the issued `id_token` audience is pinned.
- **Client authentication**: the Argon2id parameter floor follows the
  OWASP minimum, the `client_assertion` signing algorithm is pinned per
  client, and the `client_assertion` audience is scoped per endpoint —
  each endpoint accepts its own URL plus the issuer, and PAR / the
  backchannel endpoint additionally accept the token-endpoint URL (the
  canonical client_assertion audience per RFC 7523 §3 / OIDC Core §9).
- **userinfo / introspection / token**: `invalid_token` reasons are
  genericised and a pairwise `gid` is required on userinfo; opaque-token
  and JWT access-token subjects are projected through the configured
  `SubjectProjector` on egress; userinfo and end-session accept `HEAD`.
- **end-session**: the logout confirmation POST requires an `Origin` or
  `Referer` header and the logout page CSP is tightened.
- **CIBA**: a `client_notification_token` is rejected in poll-mode
  requests.
- **i18n**: `Accept-Language` entries and locale-tag length are capped,
  and the locale cookie's shape and length are validated before use.
- **Metrics**: events are forwarded before the internal counter update
  and a panicking sink is recovered; event-name labels are allow-listed
  to bound cardinality.
- **Storage adapters**: the in-memory adapter amortises PAR / JTI garbage
  collection and skips already-expired `Save`s; the Redis adapter floors
  the `jti` TTL at 60 s on `Save`.
- The interaction HTML pages relax `Referrer-Policy` to `same-origin` and
  stop pinning CSP `form-action`, fixing browser login (the prior
  `no-referrer` forced the credential POST's `Origin` to `null`, and
  `form-action 'self'` blocked the post-consent cross-origin redirect).

### Removed

- `op.CustomGrantResponse.RefreshToken` (replaced by the
  `IssueRefreshToken` flag; see Changed).

## [v0.9.1] — 2026-05-07

### Highlights

- CIBA poll mode (OpenID Connect Client-Initiated Backchannel
  Authentication Core 1.0): `/oidc/bc-authorize` endpoint, the
  `urn:openid:params:grant-type:ciba` token grant, and a new
  `op.CIBARequestStore` substore. Push and ping delivery modes are
  deferred to v2+.
- RFC 8693 token-exchange grant_type via `op.RegisterTokenExchange`
  with audience normalisation (RFC 8707 §2), act-claim chain assembly,
  and DPoP / mTLS cnf rebinding on the issued token.
- RFC 8628 device-authorization grant via `op.WithDeviceCode(...)`,
  plus the new `op/devicecodekit` sub-package for embedder-side
  user_code verification with a per-record brute-force lockout.
- OIDC Core §8 pairwise subject derivation
  (`op.WithPairwiseSubject(salt)` / `op.WithSubjectGenerator(...)`)
  with hardened `sector_identifier_uri` resolution and
  mid-life-strategy switching rejected at `op.New`.
- RFC 7516 JWE encryption for inbound JAR / PAR request objects and
  outbound `id_token`, JWT-shape `userinfo`, JARM authorization
  responses, and RFC 9701 introspection responses, advertised via the
  five matching `*_encryption_alg_values_supported` discovery fields.
- Stable custom-grant dispatcher: `op.WithCustomGrant(...)` graduates
  out of its experimental marker, with a documented cnf-binding
  contract and a `BoundAccessToken` helper for DPoP / mTLS-bound
  handler responses.
- `profile.FAPICIBA` graduates from placeholder to enforced
  (JAR + DPoP-or-MTLS, 10-minute access-token cap, FAPI 2.0
  client-authentication set, mandatory access-token revocation).
- New first-party auto-consent path
  (`op.WithFirstPartyClients` + the `consent.granted.first_party`
  audit event), a profile-level `RequiredAnyOf` auto-default that
  lets `WithProfile(FAPI2Baseline)` activate DPoP with no further
  wiring, automatic CORS allowlisting of static-client redirect URI
  origins, locale-resolver fallback for
  `ui_locales_supported`, and a
  `WithAllowInsecureBackchannelLogoutForDev` dev opt-in for
  loopback http back-channel logout.
- Breaking option renames (`op.WithInteraction` →
  `op.WithInteractionDriver`) and removal of the
  single-key wrappers (`op.WithCookieKey`, `op.WithMFAEncryptionKey`)
  and the no-op `op.WithPasskeyAttestation` stub.

### Added

- `op.WithCustomGrant(...)` graduates from the
  experimental marker introduced in v0.9.0 to a stable surface:
  `CustomGrantHandler` interface (`Name` / `ParamPolicy` / `Handle`)
  + `BoundAccessToken` helper that mints a cnf-bound `at+jwt` access
  token signed with the OP's keyset. The handler-owned cnf binding
  contract is documented on the public type — the dispatcher writes
  `resp.AccessToken` verbatim and the handler is responsible for
  embedding `cnf` when the request carries DPoP / mTLS proof.
  Openid-scoped custom grants emit an id_token signed from
  `ExtraClaims` after reserved-claim filtering.
- `op.WithDeviceCode(...)` (RFC 8628) wires the OP for
  device-authorization grant: `/device_authorization` endpoint,
  token-endpoint dispatcher honoring `authorization_pending` /
  `slow_down` / `access_denied` / `expired_token`, and discovery
  advertise of `device_authorization_endpoint` +
  `urn:ietf:params:oauth:grant-type:device_code` in
  `grant_types_supported`. The `DeviceCodeStore` substore ships in
  the in-memory adapter; `op/storeadapter/{sql,redis}` follow in
  v0.9.2.
- `op/devicecodekit` (new public sub-package) ships two embedder
  helpers around the RFC 8628 verification page that the OP itself
  never invokes (the verification UI lives in the embedder per
  `op/interaction`):
  - `devicecodekit.VerifyUserCode(ctx, deps, deviceCodeID,
    submittedUserCode)` runs the per-record brute-force gate: it
    canonicalises the submitted code, constant-time-compares it
    against the stored `UserCode`, increments the strike counter on
    mismatch, and transitions the record to Denied with reason
    `"user_code_lockout"` after `devicecodekit.MaxUserCodeStrikes`
    submissions (5). `op.AuditDeviceCodeUserCodeBruteForce` fires on
    every strike; `op.AuditDeviceCodeVerificationDenied` fires on the
    lockout transition. Submissions to a non-Pending record return
    `ErrAlreadyDecided` without further side effects.
  - `devicecodekit.Revoke(ctx, deps, deviceCodeID, reason)` wraps
    `store.DeviceCodeStore.Deny` with the new
    `op.AuditDeviceCodeRevoked` audit event. The wire-shape change is
    a no-op (the existing `Deny` already transitions Pending →
    Denied, and the next `/token` poll already returns
    `access_denied`); the audit signal is the new piece. Embedders
    who hold the user-trust posture "when a device authorization is
    revoked, every access token issued from that device_code is
    revoked alongside the row" subscribe to
    `AuditDeviceCodeRevoked`, read the `device_code_id` extra, and
    call `store.AccessTokenRegistry.RevokeByGrant(deviceCodeID)`
    (the device_code's ID is stamped verbatim onto the GrantID
    column of every issued access token at `Consume` time, so the
    existing per-grant cascade is sufficient). v0.9.1 ships the
    audit signal only; the library-side cascade walk (an
    `IssuedAccessTokens(deviceCodeID) []string` substore extension
    + an OP-side `RevokeByGrant` driver) is a v0.9.2 design task
    tracked alongside the SQL / Redis substore wiring deferred from
    v0.9.0.
- `op.WithPairwiseSubject(salt)` and `op.WithSubjectGenerator(...)`
  add OIDC Core §8 pairwise subject derivation
  and an extensible generator seam. `internal/sector` resolves
  `sector_identifier_uri` with HTTPS-only enforcement, RFC 1918 /
  loopback / link-local rejection, redirect-target re-validation,
  body-size + timeout caps, and a 24 h success cache. Mid-life
  switching of the subject strategy is rejected at `op.New` to
  prevent silently re-keying issued grants. Discovery now publishes
  `["public", "pairwise"]` in `subject_types_supported` whenever
  `WithPairwiseSubject` is active, and the subject projector
  dispatches per-client on `Client.SubjectType` so public-typed
  clients keep their UUIDv7 sub when the OP is mixed-mode.
- `mtls_endpoint_aliases` is now published under the MTLS feature so
  embedders running mTLS behind a reverse proxy can advertise the
  alias set defined in RFC 8705 §5.
- `acr_values_supported` is now publishable via
  `op.WithACRValuesSupported(values ...string)` so deployments that
  honor explicit ACR values (FAPI, eIDAS, NIST 800-63) advertise
  them in discovery without overriding the full document.
- `op.WithDiscoveryMetadata(map[string]any)` lets embedders extend
  the discovery document with non-OIDC keys (federation, custom
  registration metadata) at op.New time.
- DCR mount accepts `post_logout_redirect_uris` in inbound RFC 7591
  client metadata; the values flow into the seeded
  `Client.PostLogoutRedirectURIs` and are echoed back by the
  registration response and management endpoint.
- `audit.client_authn.failure` event fires from `/token` and `/par`
  whenever client authentication rejects (wrong secret, expired
  assertion, alg mismatch, missing `private_key_jwt`). Mirrors the
  existing introspection / revocation auth-failure events.
- `audit.introspection.error` event fires when an inbound token
  introspection request fails client authentication, completing the
  cross-endpoint authn-failure audit surface.
- `op.PtrBool(v bool) *bool` is a small generic helper for the
  pointer-to-bool opt-in pattern the public API uses for
  unambiguously-tri-state fields (e.g. `TokenExchangeDecision.IssueRefreshToken`
  defaults to nil = no refresh token, must be `op.PtrBool(true)` to
  opt in).
- `op.AuditTokenExchangeSubjectTokenRegistryError` event fires when
  the in-tree RFC 8693 handler observed a non-NotFound fault from
  `store.AccessTokenRegistry` while looking up subject_token /
  actor_token. The wire response stays `invalid_grant`; this event
  splits transient registry outages from real revocations so SOC
  tooling can react separately.
- CIBA poll mode. The OP now exposes the
  Client-Initiated Backchannel Authentication endpoint
  (`/oidc/bc-authorize`) and accepts
  `urn:openid:params:grant-type:ciba` at the token endpoint.
  Push and ping delivery modes are deferred to v2+; only poll
  mode ships in v0.9.1. Public surface:
  - `op.WithCIBA(...)` registers the CIBA substore and the
    `HintResolver` seam (login_hint / login_hint_token / id_token_hint
    → internal subject). The option is required to enable CIBA; the
    endpoint and grant_type stay off by default. Authentication-device
    response (approve / deny) is delivered out-of-band by the
    embedder calling `store.CIBARequestStore.Approve` /
    `Deny` directly from the authentication device's callback handler;
    the OP never pushes to the authentication device itself
    (`examples/32-ciba-pos/` shows the substore-direct shape).
  - `op.CIBARequestStore` is a new substore in the public store
    interface; the in-memory adapter ships, SQL / Redis adapters
    follow in v0.9.2.
  - Discovery now publishes
    `backchannel_authentication_endpoint`,
    `backchannel_token_delivery_modes_supported=["poll"]`,
    `backchannel_user_code_parameter_supported=false`, and
    `backchannel_authentication_request_signing_alg_values_supported`.
  - `profile.FAPICIBA` graduates from placeholder to enforced:
    `RequiredFeatures=[JAR]`, `RequiredAnyOf=[[DPoP, MTLS]]`,
    `MaxAccessTokenTTL=10min`, the FAPI 2.0 client-authentication
    set (`private_key_jwt` / `tls_client_auth` /
    `self_signed_tls_client_auth`), and
    `RequiresAccessTokenRevocation=true`. JAR enforcement on the
    /bc-authorize side requires `iss` / `aud` / `exp` / `nbf` and
    caps the request-object lifetime at 60 seconds.
  - `examples/32-ciba-pos/` ships a paired OP+RP demo (POS terminal
    initiates `/bc-authorize`, the staff phone approves,
    end-to-end in roughly one second).
- New paired OP+RP example demos covering the new grants and
  subject mode:
  - `examples/30-custom-grant/` — embedder defines
    `urn:example:libraz:service-token-exchange`, the OP routes it via
    `op.WithCustomGrant`, and the handler returns a `BoundAccessToken`
    so the dispatcher mints a JWT access token bound to the
    request's DPoP / mTLS confirmation.
  - `examples/31-device-code-cli/` — terminal CLI drives the
    RFC 8628 device-authorization grant against the OP, prints the
    boxed user_code panel + `verification_uri_complete` shortcut,
    and polls `/token` honoring `slow_down` and
    `authorization_pending`.
  - `examples/33-token-exchange-delegation/` — frontend →
    service-a → service-b cross-client impersonation triggers the
    OP-side `act` claim chain; service-b's RS-side
    verifier walks `act.sub` and accepts only delegated tokens.
  - `examples/34-pairwise-saas/` — `WithPairwiseSubject`
    salt with two tenants in distinct sectors observes `A != B`
    (different sector → different sub) and `A1 == A2` (same
    sector + same user → identical sub), satisfying both the
    privacy and determinism properties of OIDC Core §8.1.
- JWE encryption. The OP now decrypts JWE-shaped
  request objects (JAR / PAR) and wraps outbound `id_token`,
  `userinfo` (JWT-shape), JARM authorization responses, and
  RFC 9701 JWT introspection responses in a JWE addressed to the
  client's `use=enc` JWK whenever client metadata registers
  `*_encrypted_response_alg` / `_enc`. Public surface:
  - `op.WithEncryptionKeyset(keys ...op.EncryptionKey)` registers the
    OP's `use=enc` keyset; keys are published on the JWKS document
    alongside the existing `use=sig` material (RFC 7517 §4.2).
  - `op.WithSupportedEncryptionAlgs(algs []string, encs []string)`
    narrows the OP-advertised algorithm set below the v0.9.1 default
    allowlist (`RSA-OAEP-256` / `ECDH-ES{,+A128KW,+A256KW}` ×
    `A{128,256}GCM`). `RSA-OAEP-384` / `RSA-OAEP-512` are deferred
    (go-jose v4.1.x exposes no constants for them). `RSA1_5` is
    intentionally not shipped
    (CVE-2017-11424 padding oracle); `dir` and symmetric-only `A*KW`
    are reserved for v2+.
  - Discovery now publishes `id_token_encryption_alg_values_supported`
    / `_enc_values_supported`, the userinfo / request_object /
    authorization (JARM) / introspection counterparts, and gates each
    on the corresponding feature flag (JAR / JARM / Introspect).
  - `userinfo_signing_alg_values_supported` is now published
    unconditionally (`ES256`); the JWT-shape userinfo path is
    always available via `Accept: application/jwt`.
  - `examples/35-encrypted-id-token` ships a paired OP+RP demo of
    RSA-OAEP-256 / A256GCM id_token encryption (client metadata +
    JWKS distribution + RP-side decrypt).
- RFC 8693 token-exchange grant_type via `op.RegisterTokenExchange`.
  The provider verifies subject_token / actor_token, normalises the
  requested audience (RFC 8707 §2), enforces scope and audience
  subset rules, caps the issued TTL by the minimum of (handler
  request, subject_token remaining, global ceiling), builds the
  act-claim chain on the OP side (mandatory whenever the actor
  differs from the subject), and rebinds the issued token's cnf to
  the request's verified DPoP / mTLS credential. The
  `TokenExchangePolicy` seam is required at op.New; deployments
  without it cannot exchange.
- `op.WithInteractionDriver` replaces `op.WithInteraction` (driver
  registration). The new name disambiguates the single-driver option
  from `op.WithInteractions` (Step list).
- `op.Error` now exposes `newConfigurationError` factory pattern; the
  doc on `op.Error` directs new option-side error sites at the
  factory for consistency.
- `op/example_test.go` ships three `ExampleNew_*` runnable examples
  (minimal / FAPI 2.0 / JSON interaction driver) so godoc on
  pkg.go.dev renders working snippets.
- `internal/log.DiscardHandler` is the single shared `slog.Handler`
  used as the no-op default; `op.discardHandler`,
  `internal/redact.discardHandler`, and
  `internal/authn/orchestrator.discardHandler` now delegate.
- `internal/clone.Int64Ptr` consolidates the `cloneInt64Ptr` helper
  previously duplicated between `op/op.go` and
  `internal/registrationendpoint/metadata.go`.
- `internal/endpointsupport` extracts the client-authentication +
  bearer-extraction + audit-emission + error-response helpers shared
  by /introspect, /revoke, /register, /userinfo (~180 lines of
  duplication eliminated).
- `op/storeadapter/patterns` exposes `IsExpiredStrict`,
  `IsExpiredInclusive`, `MapSQLNotFound`, `MapRedisNotFound`,
  `DedupBatch`, `Paginate` so adapters share TTL / NotFound /
  pagination semantics.
- `op/store/contract` adds `AssertConcurrentRotate`,
  `AssertExpiredSessionReturnsNotFound`,
  `AssertSessionNotFoundOnMissing`, `AssertSessionBatchListMatches`
  so every adapter exercises the same `SessionStore` contract.
- `internal/authn/risk` and `internal/authn/audit` sub-packages carry
  the orchestrator's risk-evaluation and observation surfaces; the
  orchestrator delegates to them through narrow adapters.
- `internal/testutil/httptest` exposes `PostForm`,
  `PostFormWithAccept`, `GetWithBearer`, `DecodeJSON` so endpoint
  fixture setup stays consistent across test packages.
- `examples/internal/opkit` ships `DefaultLoginFlow`, `WithTOTP`,
  `WithMFARules` so example boilerplate around `op.New` shrinks.
  Examples 01 / 20 / 21 use the helpers.
- `op.WithPreferredLocaleStore` registers an embedder hook the locale
  resolver consults at the head of the priority chain (before
  ui_locales / cookie / Accept-Language / default).
- `op.Provider.LocaleResolver()` exposes the configured resolver so
  embedders can render emails, server-rendered admin pages, or other
  out-of-band surfaces in the same locale the OP picks for /authorize
  prompts.
- `interaction.Prompt` now carries `Locale` (OP-resolved tag),
  `UILocalesHint` (RP's raw `ui_locales` list), and
  `LocalesAvailable` (registered locales). The orchestrator stamps
  these fields before `Driver.Render`; SPAs read them on
  /oidc/interaction/{uid} to set `<html lang>` and build language
  pickers without re-running the chain or re-fetching discovery.
- `op.WithAllowInsecureBackchannelLogoutForDev(true)` is a new
  dev / CI-only opt-in that admits plain-http URLs whose host is a
  loopback identity (`127.0.0.1`, `[::1]`, `localhost`) for the
  `backchannel_logout_uri` client-metadata field. The default posture
  continues to enforce the OIDC Back-Channel Logout 1.0 §2.2
  https-only rule for every other host. `op.New` emits a loud
  audit-stream warning when the flag is set so the opt-in cannot
  silently survive a promotion to production. Both the static-client
  validator and the DCR registration path honour the carve-out.
- First-party clients registered via `op.WithFirstPartyClients(...)`
  now skip the consent prompt automatically when an active session
  exists and the request did not carry `prompt=consent`. The OP mints
  the authorization code silently, upserts the consent grant on the
  user's behalf, and emits the new
  `op.AuditConsentGrantedFirstParty` audit event
  (`"consent.granted.first_party"`) so SOC tooling can correlate
  every auto-grant with the matching code mint. Dynamic-client
  registrations are excluded; the gate also respects
  `prompt=consent` as a per-request override that forces the
  prompt regardless of the first-party list.
- Discovery's `ui_locales_supported` now falls back to every locale
  the runtime resolver knows (seed bundles + `WithLocale(...)`) when
  `DiscoveryMetadata.UILocalesSupported` is empty. Embedders who ship
  internal-only locales still hide them via `WithDiscoveryMetadata`.

### Changed

- **Breaking**: `store.DeviceCodeStore.RecordPoll` now takes
  `nextInterval time.Duration` and persists it atomically alongside
  `LastPolledAt`. The token endpoint passes the doubled value on a
  slow_down decision so the substore row reflects the elevated bar
  the next poll's gate compares against (RFC 8628 §3.5: "If the
  interval is more than 5 seconds, the client MUST honor the new
  value"). Out-of-tree adapters MUST update to honor the slow_down
  ladder; otherwise a malicious device can keep polling at the
  original cadence indefinitely. The reference inmem adapter is
  updated; SQL / Redis adapters land in v0.9.2 and pick up the
  new contract there.
- DCR (RFC 7591) JWE alg/enc validation across all five
  encrypted-response client metadata families (id_token / userinfo /
  request_object / authorization / introspection) now routes through
  `internal/jose.ParseJWEAlg` / `ParseJWEEnc` instead of a hard-coded
  local list. Future allowlist edits to the JOSE wrapper propagate
  automatically; out-of-tree DCR drivers that bypass the validator
  now share the same source of truth.
- DCR registration also rejects half-pair alg/enc submissions
  (e.g. `id_token_encrypted_response_alg=RSA-OAEP-256` without
  `_enc`) with `invalid_client_metadata` instead of admitting at
  registration and failing the first encrypted response at runtime.
  Both-empty still admits (the client opts out of encryption for
  that response type).
- CIBA `/bc-authorize` hardening:
  - Under `profile.FAPICIBA` a `requested_expiry > 600s` is now a
    hard `invalid_request` (FAPI-CIBA-ID1 §5 / FAPI 2.0 §3.1.9
    ten-minute cap). Vanilla CIBA keeps the existing silent-clamp
    posture.
  - The endpoint now validates each requested `acr_values` entry
    against the OP's published `acr_values_supported` list whenever
    the list is non-empty (`op.WithACRValuesSupported(...)`). An
    empty advertised list keeps the legacy permissive posture.
  - The endpoint now rejects a non-empty `user_code` parameter when
    discovery advertises `backchannel_user_code_parameter_supported=false`
    (the v0.9.1 default). Closes the silent admit-then-stamp gap.
- Custom-grant dispatcher (`op.WithCustomGrant(...)`) now rejects a
  non-empty `CustomGrantResponse.RefreshToken` with `server_error`.
  Lineage-tracked persistence + rotation for handler-issued refresh
  tokens needs design work that doesn't fit v0.9.1; until then the
  field SHOULD be left empty. The in-tree token-exchange handler is
  exempt — its grant_type URN is checked before the gate fires.
- Pairwise mid-life subject-strategy gate now also probes a new
  `__op_init` sentinel in the metadata substore so a re-used store
  whose subject-mode marker was wiped (manual cleanup, truncate)
  still rejects a non-public switch on the next `op.New` call. The
  sentinel is written on every successful construction so
  truly-fresh installs are unaffected.
- **Breaking**: `op.WithInteraction` was renamed to
  `op.WithInteractionDriver` so the single-driver option no longer
  collides with `op.WithInteractions` (Step list).
- **Breaking**: `op.WithCookieKey` (single-key wrapper) was removed;
  pass keys to `op.WithCookieKeys(keys ...[]byte)` directly.
- **Breaking**: `op.WithMFAEncryptionKey` (single-key wrapper) was
  removed; pass keys to `op.WithMFAEncryptionKeys(keys ...[]byte)`
  directly. The TOTP step error message references the new name.
- `op.WithMTLSProxy` graduates from "Experimental — partial wiring"
  to wired-end-to-end. `op.New` now threads the recorded
  `mtls.ProxyConfig` into the verifier so the reverse-proxy header
  path works for every request.
- JAR `AllowMissingJTI` stays at `true` for every profile, FAPI
  profiles included. RFC 9101 §6.1 marks
  `jti` OPTIONAL on the wire and FAPI 2.0 Security Profile / FAPI 2.0
  Message Signing do not promote it to MUST; the §10.8 replay-defence
  floor is preserved through the JTIs store, which the verifier still
  consumes for every `jti` it does see. An embedder that needs the
  strict reading can still construct the verifier directly with
  `AllowMissingJTI=false`.
- `internal/cookie/build.go` validate now rejects
  `SameSite=None` + `Secure=false` combinations at construction
  time. The default profiles already set Secure=true; the guard
  protects custom profiles.
- `internal/proxy/proxy.go` `walkForwardedFor` normalises bracketed
  / port-suffixed IPv6 tokens via `SplitHostPort`, matching the
  RemoteAddr path so the trust gate behaves identically across
  X-Forwarded-For shapes.
- `op/store.SessionStore` godoc + `internal/sessions.Manager.Rotate`
  comment now spell out the non-atomic Save→Delete contract;
  every adapter exercises the same `AssertConcurrentRotate`
  contract assertion.
- `internal/authn/orchestrator.go` shrank from 1,210 to ~492 lines;
  authentication-flow, risk-evaluation, and audit-emission
  responsibilities moved into
  `internal/authn/{phases.go, risk_*, audit_*}` and the new
  `internal/authn/{risk,audit}` sub-packages.
- `op/options.go` (3,268 → 2,374 lines) and `op/op.go` (2,073 → 992
  lines) split into themed companion files
  (`options_validate.go`, `options_defaults.go`,
  `op_builders.go`, `op_router.go`).
- `internal/tokenendpoint/authcode.go` shrank to 769 lines after
  factoring out `authcode_enforce.go` and `binding.go`.
- `internal/userinfo/handler.go` shrank to 713 lines after factoring
  out the opaque-format service path into `serve_opaque.go`.
- `internal/registrationendpoint/metadata.go` (759 → 185 lines) split
  into `metadata_validate.go` and `metadata_schemes.go`.
- `internal/authorize/request.go` (703 → 157 lines) split into
  `parsing.go`, `validation.go`, `normalization.go`.
- `op/storeadapter/inmem/inmem.go` (1,310 → 1,097 lines): client and
  authorization-code substores plus the hash / constant-time-match
  helpers moved into dedicated files.
- `op/options_test.go` (2,193 → 456 lines) split into theme files
  (keyset / features / authn / clients / discovery).
- The authorize handler now consults the configured locale resolver on
  every interaction tick. The chain reads `__Host-oidc_locale` cookie
  / Accept-Language / authorize ui_locales for layers 2–4; the cookie
  write endpoint (`POST /oidc/session/locale`) remains unimplemented
  and is scheduled for a follow-up plan.
- Example 04-i18n-locale now runs an in-process self-verify probe
  before the listener starts so `go run -tags example` prints a
  PASS / FAIL summary for each row of the locale-resolver chain.
- Example 10-react-login's SPA stamps the OP-resolved locale onto
  `document.documentElement.lang` on every prompt render.
- Example 15-custom-interaction now ships a thin locale-aware Driver
  wrapper that copies `Prompt.Locale` into the `Content-Language`
  response header, demonstrating the embedder pattern.
- Examples 04 / 05 / 06 now carry the standard `PRODUCTION CAVEATS`
  block (signing-key persistence, store durability, secret-source
  guidance) so the example tree's safety posture is uniform.
- `op.WithDPoPNonceSource` and `internal/authn/totp.Verifier.Verify`
  godoc spell out the multi-replica deployment expectation
  (distributed nonce / TOTP store required when running > 1 OP
  process).
- `profile.RequiredAnyOf` now documents and pins an order contract:
  the first element of each disjunctive set is the canonical default
  the option layer auto-enables when no member of the set is already
  configured. For the FAPI 2.0 family this means
  `WithProfile(FAPI2Baseline)` alone now activates DPoP without
  further wiring; an embedder who picks mTLS via
  `WithFeature(feature.MTLS)` keeps DPoP suppressed regardless of
  whether mTLS is layered before or after `WithProfile`. The
  defaulting pass runs after every option has been applied so the
  ordering between `WithProfile` and `WithFeature` is observably
  irrelevant.
- The CORS origin allowlist now admits the canonical origin of every
  static-client `redirect_uri` automatically, so a SPA that POSTs to
  `/token` from its callback page no longer needs to repeat the
  origin in `WithCORSOrigins`. Non-web schemes (custom-scheme
  native-app callbacks) are skipped silently. Dynamic-client
  registrations continue to flow through `WithCORSOrigins` only.

### Fixed

- Refresh-token rotation now preserves the original authorization-time
  `nonce` across every chained id_token issuance. OIDC Core §12 makes
  the nonce echo mandatory on refresh-issued id_tokens; the prior path
  dropped the value during the rotation copy.
- `client_secret_basic` credentials sent on `/token` and `/par` are now
  form-url-decoded per RFC 6749 §2.3.1 / Appendix B before constant-time
  comparison. Clients whose `client_id` or `client_secret` contained
  reserved characters (`:`, `+`, percent-escapes) previously rejected
  with `invalid_client` despite presenting the correct credential.
- `op/testkit.ensureTrust` now triggers `http.DefaultTransport`'s
  internal `nextProtoOnce` before mutating `TLSClientConfig`. The
  prior path raced with `httptest.Server.Close` (which calls
  `http.DefaultTransport.CloseIdleConnections`, internally invoking
  `http2configureTransports` to write `TLSClientConfig.NextProtos`)
  whenever both ran in parallel test goroutines.
- `op/storeadapter/sql/grant_revocation_test` now opens the SQLite
  test DB through a `file:` URL under `t.TempDir` instead of
  `:memory:`. Per-connection in-memory DBs were creating disjoint
  state across the parallel subtests' connection pool, so revocation
  rows written by one connection were not visible from another.

### Removed

- `op.WithInteraction` (renamed to `op.WithInteractionDriver`).
- `op.WithCookieKey` (single-key wrapper; use `op.WithCookieKeys`).
- `op.WithMFAEncryptionKey` (single-key wrapper; use
  `op.WithMFAEncryptionKeys`).
- `op.WithPasskeyAttestation` (was a no-op stub awaiting wiring;
  removed so the v1.0 surface does not freeze a non-functional
  option).

## [v0.9.0] — initial public release

[Unreleased]: https://github.com/libraz/go-oidc-provider/compare/v1.1.0...HEAD
[v1.1.0]: https://github.com/libraz/go-oidc-provider/compare/v1.0.0...v1.1.0
[v1.0.0]: https://github.com/libraz/go-oidc-provider/compare/v0.9.5...v1.0.0
[v0.9.5]: https://github.com/libraz/go-oidc-provider/compare/v0.9.4...v0.9.5
[v0.9.4]: https://github.com/libraz/go-oidc-provider/compare/v0.9.3...v0.9.4
[v0.9.3]: https://github.com/libraz/go-oidc-provider/compare/v0.9.2...v0.9.3
[v0.9.2]: https://github.com/libraz/go-oidc-provider/compare/v0.9.1...v0.9.2
[v0.9.1]: https://github.com/libraz/go-oidc-provider/compare/v0.9.0...v0.9.1
[v0.9.0]: https://github.com/libraz/go-oidc-provider/releases/tag/v0.9.0
