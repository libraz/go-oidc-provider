# Reference application

A worked application built on go-oidc-provider: accounts that belong to the
application, an OpenID Connect Provider embedded in the same process, and a
relying party completing the round-trip. Storage is the shape a deployment
actually runs — MySQL for the durable substores and the application's own
tables, Redis for the volatile ones, joined through
`op/storeadapter/composite`.

The numbered [`examples/`](../examples) each demonstrate one option in
200–500 lines. This is the other thing: how the pieces fit together once an
account has to come into existence and be used.

> This is a demonstration and is not built to be hosted publicly. It holds
> real credentials, and running it as an open service adds nothing to what
> it shows.

## Run it

```sh
docker compose -f sample/compose.yaml up -d --build
open http://127.0.0.1:8080/
```

Then: create an account, open the relying party on
<http://127.0.0.1:9090/>, sign in, approve consent, and read the verified ID
token claims. Optionally enable an authenticator app from the account page
first, and the next sign-in will ask for a code.

```sh
docker compose -f sample/compose.yaml down -v
```

Signing keys, cookie keys, and the TOTP encryption key are generated fresh
at every start, so a restart invalidates every token, session, and enrolled
secret. That is correct for a demonstration and wrong for anything else: a
deployment loads that material from a secret manager.

## What it demonstrates

**The account table belongs to the application.** `members.go` defines a
`members` table with column names of its own, and projects rows onto
`store.UserPasswordStore`. The library never reads that table directly, and
the application is free to keep columns the OP never sees. Signup generates
an opaque subject rather than deriving one from the email address, so a
member can change their address without breaking the `sub` claim already
issued to relying parties.

**The login and consent UI belongs to the application.** `ui.go` implements
`interaction.Driver` instead of using the bundled HTML driver. The library
still decides which factor comes next and validates every submission; the
application decides what the user sees. Two header choices in that file are
load-bearing rather than stylistic, and both fail only in a real browser:
`Referrer-Policy` must not be `no-referrer` (it makes the browser send
`Origin: null`, which the CSRF gate rejects), and the policy must not pin
`form-action` (consent redirects cross-origin to the relying party, and
browsers enforce `form-action` across redirects).

Owning the driver is also what makes granular consent possible. The consent
page asks scope by scope; `ParseSubmission` folds the repeated checkbox
field into the single `approved_scopes` value the orchestrator reads.
Translating the application's form into the library's submission contract is
what that method is for. Note also that `FieldSpec.Label` is an i18n key
rather than display text — the library says which field is being asked for
and leaves the wording, and the language, to whoever owns the page.

## Verifying it

```sh
(cd examples/internal/browserverify && \
  go test -tags browserverify -run TestSampleReferenceApp -v .)
```

The case brings the compose stack up itself and drives signup, authenticator
enrolment, sign-in, and consent through a headless Chrome to the relying
party's callback. It skips when Docker or Chrome is missing.

**Authentication factors use the durable SQL adapter.** The sample wires
`durable.TOTPs()` into the TOTP authenticator, so enrollment and replay
protection use the same contract-tested schema and opaque CAS tokens as the
other SQL substores. Application-owned member columns remain separate in
`members.go`.

**The application's session is its own.** It is a separate cookie from the
OP's, and the library never touches it. Sessions are held in process here;
a multi-instance deployment moves them to shared storage. The OP's own
sessions are in Redis, which is the part that governs the library's
behaviour.

**TOTP is opt-in per member.** `StepTOTP` fails when no enrolment exists, so
the rule is `op.RuleWhen(...)` rather than `op.RuleAlways` — an
unconditional rule would lock out everyone who never set it up. The
predicate resolves toward demanding the factor when the store is unhealthy,
because the alternative would let an enrolled member past their second
factor during an outage.

**The relying party verifies.** `rp.go` uses state, nonce, and PKCE, and
verifies the ID token against the OP's JWKS rather than decoding it.

## Configuration

Every variable has a default that works for the loopback stack.

| Variable | Default | Purpose |
|---|---|---|
| `ISSUER` | `http://127.0.0.1:8080` | OP issuer. An `https://` value turns off the loopback relaxations. |
| `RP_BASE` | `http://127.0.0.1:9090` | Relying-party base URL; the redirect URI is derived from it. |
| `OP_ADDR` / `RP_ADDR` | `0.0.0.0:8080` / `0.0.0.0:9090` | Listen addresses. |
| `CLIENT_ID` | `sample-rp` | The seeded public client. |
| `MYSQL_DSN` | assembled from the parts below | Full DSN, overriding the parts. |
| `MYSQL_HOST` / `MYSQL_USER` / `MYSQL_PASS` / `MYSQL_DB` | `127.0.0.1:3306` / `sample` / `sample` / `sample` | DSN parts. |
| `REDIS_DSN` | `redis://127.0.0.1:6379/0` | Redis DSN. Plaintext is admitted only while the issuer is not `https://`. |

## Running without Docker

```sh
# with MySQL and Redis already listening
(cd sample && go run -tags example .)
```
