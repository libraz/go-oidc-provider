# Examples

Runnable demos for [`github.com/libraz/go-oidc-provider`](../README.md).

All examples build behind the `example` build tag, so they are excluded from
`go test ./...` and from production `go.sum`. Each one is its own module wired
to the checkout through a development `replace`, so run it with the repository
workspace disabled:

```sh
(cd examples/01-minimal && GOWORK=off go run -tags example .)
```

`make example-01` (and the other `example-NN` targets) does the same thing.

Embedder-side install (the same versions every example pins):

```sh
go get github.com/libraz/go-oidc-provider/op@v1.0.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v1.0.0       # examples 06 / 07 / 08 / 09 / 17 / 24 / 25 / 27
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v1.0.0     # examples 09 / 17
go get github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb@v1.0.0  # example 18
```

Each row in the table below also maps to a use-case page on the docs site under
[/use-cases](https://go-oidc-provider.libraz.net/use-cases/) with a
production-shaped narrative around the example file.

## Docker stacks

`07-mysql-store`, `09-redis-volatile`, `17-spa-composite-store`, and
`18-dynamodb-store` ship a `compose.yaml` + `Dockerfile` that boot the
engine(s) and the OP+RP binary on a private docker network. All four build from
the repo root (`build.context: ../..`), so the commands below work from
anywhere in the repo:

```sh
# 07: OP + MySQL on a private network
docker compose -f examples/07-mysql-store/compose.yaml up -d --build
docker compose -f examples/07-mysql-store/compose.yaml down -v

# 09: OP + MySQL + Redis (durable + volatile split)
docker compose -f examples/09-redis-volatile/compose.yaml up -d --build
docker compose -f examples/09-redis-volatile/compose.yaml down -v

# 17: the same storage split with the SPA seam on top
docker compose -f examples/17-spa-composite-store/compose.yaml up -d --build
docker compose -f examples/17-spa-composite-store/compose.yaml down -v

# 18: OP + a DynamoDB emulator (the whole OP on one non-relational backend)
docker compose -f examples/18-dynamodb-store/compose.yaml up -d --build
docker compose -f examples/18-dynamodb-store/compose.yaml down -v
```

`08-composite-hot-cold` is the no-docker counterpart of `09`: the same
`composite.With(...)` wiring with `inmem` standing in for the volatile half, so
it boots with
`(cd examples/08-composite-hot-cold && GOWORK=off go run -tags example .)`.

## I want to…

| Goal | Start with |
|---|---|
| stand up the smallest possible OP | [`01-minimal`](01-minimal/main.go) |
| declare which security posture the OP runs (OAuth 2.1 vs plain OIDC) | [`00-security-profile`](00-security-profile/main.go) |
| see every option a typical embedder reaches for | [`02-bundle`](02-bundle/main.go) |
| run a FAPI 2.0 Baseline OP (PAR + JAR + DPoP) | [`03-fapi2`](03-fapi2/main.go), [`50-fapi-tls-jwks`](50-fapi-tls-jwks/main.go) |
| issue tokens to backend services (no end user) | [`05-client-credentials`](05-client-credentials/main.go) |
| serve plain OAuth 2.0 alongside OIDC | [`04-oauth2-only`](04-oauth2-only/main.go) |
| persist on a real database (SQLite / MySQL) | [`06-sql-store`](06-sql-store/main.go), [`07-mysql-store`](07-mysql-store/main.go) |
| run the whole OP on DynamoDB, transactions included | [`18-dynamodb-store`](18-dynamodb-store/main.go) |
| customise SQL table names | [`25-byo-table-names`](25-byo-table-names/main.go) |
| implement a store from scratch | [`26-byo-store-from-scratch`](26-byo-store-from-scratch/main.go) |
| split hot volatile state from durable state | [`08-composite-hot-cold`](08-composite-hot-cold/main.go), [`09-redis-volatile`](09-redis-volatile/main.go) |
| swap the default HTML driver for JSON | [`16-custom-interaction`](16-custom-interaction/main.go) |
| drive login / consent / logout from a SPA | [`10-react-login`](10-react-login/main.go) — bundle is dependency-free vanilla JS, so it runs with no build step; the JSON contract is the same one a React / Vue / Svelte build output consumes |
| run a SPA against MySQL + Redis (the usual deployment shape) | [`17-spa-composite-store`](17-spa-composite-store/main.go) |
| customise the consent screen | [`11-custom-consent-ui`](11-custom-consent-ui/main.go) |
| support `prompt=select_account` (multi-account) | [`13-multi-account`](13-multi-account/main.go) |
| customise the account chooser (HTML template) | [`12-custom-chooser-ui`](12-custom-chooser-ui/main.go) |
| serve a SPA from a different origin (CORS) | [`14-cors-spa`](14-cors-spa/main.go) |
| translate prompts (i18n) | [`15-i18n-locale`](15-i18n-locale/main.go) |
| split public-discoverable from internal-only scopes | [`60-scopes-public-private`](60-scopes-public-private/main.go) |
| honour the OIDC §5.5 `claims` request parameter | [`61-claims-request`](61-claims-request/main.go) |
| project an embedder-owned users / members table onto OIDC | [`24-byo-userstore`](24-byo-userstore/main.go) |
| dispatch an embedder-defined `grant_type` at the token endpoint | [`30-custom-grant`](30-custom-grant/main.go) |
| require password + TOTP at every login (always-on 2FA) | [`20-mfa-totp`](20-mfa-totp/main.go) |
| require risk-based MFA / captcha | [`21-risk-based-mfa`](21-risk-based-mfa/main.go), [`22-login-captcha`](22-login-captcha/main.go) |
| step a logged-in session up to a higher ACR (RFC 9470) | [`23-step-up`](23-step-up/main.go) |
| persist MFA factors on the same database as the core tables | [`27-durable-mfa-store`](27-durable-mfa-store/main.go) |
| use a mailed one-time code, with recovery codes as the fallback | [`28-email-otp-recovery`](28-email-otp-recovery/main.go) |
| register a passkey and then sign in with it (WebAuthn) | [`29-passkey`](29-passkey/main.go) |
| drive a TV / IoT / CLI tool via RFC 8628 device authorization | [`31-device-code-cli`](31-device-code-cli/main.go) |
| issue tokens via Client-Initiated Backchannel Authentication (CIBA) | [`32-ciba-pos`](32-ciba-pos/main.go) |
| exchange a service token for an audience-narrowed token (RFC 8693) | [`33-token-exchange-delegation`](33-token-exchange-delegation/main.go) |
| issue distinct `sub` per RP sector for the same end-user (pairwise) | [`34-pairwise-saas`](34-pairwise-saas/main.go) |
| issue encrypted ID Tokens (JWE-of-JWS) to a registered RP | [`35-encrypted-id-token`](35-encrypted-id-token/main.go) |
| skip consent for first-party clients | [`40-first-party-skip-consent`](40-first-party-skip-consent/main.go) |
| let RPs register themselves (Dynamic Client Registration) | [`41-dynamic-registration`](41-dynamic-registration/main.go) |
| notify RPs when a session ends (Back-Channel Logout) | [`42-back-channel-logout`](42-back-channel-logout/main.go) |
| run the RFC 9449 §8 DPoP nonce flow | [`51-dpop-nonce`](51-dpop-nonce/main.go) |
| expose Prometheus metrics | [`52-prometheus-metrics`](52-prometheus-metrics/main.go) |

## The shared SPA bundle

Every [`op.WithSPAUI`](../op/options_authn.go) example serves the same
directory, [`internal/webui/static`](internal/webui/static) — one hand-written
vanilla HTML/CSS/JS bundle with no build step, pointed at through
`webui.StaticDir`. There is no per-example copy, so a fix to the prompt
renderer reaches every SPA example at once and none of them can fall behind on
a prompt type the others render.

The bundle implements the whole prompt vocabulary the SPA seam defines
(password, TOTP, captcha, e-mail and recovery codes, the passkey ceremony,
consent), which is what lets one directory back examples with very different
login flows. `29-passkey` additionally serves its own
[`web/account`](29-passkey/web/account) — the enrolment page the *embedder*
owns, which is precisely the part the OP does not provide.

Production embedders serve their framework's build output under
`SPAUI.StaticDir` instead; only the JSON contract belongs to the library.

## Numeric inventory

Numbers group examples by topic — bands without entries today are reserved for
in-flight or v1.x work:

| Band  | Topic                                                          |
|-------|----------------------------------------------------------------|
| 00–09 | bootstrap, core flows, profiles, storage adapters              |
| 10–19 | UI and browser integration (SPA, consent, chooser, CORS, i18n); 18–19 hold the storage-adapter overflow, 00–09 being full |
| 20–29 | MFA, authentication rules, and user-store projection           |
| 30–39 | advanced grants, subject modes, encrypted tokens, federation   |
| 40–49 | governance: first-party, DCR, back-channel logout              |
| 50–59 | operations: FAPI helpers, metrics, tracing, DPoP nonce         |
| 60–69 | scopes, claims, and compliance-adjacent examples               |
