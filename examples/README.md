# Examples

Runnable demos for [`github.com/libraz/go-oidc-provider`](../README.md).

All examples build behind the `example` build tag, so they are excluded from
`go test ./...` and from production `go.sum`:

```sh
(cd examples/01-minimal && go run -tags example .)
```

Embedder-side install (the same versions every example pins):

```sh
go get github.com/libraz/go-oidc-provider/op@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.0    # examples 06 / 07 / 08 / 09
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.0  # example 09
```

Each row in the table below also maps to a use-case page on the docs site under
[/use-cases](https://go-oidc-provider.libraz.net/use-cases/) with a
production-shaped narrative around the example file.

## Docker stacks

`07-mysql-store` and `09-redis-volatile` ship a `compose.yaml` + `Dockerfile`
that boot the engine(s) and the OP+RP binary on a private docker network. Both
stacks build from the repo root (`build.context: ../..`), so the commands below
work from anywhere in the repo:

```sh
# 07: OP + MySQL on a private network
docker compose -f examples/07-mysql-store/compose.yaml up -d --build
docker compose -f examples/07-mysql-store/compose.yaml down -v

# 09: OP + MySQL + Redis (durable + volatile split)
docker compose -f examples/09-redis-volatile/compose.yaml up -d --build
docker compose -f examples/09-redis-volatile/compose.yaml down -v
```

`08-composite-hot-cold` is the no-docker counterpart of `09`: the same
`composite.With(...)` wiring with `inmem` standing in for the volatile half, so
it boots with `(cd examples/08-composite-hot-cold && go run -tags example .)`.

## I want to…

| Goal | Start with |
|---|---|
| stand up the smallest possible OP | [`01-minimal`](01-minimal/main.go) |
| see every option a typical embedder reaches for | [`02-bundle`](02-bundle/main.go) |
| run a FAPI 2.0 Baseline OP (PAR + JAR + DPoP) | [`03-fapi2`](03-fapi2/main.go), [`50-fapi-tls-jwks`](50-fapi-tls-jwks/main.go) |
| issue tokens to backend services (no end user) | [`05-client-credentials`](05-client-credentials/main.go) |
| serve plain OAuth 2.0 alongside OIDC | [`04-oauth2-only`](04-oauth2-only/main.go) |
| persist on a real database (SQLite / MySQL) | [`06-sql-store`](06-sql-store/main.go), [`07-mysql-store`](07-mysql-store/main.go) |
| customise SQL table names | [`25-byo-table-names`](25-byo-table-names/main.go) |
| implement a store from scratch | [`26-byo-store-from-scratch`](26-byo-store-from-scratch/main.go) |
| split hot volatile state from durable state | [`08-composite-hot-cold`](08-composite-hot-cold/main.go), [`09-redis-volatile`](09-redis-volatile/main.go) |
| swap the default HTML driver for JSON | [`16-custom-interaction`](16-custom-interaction/main.go) |
| drive login / consent / logout from a SPA | [`10-react-login`](10-react-login/main.go) |
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

## Numeric inventory

Numbers group examples by topic — bands without entries today are reserved for
in-flight or v1.x work:

| Band  | Topic                                                          |
|-------|----------------------------------------------------------------|
| 00–09 | bootstrap, core flows, profiles, storage adapters              |
| 10–19 | UI and browser integration (SPA, consent, chooser, CORS, i18n) |
| 20–29 | MFA, authentication rules, and user-store projection           |
| 30–39 | advanced grants, subject modes, encrypted tokens, federation   |
| 40–49 | governance: first-party, DCR, back-channel logout              |
| 50–59 | operations: FAPI helpers, metrics, tracing, DPoP nonce         |
| 60–69 | scopes, claims, and compliance-adjacent examples               |
