# Changelog

`v0.9.0` is the initial public release of go-oidc-provider. Notable changes
in subsequent releases are tracked here in
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

The project follows strict [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
from `v1.0.0` onwards; pre-v1.0 minor releases (including the `v0.9.x`
series) may carry breaking changes — see the `Changed` / `Removed`
sections of each release for the migration notes.

The main module and the storage-adapter sub-modules
(`op/storeadapter/sql`, `op/storeadapter/redis`) share the same release
tag. Embedders pull each sub-module independently:

```
go get github.com/libraz/go-oidc-provider@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/sql@v0.9.0
go get github.com/libraz/go-oidc-provider/op/storeadapter/redis@v0.9.0
```

## [Unreleased]

### Added

- `op.WithPreferredLocaleStore` registers an embedder hook the locale
  resolver consults at the head of the §L.2 priority chain (before
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

### Changed

- The authorize handler now consults the configured locale resolver on
  every interaction tick. The chain reads `__Host-oidc_locale` cookie
  / Accept-Language / authorize ui_locales for layers 2–4; the cookie
  write endpoint (`POST /oidc/session/locale`) remains unimplemented
  and is scheduled for a follow-up plan.
- Example 16-i18n-locale now runs an in-process self-verify probe
  before the listener starts so `go run -tags example` prints a
  PASS / FAIL summary for each row of the §L.2 chain.
- Example 10-react-login's SPA stamps the OP-resolved locale onto
  `document.documentElement.lang` on every prompt render.
- Example 04-custom-interaction now ships a thin locale-aware Driver
  wrapper that copies `Prompt.Locale` into the `Content-Language`
  response header, demonstrating the embedder pattern.

## [v0.9.0] — initial public release

[Unreleased]: https://github.com/libraz/go-oidc-provider/compare/v0.9.0...HEAD
[v0.9.0]: https://github.com/libraz/go-oidc-provider/releases/tag/v0.9.0
