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

## [v0.9.0] — initial public release

[Unreleased]: https://github.com/libraz/go-oidc-provider/compare/v0.9.0...HEAD
[v0.9.0]: https://github.com/libraz/go-oidc-provider/releases/tag/v0.9.0
