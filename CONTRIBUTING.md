# Contributing

Thanks for considering a contribution to `go-oidc-provider`.

## Ground rules

- The library is in **pre-v1.0** (`v0.9.0` is the initial public release).
  Breaking changes are allowed in any minor release until `v1.0.0`; every
  break must be called out in `CHANGELOG.md` (which begins tracking from
  the first release after `v0.9.0`).
- Public API lives in `op/` and its sub-packages. The `internal/` tree is not
  part of the API surface and may change without notice.
- Run `make verify` locally before opening a pull request.

## Conventional Commits

We use [Conventional Commits](https://www.conventionalcommits.org/) with
project-specific scopes:

- `feat(grant): add device_code grant`
- `fix(jose): reject "none" alg explicitly`
- `security(dpop): tighten jti replay window`
- `docs(plans): clarify Tx cluster wording`

## Test requirements

- New features land with unit, integration, and (where relevant) golden /
  fuzz / conformance coverage. The Makefile entry points (`make test`,
  `make fuzz`, `make verify`) document the expected test layers.
- DB and external IdP mocks are forbidden. Use the in-memory reference
  store (`op/storeadapter/inmem`) or testcontainers-based integration
  tests.

## RFC references

When code asserts a specification requirement, cite it in the form
`RFC 6749 §10.5`. Avoid bare RFC numbers without a section.

## Code of Conduct

Participation in this project is governed by the project's
[Code of Conduct](CODE_OF_CONDUCT.md), which adopts the Contributor
Covenant 2.1.

## License

By submitting a pull request, you agree that your contribution will be
licensed under the Apache License 2.0.
