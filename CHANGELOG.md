# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches v1.0.0. During the pre-v1.0 period, breaking changes may occur
in any minor release.

## [Unreleased]

### Added

- Initial repository scaffold (Apache-2.0 license, contribution guide, security
  policy, baseline `op` package skeleton).
- RFC 9449 DPoP (Demonstrating Proof of Possession). Enabled via
  `op.WithFeature(feature.DPoP)`. The token endpoint binds issued
  access and refresh tokens to the proof's JWK thumbprint (`cnf.jkt`),
  the userinfo endpoint enforces the binding, and refresh requests
  must present a matching proof. Replay protection is wired through
  the existing `store.ConsumedJTIStore`. Discovery advertises the
  accepted proof signing algorithms via
  `dpop_signing_alg_values_supported` (ES256, EdDSA).
- RFC 8705 mTLS certificate-bound access tokens. Enabled via
  `op.WithFeature(feature.MTLS)`. When a client presents a TLS
  certificate at the token endpoint, the issued access token carries
  `cnf.x5t#S256` (SHA-256 thumbprint of the leaf cert DER bytes),
  the persisted refresh token records the same thumbprint, and the
  userinfo endpoint enforces the binding on every call. Discovery
  advertises `tls_client_certificate_bound_access_tokens: true` and
  appends `tls_client_auth` / `self_signed_tls_client_auth` to the
  supported auth-method list. The §2 client-authentication paths
  (matching cert subject DN / SAN against client metadata, or
  matching against a registered JWK) are exposed as
  `internal/mtls.VerifyTLSClientAuth` /
  `internal/mtls.VerifySelfSignedTLSClientAuth`; full wiring at the
  token endpoint is deferred to a follow-up that lands the
  `TLSClientAuth*` fields on `op/store.Client` alongside the
  RFC 7591 dynamic-registration work.
