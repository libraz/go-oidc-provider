# Security Policy

## Reporting a Vulnerability

If you discover a security issue in `go-oidc-provider`, please **do not** open a
public GitHub issue.

Instead, report it privately via:

- GitHub Security Advisories: <https://github.com/libraz/go-oidc-provider/security/advisories/new>
- Email: see the maintainer profile at <https://github.com/libraz>

Please include:

- A description of the issue and its impact.
- Steps to reproduce or a minimal proof of concept.
- Affected versions, if known.
- Your assessment of severity (CVSS welcome but not required).

We aim to acknowledge reports within 3 business days and to provide a fix or
mitigation timeline within 14 days for confirmed issues.

## Supported Versions

`go-oidc-provider` is in pre-v1.0 development; `v0.9.0` is the initial
public release. Only the latest minor release receives security fixes
during the `v0.9.x` series.

| Version | Supported |
|---------|-----------|
| v0.9.x  | latest minor only |
| v1.x    | latest minor + previous minor (planned, post-v1.0) |

## Disclosure

We follow coordinated disclosure. Once a fix is released, we publish a GitHub
Security Advisory with the relevant CVE (when assigned). Subscribers of releases
will receive notifications automatically.
