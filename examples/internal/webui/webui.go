//go:build example

// Package webui locates the SPA bundle that every [op.WithSPAUI]
// example serves.
//
// The bundle itself lives next to this file under static/ and is
// hand-written vanilla HTML/CSS/JS with no build step, so the examples
// run straight from a checkout. It implements the whole prompt
// vocabulary the SPA seam defines — password, TOTP, captcha, e-mail
// and recovery codes, the passkey ceremony, and consent — which is
// what lets one directory back examples with very different login
// flows.
//
// There is exactly one copy of the bundle and the examples point at
// it; none of them holds its own. That is the point: a fix to the
// prompt renderer reaches every example at once, and no example can
// quietly fall behind on a feature the others have.
//
// Production embedders serve their own framework's build output under
// [op.SPAUI.StaticDir]; only the JSON contract is part of the library.
// The package is gated behind the "example" build tag so it cannot be
// imported into production binaries by accident.
package webui

// StaticDir is the bundle's path relative to an example's own
// directory. Examples run with their directory as the working
// directory — `cd examples/10-react-login && go run -tags example .`,
// and the same layout inside the docker images — so the relative form
// is what resolves in both.
const StaticDir = "../internal/webui/static"
