// Module github.com/libraz/go-oidc-provider/examples/internal/browserverify
// is an examples-only test harness that boots a browser-driven example
// (e.g. examples/01-minimal) under the "example" build tag and drives
// its happy-path login round-trip with a headless Chrome via chromedp.
//
// It is its own sub-module so chromedp and its transitive dependencies
// stay out of every tutorial example's go.sum. Nothing in the published
// library imports it; it exists to give CI an automated equivalent of
// the manual example walkthroughs.
module github.com/libraz/go-oidc-provider/examples/internal/browserverify

go 1.26

require github.com/chromedp/chromedp v0.15.1

require (
	github.com/chromedp/cdproto v0.0.0-20260321001828-e3e3800016bc // indirect
	github.com/chromedp/sysutil v1.1.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20260214004413-d219187c3433 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
)
