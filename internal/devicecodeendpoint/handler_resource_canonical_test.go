// Package devicecodeendpoint_test (this file): the resource-indicator
// canonicalisation rules the device-authorization endpoint enforces are
// pinned by the helper tests
// (internal/resourceindicator/resourceindicator_test.go) and by the
// cross-endpoint client-credentials suite
// (internal/tokenendpoint/clientcred_resource_test.go). The device
// handler delegates to the helper, so a per-endpoint integration test
// would re-cover the same branches without exercising any device-
// specific behaviour.
//
// A test file is left in place (rather than deleted) so a future
// reviewer searching the package for "resource canonicalisation" lands
// on this pointer instead of concluding the device endpoint lacks
// coverage.
package devicecodeendpoint_test
