package registrationendpoint

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/internal/sector"
)

// validateSectorIdentifierURI implements the OIDC Core 1.0 §5 / §8.1
// fetch-and-subset rule. When sector_identifier_uri is set the OP MUST
// GET the document, parse it as a JSON array of strings, and confirm
// every redirect_uri the client registered appears verbatim in the
// array. The fetch and SSRF posture (https-only, no redirects, IP
// literal denylist, DNS-time host check, 64 KiB body cap, 5 s timeout,
// 24 h success cache with poison-detection on refresh) lives in the
// in-tree [sector.Resolver]; this helper is the wire-error adapter
// that translates the resolver's typed sentinels into the RFC 7591
// invalid_client_metadata envelope.
//
// A nil [Deps.SectorResolver] falls back to a zero-config resolver so
// unit tests that exercise the validator without going through op.New
// (e.g. metadata_unit_test.go) still see the production posture.
//
// Failure causes are logged at WARN with the typed sentinel chain so
// operators can distinguish a private-network attempt from a redirect
// attempt from a hash mismatch; the response body never repeats the
// upstream error so an attacker cannot probe the OP for internal
// hostnames or response shapes.
func validateSectorIdentifierURI(ctx context.Context, deps Deps, m ClientMetadata) error {
	if m.SectorIdentifierURI == "" {
		return nil
	}
	resolver := deps.SectorResolver
	if resolver == nil {
		resolver = sector.New()
	}
	if _, err := resolver.Resolve(ctx, m.SectorIdentifierURI, m.RedirectURIs); err != nil {
		deps.logger().WarnContext(ctx, "dcr.sector_identifier.fetch_failed",
			"sector_identifier_uri", m.SectorIdentifierURI, "err", err)
		return mapSectorError(err)
	}
	return nil
}

// mapSectorError converts a [sector] sentinel into the RFC 7591
// invalid_client_metadata wire shape with a description that reveals
// the failure family without leaking response data. The branch order
// matters: ErrSectorContentChanged is most specific (subset check
// passed once but the document mutated) so it is checked before the
// broader subset / fetch errors.
func mapSectorError(err error) error {
	switch {
	case errors.Is(err, sector.ErrSectorContentChanged):
		return errInvalidClientMetadata("sector_identifier_uri document changed since last fetch")
	case errors.Is(err, sector.ErrSectorRedirectMissing):
		return errInvalidClientMetadata("redirect_uris not contained in sector_identifier_uri document")
	case errors.Is(err, sector.ErrSectorPrivateAddress):
		return errInvalidClientMetadata("sector_identifier_uri host resolves to a private address")
	case errors.Is(err, sector.ErrSectorRedirectFollowed):
		return errInvalidClientMetadata("sector_identifier_uri must not redirect")
	case errors.Is(err, sector.ErrSectorMalformed):
		return errInvalidClientMetadata("sector_identifier_uri document is malformed")
	default:
		return errInvalidClientMetadata("sector_identifier_uri fetch failed")
	}
}
