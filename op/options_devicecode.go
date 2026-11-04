package op

import (
	"net/url"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/op/grant"
)

// DeviceCodeGrant configures the RFC 8628 device-authorization grant
// enabled by [WithDeviceCodeGrant]. Zero-valued fields keep the
// library defaults.
//
// Stable since v1.5.
type DeviceCodeGrant struct {
	// VerificationURI is the verification URI advertised on the
	// device's display in the §3.2 device-authorization response. The
	// library default is `<issuer>/device`; the field exists for
	// embedders whose verification page lives outside the OP's mount
	// prefix or under a separate hostname (e.g. a marketing landing
	// page that proxies to the OP).
	//
	// A non-empty value MUST be an absolute URL with a non-empty
	// authority; relative paths are rejected so the device-side wire
	// shape cannot drift from the spec's "complete URI" requirement.
	// The value is not checked for reachability; embedders SHOULD
	// ensure their verification page is served at the supplied URL
	// before activating the grant.
	VerificationURI string

	// TTL is the lifetime advertised to the device as `expires_in` on
	// the RFC 8628 §3.2 device-authorization response, and stamped on
	// the persisted device_code record.
	//
	// This knob is intentionally independent of [WithAccessTokenTTL]:
	// RFC 8628 leaves the device_code lifetime unspecified, and a
	// deployment running a short access-token TTL (seconds to a couple
	// of minutes) would otherwise make the device flow impractical — a
	// user needs time to reach a secondary device, read the user_code,
	// and complete the verification ceremony. Zero falls back to
	// [devicecode.DefaultExpiresIn] (10 minutes); a negative value is
	// rejected.
	TTL time.Duration

	// PollInterval is the value advertised to the device as `interval`
	// on the RFC 8628 §3.2 device-authorization response — the minimum
	// number of seconds the device MUST wait between polls of the
	// token endpoint. Zero falls back to [devicecode.DefaultInterval]
	// (5 seconds); a negative value is rejected.
	PollInterval time.Duration
}

// WithDeviceCodeGrant enables the RFC 8628 device-authorization grant,
// configured by g. The option:
//
//   - adds [grant.DeviceCode] to the resolved grant set. The addition
//     composes rather than replaces: a deployment that calls only this
//     option keeps the default authorization_code + refresh_token
//     pair, and one that also calls [WithGrants] gets the device-code
//     grant on top of the listed set regardless of which option runs
//     first. Naming [grant.DeviceCode] in [WithGrants] as well is a
//     no-op, not a duplicate;
//   - records the explicit opt-in so [op.New] can require a non-nil
//     [store.Store.DeviceCodes] substore at construction time —
//     starting the OP with the option but without the substore wired
//     surfaces as a configuration error rather than a runtime nil
//     panic on the first poll;
//   - causes the discovery document to advertise the
//     `device_authorization_endpoint` field and the OP to mount
//     /device_authorization at the configured endpoint path.
//
// The option does NOT add the user-facing /device verification page
// to the OP's router; the verification ceremony is owned by the
// embedder (consent UI, brute-force lockout policy, audit emission)
// and wired through the [interaction.Driver] hook the OP already
// exposes. The verification URI advertised on the device's display
// defaults to `<issuer>/device`; embedders override it through
// [DeviceCodeGrant.VerificationURI].
//
//	op.WithDeviceCodeGrant(op.DeviceCodeGrant{
//		TTL:          15 * time.Minute,
//		PollInterval: 5 * time.Second,
//	})
//
// WithDeviceCodeGrant may be supplied at most once.
//
// Stable since v1.0.
func WithDeviceCodeGrant(g DeviceCodeGrant) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithDeviceCodeGrant"); err != nil {
			return err
		}
		verificationURI, err := deviceVerificationURI(g.VerificationURI)
		if err != nil {
			return err
		}
		if g.TTL < 0 {
			return newConfigurationError("WithDeviceCodeGrant: DeviceCodeGrant.TTL must be zero or positive", nil)
		}
		if g.PollInterval < 0 {
			return newConfigurationError("WithDeviceCodeGrant: DeviceCodeGrant.PollInterval must be zero or positive", nil)
		}
		// Only the opt-in bit and the settings are recorded here; the
		// grant set is assembled in [config.applyDefaults] once every
		// option has run, so the result cannot depend on whether this
		// option or [WithGrants] was applied first.
		c.deviceCodeGrantEnabled = true
		c.deviceVerificationURI = verificationURI
		c.deviceCodeExpiry = g.TTL
		c.deviceCodePollInterval = g.PollInterval
		return nil
	})
}

// deviceVerificationURI trims raw and checks it is an absolute URI with a
// host. Empty leaves the OP's own verification page in place.
func deviceVerificationURI(raw string) (string, error) {
	uri := strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if uri == "" {
		return "", newConfigurationError("WithDeviceCodeGrant: DeviceCodeGrant.VerificationURI must not be blank", nil)
	}
	u, err := url.Parse(uri)
	if err != nil {
		return "", newConfigurationError("WithDeviceCodeGrant: DeviceCodeGrant.VerificationURI is unparseable", err)
	}
	if !u.IsAbs() || u.Host == "" {
		return "", newConfigurationError("WithDeviceCodeGrant: DeviceCodeGrant.VerificationURI must be an absolute URI with a host", nil)
	}
	return uri, nil
}

// effectiveDeviceCodeExpiry returns the device_code lifetime the
// /device_authorization handler advertises, resolved against the
// library default when the embedder has not called
// [DeviceCodeGrant.TTL].
func (c *config) effectiveDeviceCodeExpiry() time.Duration {
	if c.deviceCodeExpiry <= 0 {
		return devicecode.DefaultExpiresIn
	}
	return c.deviceCodeExpiry
}

// effectiveDeviceCodePollInterval returns the poll interval the
// /device_authorization handler advertises, resolved against the
// library default when the embedder has not called
// [DeviceCodeGrant.PollInterval].
func (c *config) effectiveDeviceCodePollInterval() time.Duration {
	if c.deviceCodePollInterval <= 0 {
		return devicecode.DefaultInterval
	}
	return c.deviceCodePollInterval
}

// validateDeviceCodeGrant enforces the substore-presence invariant
// the device-flow surfaces depend on: any embedder that activates
// the grant — through the dedicated [WithDeviceCodeGrant] option OR
// by listing [grant.DeviceCode] in [WithGrants] — MUST have a
// [store.Store.DeviceCodes] substore wired. Without it the
// /device_authorization handler's Save call would reach a nil
// substore on the first request, and the token endpoint's poll path
// would dispatch to a grant whose backing store cannot resolve the
// presented device_code. Surfacing the gap at construction time is
// the same posture every other option takes.
func (c *config) validateDeviceCodeGrant() error {
	if !c.grantEnabled(grant.DeviceCode) {
		return nil
	}
	if nilcheck.IsNil(c.store) {
		// validateRequired has already failed; bail out so the
		// substore-nil branch does not panic on the nil store.
		return nil
	}
	if nilcheck.IsNil(c.store.DeviceCodes()) {
		return newConfigurationError("the device_code grant requires the configured Store to provide "+
			"a non-nil DeviceCodes substore (the inmem, sql and dynamodb adapters ship one; "+
			"the redis adapter does not — route this substore to another backend through storeadapter/composite)", nil)
	}
	return nil
}
