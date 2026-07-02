package op

import (
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/op/grant"
)

// WithDeviceCodeGrant enables the RFC 8628 device-authorization grant.
// The option:
//
//   - appends [grant.DeviceCode] to the configured grant set when it
//     is not already present (idempotent so the embedder may also
//     include it via [WithGrants]);
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
// defaults to `<issuer>/device`; embedders override it via
// [WithDeviceVerificationURI].
//
// Stable since v0.x.
func WithDeviceCodeGrant() Option {
	return optionFunc(func(c *config) error {
		c.deviceCodeGrantEnabled = true
		if !slices.Contains(c.grants, grant.DeviceCode) {
			c.grants = append(c.grants, grant.DeviceCode)
		}
		return nil
	})
}

// WithDeviceVerificationURI overrides the verification URI advertised
// on the device's display in the §3.2 device-authorization response.
// The library default is `<issuer>/device`; the option exists for
// embedders whose verification page lives outside the OP's mount
// prefix or under a separate hostname (e.g. a marketing landing page
// that proxies to the OP).
//
// The supplied value MUST be an absolute URL with a non-empty
// authority; relative paths are rejected at the option site so the
// device-side wire shape cannot drift from the spec's "complete URI"
// requirement. The option does not validate that the URL is
// reachable; embedders SHOULD ensure their verification page is
// served at the supplied URL before activating the option.
//
// Stable since v0.x.
func WithDeviceVerificationURI(uri string) Option {
	return optionFunc(func(c *config) error {
		trimmed := strings.TrimSpace(uri)
		if trimmed == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDeviceVerificationURI requires a non-empty URI",
			}
		}
		u, err := url.Parse(trimmed)
		if err != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDeviceVerificationURI received an unparseable URI",
				Cause:       err,
			}
		}
		if !u.IsAbs() || u.Host == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDeviceVerificationURI requires an absolute URI with a host",
			}
		}
		c.deviceVerificationURI = trimmed
		return nil
	})
}

// WithDeviceCodeExpiry overrides the lifetime advertised to the
// device as `expires_in` on the RFC 8628 §3.2 device-authorization
// response, and stamped on the persisted device_code record.
//
// This knob is intentionally independent of [WithAccessTokenTTL]:
// RFC 8628 leaves the device_code lifetime unspecified, and a
// deployment running a short access-token TTL (seconds to a couple
// of minutes) would otherwise make the device flow impractical — a
// user needs time to reach a secondary device, read the user_code,
// and complete the verification ceremony. The library default is
// [devicecode.DefaultExpiresIn] (10 minutes) when this option is
// not called.
//
// A non-positive duration is rejected at the option site.
//
// Stable since v0.x.
func WithDeviceCodeExpiry(ttl time.Duration) Option {
	return optionFunc(func(c *config) error {
		if ttl <= 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDeviceCodeExpiry requires a positive duration",
			}
		}
		c.deviceCodeExpiry = ttl
		return nil
	})
}

// WithDeviceCodePollInterval overrides the value advertised to the
// device as `interval` on the RFC 8628 §3.2 device-authorization
// response — the minimum number of seconds the device MUST wait
// between polls of the token endpoint. The library default is
// [devicecode.DefaultInterval] (5 seconds) when this option is not
// called.
//
// A non-positive duration is rejected at the option site.
//
// Stable since v0.x.
func WithDeviceCodePollInterval(interval time.Duration) Option {
	return optionFunc(func(c *config) error {
		if interval <= 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDeviceCodePollInterval requires a positive duration",
			}
		}
		c.deviceCodePollInterval = interval
		return nil
	})
}

// effectiveDeviceCodeExpiry returns the device_code lifetime the
// /device_authorization handler advertises, resolved against the
// library default when the embedder has not called
// [WithDeviceCodeExpiry].
func (c *config) effectiveDeviceCodeExpiry() time.Duration {
	if c.deviceCodeExpiry <= 0 {
		return devicecode.DefaultExpiresIn
	}
	return c.deviceCodeExpiry
}

// effectiveDeviceCodePollInterval returns the poll interval the
// /device_authorization handler advertises, resolved against the
// library default when the embedder has not called
// [WithDeviceCodePollInterval].
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
// the same posture the rest of the v0.x options take.
func (c *config) validateDeviceCodeGrant() error {
	if !c.deviceCodeGrantConfiguredOrEnabled() {
		return nil
	}
	if c.store == nil {
		// validateRequired has already failed; bail out so the
		// substore-nil branch does not panic on the nil store.
		return nil
	}
	if c.store.DeviceCodes() == nil {
		return &Error{
			Code: codeConfiguration,
			Description: "the device_code grant requires the configured Store to provide " +
				"a non-nil DeviceCodes substore (storeadapter/inmem ships one; SQL / " +
				"Redis adapters require an explicit implementation)",
		}
	}
	return nil
}

// deviceCodeGrantConfiguredOrEnabled reports whether the embedder
// activated the device_code grant through any supported entry point
// (the dedicated [WithDeviceCodeGrant] option or [WithGrants] with
// [grant.DeviceCode]). The validator and the router both key on this
// helper so the substore-presence invariant cannot drift between the
// "explicit opt-in" and "grant set" paths.
func (c *config) deviceCodeGrantConfiguredOrEnabled() bool {
	if c.deviceCodeGrantEnabled {
		return true
	}
	return slices.Contains(c.grants, grant.DeviceCode)
}

// effectiveDeviceVerificationURI returns the URI the
// /device_authorization handler stamps on the device-display response.
// An embedder-supplied override wins; otherwise the library
// synthesises `<issuer>/device` so a default boot has a sensible
// fallback.
func (c *config) effectiveDeviceVerificationURI() string {
	if c.deviceVerificationURI != "" {
		return c.deviceVerificationURI
	}
	return strings.TrimRight(c.issuer, "/") + "/device"
}

// deviceCodeGrantConfigured reports whether the OP should mount the
// /device_authorization endpoint and advertise it in discovery. A
// grant is "configured" when the embedder activated it (via the
// dedicated [WithDeviceCodeGrant] option OR by listing
// [grant.DeviceCode] in [WithGrants]). The substore-presence
// invariant is enforced ahead of this helper by
// [validateDeviceCodeGrant], so once the helper returns true the
// router can rely on the [store.Store.DeviceCodes] substore being
// non-nil — there is no longer a configured-without-substore path
// that the runtime needs to fall back from.
func (c *config) deviceCodeGrantConfigured() bool {
	return c.deviceCodeGrantConfiguredOrEnabled()
}
