package netsec

import (
	"net"
	"strings"
)

// IsLocalHostname reports whether host is a literal "localhost" string
// or one of its common variants. The match is case-insensitive because
// DNS is. The check is independent of [IsPrivateIP] because some peers
// resolve "localhost" to a public-looking record (split-horizon DNS)
// and the OP wants to refuse the textual form regardless.
func IsLocalHostname(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "localhost.", "ip6-localhost", "ip6-loopback":
		return true
	default:
		return false
	}
}

// IsPrivateIP reports whether ip falls inside one of the deny-listed
// ranges: loopback (127.0.0.0/8 + ::1), link-local (169.254.0.0/16 +
// fe80::/10), the RFC 1918 / IPv6 ULA private blocks, the unspecified
// address, and the cloud-metadata literals (covered separately by
// [IsCloudMetadataIP] and folded in here so callers have a single
// "is this address safe to dial" predicate).
//
// The function returns false for a nil ip; callers that want to refuse
// "no address" should check len(addrs) == 0 separately.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	if IsCloudMetadataIP(ip) {
		return true
	}
	return false
}

// cloudMetadataIPs is the closed list of cloud-provider metadata
// service addresses. The list is intentionally narrow: only the
// well-known IP literals every major provider documents, not the wider
// link-local space (which [IsPrivateIP] already covers). Keeping the
// list small lets [IsCloudMetadataIP] return false for legitimate
// link-local services on a private LAN even when the deployment opts
// into [Options.AllowPrivate].
//
//nolint:gochecknoglobals // closed deny-list table.
var cloudMetadataIPs = []net.IP{
	// AWS / GCP / Azure / OpenStack / DO / Hetzner — IPv4.
	net.IPv4(169, 254, 169, 254),
	// Alibaba Cloud — IPv4.
	net.IPv4(100, 100, 100, 200),
	// AWS — IPv6 (fd00:ec2::254).
	net.ParseIP("fd00:ec2::254"),
	// GCP — IPv6 (fd00:ec2::254 alternative; documented as fde4:7e0c:cb53:5cb1::1
	// for some Google-internal references but not stable, so we pin the
	// AWS-shape literal only).
}

// IsCloudMetadataIP reports whether ip is one of the cloud-provider
// metadata service addresses (AWS / GCP / Azure / Alibaba / OpenStack
// IMDS, AWS IPv6 metadata). Cloud metadata services hand out IAM
// credentials over plain HTTP without any authentication header, so a
// successful SSRF to one of these is functionally a credential leak.
//
// [Options.AllowPrivate] suppresses the broader [IsPrivateIP] gate but
// MUST NOT suppress this one — the opt-in is documented as "I run RPs
// on a private LAN", not "I want to expose cloud credentials". Every
// caller that consults [Options.AllowPrivate] re-checks
// [IsCloudMetadataIP] independently so the carve-out is structural.
func IsCloudMetadataIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, candidate := range cloudMetadataIPs {
		if candidate != nil && candidate.Equal(ip) {
			return true
		}
	}
	return false
}
