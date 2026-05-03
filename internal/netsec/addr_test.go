//nolint:testpackage // keep white-box access to the cloud-metadata table.
package netsec

import (
	"net"
	"testing"
)

func TestIsLocalHostname(t *testing.T) {
	t.Parallel()

	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"LocalHost", true},
		{"localhost.", true},
		{"ip6-localhost", true},
		{"ip6-loopback", true},
		{"localhost.example", false},
		{"example.com", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			t.Parallel()
			if got := IsLocalHostname(tc.host); got != tc.want {
				t.Fatalf("IsLocalHostname(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"loopback-v4", "127.0.0.1", true},
		{"loopback-v4-block", "127.10.20.30", true},
		{"loopback-v6", "::1", true},
		{"link-local-v4", "169.254.10.20", true},
		{"link-local-v6", "fe80::1", true},
		{"rfc1918-10", "10.1.2.3", true},
		{"rfc1918-172", "172.16.5.6", true},
		{"rfc1918-192", "192.168.1.10", true},
		{"ula-v6", "fc00::1", true},
		{"unspecified-v4", "0.0.0.0", true},
		{"unspecified-v6", "::", true},
		{"cloud-metadata-aws", "169.254.169.254", true}, // also link-local
		{"cloud-metadata-alibaba", "100.100.100.200", true},
		{"public-v4", "1.1.1.1", false},
		{"public-v6", "2001:db8::1", false},
		{"nil", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var ip net.IP
			if tc.ip != "" {
				ip = net.ParseIP(tc.ip)
				if ip == nil {
					t.Fatalf("invalid test fixture IP %q", tc.ip)
				}
			}
			if got := IsPrivateIP(ip); got != tc.want {
				t.Fatalf("IsPrivateIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestIsCloudMetadataIP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"aws-gcp-azure-imds", "169.254.169.254", true},
		{"alibaba-imds", "100.100.100.200", true},
		{"aws-ipv6-imds", "fd00:ec2::254", true},
		{"public-v4", "1.1.1.1", false},
		{"link-local-non-metadata", "169.254.0.1", false},
		{"loopback", "127.0.0.1", false},
		{"nil", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var ip net.IP
			if tc.ip != "" {
				ip = net.ParseIP(tc.ip)
				if ip == nil {
					t.Fatalf("invalid test fixture IP %q", tc.ip)
				}
			}
			if got := IsCloudMetadataIP(ip); got != tc.want {
				t.Fatalf("IsCloudMetadataIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}
