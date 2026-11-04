package netsec

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

const testOptIn = "op.WithAllowPrivateNetwork(op.OutboundJWKS)"

func privateLookup(_ context.Context, _ string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
}

func metadataLookup(_ context.Context, _ string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
}

func TestPrivateRefusalNamesOptIn(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		run  func(opts Options) error
	}{
		{"url-gate-localhost", func(o Options) error {
			return AssertSafeURL(context.Background(), "http://localhost/x", o)
		}},
		{"url-gate-ip-literal", func(o Options) error {
			return AssertSafeURL(context.Background(), "http://10.0.0.1/x", o)
		}},
		{"dns-time", func(o Options) error {
			o.LookupHook = privateLookup
			return AssertSafeURL(context.Background(), "http://rp.example/x", o)
		}},
		{"dial-time", func(o Options) error {
			return makeDialControl(o)("tcp4", "127.0.0.1:8080", nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.run(Options{OptIn: testOptIn})
			if !errors.Is(err, ErrPrivateNetworkBlocked) {
				t.Fatalf("err=%v want ErrPrivateNetworkBlocked", err)
			}
			if !strings.Contains(err.Error(), "pass "+testOptIn+" to admit private-network targets") {
				t.Fatalf("err=%q lacks the opt-in hint", err)
			}

			err = tc.run(Options{})
			if !errors.Is(err, ErrPrivateNetworkBlocked) {
				t.Fatalf("err=%v want ErrPrivateNetworkBlocked", err)
			}
			if strings.Contains(err.Error(), "pass ") {
				t.Fatalf("err=%q carries a hint without OptIn", err)
			}
		})
	}
}

func TestMetadataRefusalNeverNamesOptIn(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		run  func(opts Options) error
	}{
		{"url-gate", func(o Options) error {
			return AssertSafeURL(context.Background(), "http://169.254.169.254/x", o)
		}},
		{"dns-time", func(o Options) error {
			o.LookupHook = metadataLookup
			return AssertSafeURL(context.Background(), "http://rp.example/x", o)
		}},
		{"dial-time", func(o Options) error {
			return makeDialControl(o)("tcp4", "169.254.169.254:80", nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.run(Options{OptIn: testOptIn})
			if !errors.Is(err, ErrCloudMetadataBlocked) {
				t.Fatalf("err=%v want ErrCloudMetadataBlocked", err)
			}
			if strings.Contains(err.Error(), testOptIn) {
				t.Fatalf("err=%q names an option that cannot lift the refusal", err)
			}
		})
	}
}

func TestSchemeRefusalNeverNamesOptIn(t *testing.T) {
	t.Parallel()
	err := AssertSafeURL(context.Background(), "ftp://rp.example/x", Options{OptIn: testOptIn})
	if !errors.Is(err, ErrSchemeNotAllowed) || strings.Contains(err.Error(), testOptIn) {
		t.Fatalf("err=%v want a scheme refusal without the hint", err)
	}
}
