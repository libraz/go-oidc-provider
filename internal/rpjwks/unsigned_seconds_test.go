//nolint:testpackage // intentional white-box test for unexported helpers.
package rpjwks

import "testing"

func TestParseUnsignedSeconds_EdgeCases(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"0", 0, false},
		{"300", 300, false},
		{"00000000000000000000000042", 42, false},
		{"2147483648", 1 << 31, false}, // the cap itself is admitted
		{"2147483649", 0, true},        // one past the cap
		{"99999999999999999999999", 0, true},
		{"", 0, true},
		{"+5", 0, true},
		{"-5", 0, true},
		{"5s", 0, true},
		{"1_000", 0, true},
		{" 5", 0, true},
		{"٣", 0, true}, // non-ASCII digit
	} {
		got, err := parseUnsignedSeconds(tc.in)
		if (err != nil) != tc.wantErr || (err == nil && got != tc.want) {
			t.Errorf("parseUnsignedSeconds(%q) = (%d, %v), want (%d, err=%v)", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}
