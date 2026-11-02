package securefetch_test

import (
	"math"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/securefetch"
)

func TestParseCacheControl(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		values []string
		want   securefetch.CacheControl
	}{
		{"empty", nil, securefetch.CacheControl{}},
		{"max-age", []string{"public, max-age=120"}, securefetch.CacheControl{HasMaxAge: true, MaxAge: 120 * time.Second}},
		{"mixed case and spaces", []string{" Max-Age = 30 "}, securefetch.CacheControl{HasMaxAge: true, MaxAge: 30 * time.Second}},
		{"quoted", []string{`max-age="45"`}, securefetch.CacheControl{HasMaxAge: true, MaxAge: 45 * time.Second}},
		{"later header line", []string{"public", "max-age=60"}, securefetch.CacheControl{HasMaxAge: true, MaxAge: 60 * time.Second}},
		{"first max-age wins", []string{"max-age=10, max-age=20"}, securefetch.CacheControl{HasMaxAge: true, MaxAge: 10 * time.Second}},
		{"malformed ignored then valid", []string{"max-age=abc, max-age=20"}, securefetch.CacheControl{HasMaxAge: true, MaxAge: 20 * time.Second}},
		{"negative ignored", []string{"max-age=-5"}, securefetch.CacheControl{}},
		{"zero is present", []string{"max-age=0"}, securefetch.CacheControl{HasMaxAge: true}},
		{"flags", []string{`no-store, no-cache="Set-Cookie", private`}, securefetch.CacheControl{NoStore: true, NoCache: true, Private: true}},
		{"overflow capped", []string{"max-age=9223372036854775807"}, securefetch.CacheControl{
			HasMaxAge: true, MaxAge: time.Duration(math.MaxInt64/int64(time.Second)) * time.Second,
		}},
		{"unparseable overflow ignored", []string{"max-age=99999999999999999999"}, securefetch.CacheControl{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := securefetch.ParseCacheControl(tc.values); got != tc.want {
				t.Errorf("ParseCacheControl(%q) = %+v, want %+v", tc.values, got, tc.want)
			}
		})
	}
}
