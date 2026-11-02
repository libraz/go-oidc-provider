package securefetch

import (
	"math"
	"strconv"
	"strings"
	"time"
)

// CacheControl holds the Cache-Control directives a fetched-document cache
// consults.
type CacheControl struct {
	NoStore, NoCache, Private bool

	// HasMaxAge reports whether a well-formed max-age directive was present;
	// MaxAge is its value, capped at the largest representable duration.
	HasMaxAge bool
	MaxAge    time.Duration
}

// ParseCacheControl reads the directives from every Cache-Control header line
// in values. A directive argument on no-cache or private (a field-name list)
// still counts as the directive. The first well-formed max-age wins; a
// malformed or negative one is ignored, and a quoted value is accepted.
func ParseCacheControl(values []string) CacheControl {
	const maxSeconds = int64(math.MaxInt64 / int64(time.Second))
	var cc CacheControl
	for _, v := range values {
		for raw := range strings.SplitSeq(v, ",") {
			name, arg, _ := strings.Cut(strings.TrimSpace(raw), "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "no-store":
				cc.NoStore = true
			case "no-cache":
				cc.NoCache = true
			case "private":
				cc.Private = true
			case "max-age":
				if cc.HasMaxAge {
					continue
				}
				secs, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(arg), `"`), 10, 64)
				if err != nil || secs < 0 {
					continue
				}
				cc.HasMaxAge = true
				cc.MaxAge = time.Duration(min(secs, maxSeconds)) * time.Second
			}
		}
	}
	return cc
}
