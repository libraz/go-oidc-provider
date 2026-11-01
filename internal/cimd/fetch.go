package cimd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/securefetch"
)

// Fetch and cache envelope. The values are fixed rather than exposed as
// options: the body cap is the draft's recommended 5 KB, and the lifetime
// bounds keep a document from either hammering its host or outliving a
// change to it by more than a day.
const (
	maxDocumentBytes = 5 * 1024
	minDocumentTTL   = 60 * time.Second
	maxDocumentTTL   = 24 * time.Hour
	cacheMaxEntries  = 256
)

// acceptContentTypes is the media-type allow-list for a metadata document; the
// request's Accept header is derived from it.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var acceptContentTypes = []string{"application/json", "application/*+json"}

// Closed set of cimd.fetch_failed reasons.
const (
	reasonStatus      = "status"
	reasonNetwork     = "network"
	reasonTooLarge    = "too_large"
	reasonContentType = "content_type"
	reasonJSON        = "json"
	reasonValidation  = "validation"
)

// fallbackValidationCode is the error_code recorded when the validator's error
// does not carry a code of its own.
const fallbackValidationCode = "invalid_client_metadata"

// fetchFailure is the loader error for a document that could not be used. It
// deliberately does not wrap the underlying cause: a transport timeout would
// otherwise read as context.DeadlineExceeded, which remotecache refuses to
// negative-cache, and a slow attacker URL would be re-fetched on every request.
type fetchFailure struct {
	reason string
}

func (f *fetchFailure) Error() string { return "cimd: metadata document " + f.reason }

// codedError is the shape a validator error exposes its wire error code with.
type codedError interface {
	ErrorCode() string
}

// validationCode extracts the validator's error code for the audit record.
func validationCode(err error) string {
	var coded codedError
	if errors.As(err, &coded) {
		if code := coded.ErrorCode(); code != "" {
			return code
		}
	}
	return fallbackValidationCode
}

// fetchPolicy returns the securefetch envelope for client_id URLs. The dev
// opt-in widens the scheme set to http and lifts the private and loopback
// deny-list together; cloud-metadata addresses stay refused either way.
func fetchPolicy(allowPrivate bool, timeout time.Duration, lookup func(context.Context, string) ([]net.IPAddr, error)) securefetch.Policy {
	schemes := []string{"https"}
	if allowPrivate {
		schemes = []string{"http", "https"}
	}
	return securefetch.Policy{
		AllowPrivateNetwork:  allowPrivate,
		AllowLoopbackNetwork: allowPrivate,
		AllowedSchemes:       schemes,
		MaxBodyBytes:         maxDocumentBytes,
		AcceptContentTypes:   acceptContentTypes,
		Timeout:              timeout,
		LookupHook:           lookup,
		// MaxRedirects stays zero: a 3xx is returned as-is and fails the
		// status check.
	}
}

// fetchDocument GETs the document at id and returns its body and headers, or a
// classified failure reason.
func fetchDocument(ctx context.Context, client *securefetch.Client, id string) ([]byte, http.Header, string) {
	req, err := client.NewRequest(ctx, http.MethodGet, id, nil)
	if err != nil {
		return nil, nil, reasonNetwork
	}
	req.Header.Set("Accept", strings.Join(acceptContentTypes, ", "))
	body, resp, err := client.Do(req) //nolint:bodyclose // securefetch.Do drains and closes the body internally.
	if err != nil {
		return nil, nil, classifyFetchError(err)
	}
	// securefetch admits any 2xx; the draft requires exactly 200.
	if resp.StatusCode != http.StatusOK {
		return nil, nil, reasonStatus
	}
	return body, resp.Header, ""
}

// classifyFetchError maps a securefetch error onto the closed reason set.
// Anything that is not a response-side gate is a transport-level failure,
// including the URL- and dial-time SSRF refusals.
func classifyFetchError(err error) string {
	switch {
	case errors.Is(err, securefetch.ErrUnexpectedStatus):
		return reasonStatus
	case errors.Is(err, securefetch.ErrBodyTooLarge):
		return reasonTooLarge
	case errors.Is(err, securefetch.ErrUnexpectedContentType):
		return reasonContentType
	default:
		return reasonNetwork
	}
}

// documentTTL derives a document's cache lifetime from its response headers:
// Cache-Control max-age, else Expires, else the floor, clamped to
// [minDocumentTTL, maxDocumentTTL]. no-store, no-cache and private pin the
// floor. An unparseable Expires is treated as already expired (RFC 9111
// §5.3), which the clamp lifts to the floor.
func documentTTL(h http.Header, now time.Time) time.Duration {
	cc := parseCacheControl(h.Values("Cache-Control"))
	if cc.noStore || cc.noCache || cc.private {
		return minDocumentTTL
	}
	ttl := minDocumentTTL
	switch {
	case cc.hasMaxAge:
		ttl = cc.maxAge
	case h.Get("Expires") != "":
		if exp, err := http.ParseTime(h.Get("Expires")); err == nil {
			ttl = exp.Sub(now)
		} else {
			ttl = 0
		}
	}
	return min(max(ttl, minDocumentTTL), maxDocumentTTL)
}

type cacheControl struct {
	noStore, noCache, private bool
	hasMaxAge                 bool
	maxAge                    time.Duration
}

// parseCacheControl reads the directives documentTTL consults. A directive
// argument on no-cache or private (a field-name list) still counts as the
// directive. The first well-formed max-age wins; a malformed one is ignored.
func parseCacheControl(values []string) cacheControl {
	var cc cacheControl
	for _, v := range values {
		for raw := range strings.SplitSeq(v, ",") {
			name, arg, _ := strings.Cut(strings.TrimSpace(raw), "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "no-store":
				cc.noStore = true
			case "no-cache":
				cc.noCache = true
			case "private":
				cc.private = true
			case "max-age":
				if cc.hasMaxAge {
					continue
				}
				secs, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(arg), `"`), 10, 64)
				if err != nil || secs < 0 {
					continue
				}
				cc.hasMaxAge = true
				cc.maxAge = time.Duration(min(secs, int64(maxDocumentTTL/time.Second))) * time.Second
			}
		}
	}
	return cc
}
