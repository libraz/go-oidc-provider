package oidcdynamo

import (
	"time"

	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// digestKey derives the partition key for a value the client presents
// as a bearer secret. Only the digest is stored, so a table export, a
// stream consumer, or a backup yields values that cannot be redeemed.
func digestKey(raw string) string { return patterns.Digest(raw) }

// isExpired reports whether t has passed. The zero time means "no
// expiry". The boundary is strict-less-than, matching the shared
// [patterns.IsExpiredStrict] the other adapters use, so the three
// backends agree on the exact instant a record dies.
func (s *Store) isExpired(t time.Time) bool {
	return patterns.IsExpiredStrict(t, s.now())
}

// optionalTime reads an attribute that models a *time.Time: zero means
// "not set" and yields nil rather than a pointer to the zero instant.
func optionalTime(from item, attr string) *time.Time {
	t := readTime(from, attr)
	if t.IsZero() {
		return nil
	}
	return &t
}

// timeOrZero flattens a *time.Time for projection into an attribute.
func timeOrZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
