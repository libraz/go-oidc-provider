package netsec

import "errors"

// IsDenyListed reports whether err is a deny-list rejection: the target
// resolves to a loopback, private or link-local range, or to a
// cloud-metadata address.
func IsDenyListed(err error) bool {
	return errors.Is(err, ErrPrivateNetworkBlocked) || errors.Is(err, ErrCloudMetadataBlocked)
}

// IsRequestRefusal reports whether err is one of the rejections the
// request-build gate raises before any network I/O: a deny-listed target
// ([IsDenyListed]), a disallowed scheme or a missing host.
func IsRequestRefusal(err error) bool {
	return IsDenyListed(err) ||
		errors.Is(err, ErrSchemeNotAllowed) ||
		errors.Is(err, ErrMissingHost)
}
