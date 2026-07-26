package oidcdynamo

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Attribute names shared by every table. Keeping them in one block
// makes the item layout auditable at a glance and stops a typo in one
// substore from silently writing to a second attribute.
const (
	// attrDoc holds the record itself, JSON-encoded. Nothing conditions
	// on it, so its encoding is free to follow the Go types.
	attrDoc = "doc"

	// attrTTL is the table's TTL attribute (unix seconds). It exists so
	// DynamoDB reclaims storage; expiry is enforced on read.
	attrTTL = "ttl"

	// attrExpiresAt is the record's expiry as unix nanoseconds. It is
	// projected separately from attrTTL because TTL must be seconds
	// while the library's comparisons are nanosecond-precise.
	attrExpiresAt = "expires_at"
)

// The av* constructors all return types.AttributeValue, which the AWS
// SDK models as an interface with one unexported method and a
// per-shape implementation. Returning the concrete member type instead
// would force every call site to convert, so the interface return is
// the SDK's design rather than a choice this package makes.
//
//nolint:ireturn // types.AttributeValue is the SDK's own sum type.
func avS(s string) types.AttributeValue { return &types.AttributeValueMemberS{Value: s} }

//nolint:ireturn // types.AttributeValue is the SDK's own sum type.
func avN(n int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: formatInt(n)}
}

//nolint:ireturn // types.AttributeValue is the SDK's own sum type.
func avB(b []byte) types.AttributeValue {
	// DynamoDB rejects an empty binary value for a key attribute and
	// round-trips it inconsistently elsewhere, so an empty slice is
	// stored as the empty string marker instead.
	if len(b) == 0 {
		return &types.AttributeValueMemberNULL{Value: true}
	}
	return &types.AttributeValueMemberB{Value: b}
}

//nolint:ireturn // types.AttributeValue is the SDK's own sum type.
func avBool(b bool) types.AttributeValue { return &types.AttributeValueMemberBOOL{Value: b} }

// avTime renders a wall-clock instant as unix nanoseconds. The zero
// time maps to 0 so a caller that checked IsZero before writing sees
// the same shape on the way back out.
//
//nolint:ireturn // types.AttributeValue is the SDK's own sum type.
func avTime(t time.Time) types.AttributeValue {
	if t.IsZero() {
		return avN(0)
	}
	return avN(t.UnixNano())
}

// avTTL renders an expiry as the unix seconds DynamoDB's TTL feature
// requires. A zero expiry yields no attribute at all: the item then has
// no TTL and is retained until something deletes it explicitly.
//
//nolint:ireturn // types.AttributeValue is the SDK's own sum type.
func avTTL(t time.Time) (types.AttributeValue, bool) {
	if t.IsZero() {
		return nil, false
	}
	return avN(t.Unix()), true
}

func readS(item map[string]types.AttributeValue, key string) string {
	if v, ok := item[key].(*types.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

func readN(item map[string]types.AttributeValue, key string) int64 {
	v, ok := item[key].(*types.AttributeValueMemberN)
	if !ok {
		return 0
	}
	n, err := parseInt(v.Value)
	if err != nil {
		return 0
	}
	return n
}

func readBool(item map[string]types.AttributeValue, key string) bool {
	if v, ok := item[key].(*types.AttributeValueMemberBOOL); ok {
		return v.Value
	}
	return false
}

func readTime(item map[string]types.AttributeValue, key string) time.Time {
	return nanosToTime(readN(item, key))
}

// readBytes returns a copy of a binary attribute, or nil when the
// attribute is absent or was stored as the empty-value NULL marker.
func readBytes(item map[string]types.AttributeValue, key string) []byte {
	v, ok := item[key].(*types.AttributeValueMemberB)
	if !ok {
		return nil
	}
	return append([]byte(nil), v.Value...)
}

func nanosToTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

// marshalDoc encodes a record as the JSON document stored under
// [attrDoc].
//
//nolint:ireturn // types.AttributeValue is the SDK's own sum type.
func marshalDoc(v any) (types.AttributeValue, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidDocument, err)
	}
	return &types.AttributeValueMemberB{Value: b}, nil
}

// unmarshalDoc decodes the document written by [marshalDoc].
//
// UseNumber preserves integer fidelity through the map[string]any
// fields (authorization_details, access-token extras) so a round trip
// does not silently widen a payment amount to float64 — the same
// concern the SQL adapter handles in its JSON column decoding.
func unmarshalDoc(item map[string]types.AttributeValue, out any) error {
	v, ok := item[attrDoc].(*types.AttributeValueMemberB)
	if !ok {
		return fmt.Errorf("%w: item has no %s attribute", ErrInvalidDocument, attrDoc)
	}
	dec := json.NewDecoder(bytes.NewReader(v.Value))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDocument, err)
	}
	return nil
}

func formatInt(n int64) string { return strconv.FormatInt(n, 10) }

// hexEncode renders opaque bytes as a string key attribute. WebAuthn
// credential ids are arbitrary bytes and DynamoDB key attributes are
// either strings or binary; hex keeps the value printable in a console
// or a CloudWatch log without changing what it identifies.
func hexEncode(b []byte) string { return hex.EncodeToString(b) }

func parseInt(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("oidcdynamo: parse numeric attribute %q: %w", s, err)
	}
	return n, nil
}
