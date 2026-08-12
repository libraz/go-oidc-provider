package oidcsql

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// ErrInvalidJSON is returned when an embedder supplies a map or
// authorization-details value that JSON cannot represent (for example NaN,
// a function, channel, or cycle). Store writes reject it before executing SQL.
var ErrInvalidJSON = errors.New("oidcsql: value is not JSON-serializable")

// encodeStrings serialises a []string column. The adapter stores
// slices as JSON text (for SQLite) or JSON/JSONB (for MySQL/Postgres);
// either path accepts the same JSON bytes verbatim.
func encodeStrings(s []string) []byte {
	if s == nil {
		return []byte("[]")
	}
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal of a []string never fails; the panic surfaces
		// only an implementation error.
		panic(fmt.Sprintf("oidcsql: marshal []string: %v", err)) //nolint:forbidigo // infallible: encoding/json never errors on []string.
	}
	return b
}

// encodeNullableStrings preserves a nil allowlist as SQL NULL. A nil RAT
// ceiling means unrestricted and is distinct from an explicitly supplied
// empty JSON array for callers that care about round-trip shape.
func encodeNullableStrings(s []string) any {
	if s == nil {
		return nil
	}
	return encodeStrings(s)
}

// decodeStrings deserialises bytes written by encodeStrings. Empty or
// JSON-null inputs decode to a nil slice so contract tests that
// observe equality on (nil) keep their semantics.
func decodeStrings(b []byte) ([]string, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var s []string
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("oidcsql: unmarshal []string: %w", err)
	}
	return s, nil
}

// encodeMap serialises a map[string]any column. nil maps encode as
// the JSON null literal so the round-trip preserves "no claims".
func encodeMap(m map[string]any) ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("%w: map[string]any: %w", ErrInvalidJSON, err)
	}
	return b, nil
}

// decodeMap deserialises a column written by encodeMap. The literal
// JSON null decodes to a nil map, mirroring the inmem reference.
//
// UseNumber for the same reason [decodeObjectArray] uses it, and it
// matters more here: these columns hold embedder-supplied claim maps
// that are re-serialised into ID tokens and /userinfo responses, so a
// number widened to float64 on the way out of the database is a wrong
// value delivered to the relying party. Anything past the float64
// integer-exact range — an upstream account id, an order number — comes
// back rounded, silently and identically on every read, which is not a
// shape an embedder can detect downstream. The DynamoDB adapter decodes
// its whole document this way already; this keeps SQL from being the
// one backend that corrupts the value.
func decodeMap(b []byte) (map[string]any, error) {
	if len(b) == 0 || string(b) == "null" {
		return nil, nil //nolint:nilnil // empty/null column legitimately maps to (nil, nil); mirrors the inmem reference.
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("oidcsql: unmarshal map[string]any: %w", err)
	}
	return m, nil
}

// encodeObjectArray serialises a []map[string]any column (the RFC 9396
// authorization_details). A nil slice encodes as the JSON null literal so
// the round-trip preserves "no authorization_details".
func encodeObjectArray(a []map[string]any) ([]byte, error) {
	if a == nil {
		return []byte("null"), nil
	}
	b, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("%w: []map[string]any: %w", ErrInvalidJSON, err)
	}
	return b, nil
}

// decodeObjectArray deserialises a column written by encodeObjectArray.
// The literal JSON null (or an empty column) decodes to a nil slice,
// mirroring the inmem reference.
func decodeObjectArray(b []byte) ([]map[string]any, error) {
	if len(b) == 0 || string(b) == "null" {
		return nil, nil
	}
	// UseNumber preserves integer fidelity so a round-trip through the
	// column matches what authorizationdetails.Check decoded at the front
	// door (e.g. a payment amount is not silently widened to float64).
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var a []map[string]any
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("oidcsql: unmarshal []map[string]any: %w", err)
	}
	return a, nil
}

// timeToInt64 converts a time.Time to the unix-nanosecond integer
// representation used by the schema. The zero time encodes as 0 so
// callers that observe (time.Time{}).IsZero() before writing get the
// same shape on the way back out.
func timeToInt64(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// int64ToTime is the inverse of timeToInt64.
func int64ToTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

// timePtrToInt64Ptr maps a *time.Time to a nullable *int64 column.
func timePtrToInt64Ptr(t *time.Time) *int64 {
	if t == nil {
		return nil
	}
	v := timeToInt64(*t)
	return &v
}

// int64PtrToTimePtr is the inverse of timePtrToInt64Ptr.
func int64PtrToTimePtr(n *int64) *time.Time {
	if n == nil {
		return nil
	}
	t := int64ToTime(*n)
	return &t
}

// isExpired reports whether t is strictly before clock.Now(). The
// zero time is treated as "no expiry" so records may opt out of
// expiry by leaving the field unset. The body delegates to
// [patterns.IsExpiredStrict] so the strict-less-than boundary
// semantic stays byte-equivalent with the inmem reference adapter
// — the contract harness pins the equivalence and the shared helper
// guarantees a single call site can never drift.
func isExpired(t time.Time, clock Clock) bool {
	return patterns.IsExpiredStrict(t, clock.Now())
}

// boolToInt64 maps a Go bool to the integer 0/1 the schema stores.
// Every dialect's boolean-shaped column is declared as an integer type
// (MySQL TINYINT(1), SQLite INTEGER, PostgreSQL SMALLINT) so one bind
// shape works everywhere. PostgreSQL BOOLEAN is deliberately not used:
// pgx refuses an integer bind parameter for OID 16.
func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// int64ToBool is the inverse of boolToInt64. database/sql may surface
// the value as int64 (sqlite, mysql) or as bool (postgres); the
// scanning helpers always use int64 so the adapter normalises the
// shape itself.
func int64ToBool(n int64) bool { return n != 0 }
