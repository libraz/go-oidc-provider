// Package clone holds tiny defensive-copy helpers shared across the
// library. The package exists so two unrelated call sites (op/op.go's
// client-metadata projection and internal/registrationendpoint's DCR
// canonicaliser) can share a single, audited implementation rather
// than each re-deriving the helper inline.
//
// New helpers SHOULD be added here only when at least two unrelated
// packages need them; one-off clones belong with the type that owns
// them.
package clone

// Int64Ptr returns a fresh *int64 pointing at the same value as v, or
// nil when v is nil. The helper exists so callers that hand metadata
// across a copy boundary do not accidentally share the underlying
// integer with the caller's struct.
func Int64Ptr(v *int64) *int64 {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}
