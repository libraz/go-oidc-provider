// Package nilcheck detects typed nils: an interface value whose dynamic
// type is set but whose underlying pointer, map, slice, channel or func is
// nil. A plain `v == nil` misses that case, so option validators that must
// reject an unusable dependency use [IsNil] instead.
package nilcheck

import "reflect"

// IsNil reports whether v is nil or a typed nil of a nillable kind.
func IsNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return rv.IsNil()
	default:
		return false
	}
}
