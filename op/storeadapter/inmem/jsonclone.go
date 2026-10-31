package inmem

import "reflect"

// cloneObjectArray deep-copies a []map[string]any (the RFC 9396
// authorization_details), including nested JSON maps and arrays, so a stored
// grant cannot be mutated through a caller-held reference.
func cloneObjectArray(in []map[string]any) []map[string]any {
	if in == nil {
		return nil
	}
	out := make([]map[string]any, len(in))
	for i, m := range in {
		out[i] = cloneMap(m)
	}
	return out
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = cloneJSONValue(v)
	}
	return out
}

// cloneJSONValue recursively copies maps and slices while preserving their Go
// type. Claims and authorization details accept arbitrary JSON-compatible
// values, so cloning only map[string]any / []any would still alias legitimate
// typed values such as []string or map[string][]any.
func cloneJSONValue(v any) any {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return nil
	}
	return cloneJSONReflect(rv).Interface()
}

func cloneJSONReflect(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(cloneJSONReflect(v.Elem()))
		return out
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(iter.Key(), cloneJSONReflect(iter.Value()))
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		length := v.Len()
		for i := range length {
			out.Index(i).Set(cloneJSONReflect(v.Index(i)))
		}
		return out
	default:
		return v
	}
}
