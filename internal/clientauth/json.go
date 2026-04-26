package clientauth

import "encoding/json"

// jsonUnmarshal centralises encoding/json access so the package can swap
// implementations later (e.g. for a stricter decoder) without touching
// every call site. It also keeps the import surface of this package
// small enough to audit.
func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
