package jose

import (
	"encoding/json"
	"fmt"
)

// DecodeAudience decodes the RFC 7519 §4.1.3 "aud" claim, which is either a
// single string or an array of strings. An absent claim, a JSON null, an
// empty string and an empty array all decode to a nil slice; the caller
// applies its own rule for an empty audience. A value of any other shape,
// including an array holding a non-string element, is an error.
func DecodeAudience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return nil, nil
		}
		return []string{single}, nil
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err != nil {
		return nil, fmt.Errorf("decode aud: %w", err)
	}
	if len(multi) == 0 {
		return nil, nil
	}
	return multi, nil
}
