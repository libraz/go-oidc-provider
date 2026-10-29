package op

import (
	"maps"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/authn"
)

// validateACRAdvertisement rejects an acr_values_supported entry the
// built-in ACR policy cannot resolve, and an [ACRLevels] table that is
// malformed or contradicts the canonical URI mapping. A custom
// [ACRPolicy] is not inspected.
func (c *config) validateACRAdvertisement() error {
	var levels ACRLevels
	switch p := c.effectiveACRPolicy().(type) {
	case DefaultACRPolicy:
	case ACRLevels:
		levels = p
	default:
		return nil
	}
	for _, key := range slices.Sorted(maps.Keys(levels)) {
		lvl := levels[key]
		if key == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "ACRLevels: key must not be empty",
			}
		}
		if lvl < AAL1 || lvl > AAL3 {
			return &Error{
				Code:        codeConfiguration,
				Description: "ACRLevels: key " + key + " must map to AAL1, AAL2 or AAL3",
			}
		}
		if canonical := authn.AALFromACRURI(key); canonical != AAL0 && canonical != lvl {
			return &Error{
				Code: codeConfiguration,
				Description: "ACRLevels: key " + key + " is the canonical URI of " +
					canonical.String() + " and cannot map to " + lvl.String(),
			}
		}
	}
	for _, v := range c.acrValuesSupported {
		if _, ok := levels.level(v); !ok {
			return &Error{
				Code: codeConfiguration,
				Description: "WithACRValuesSupported advertises " + v +
					", which the ACR policy cannot satisfy; declare it with ACRLevels via WithACRPolicy",
			}
		}
	}
	return nil
}
