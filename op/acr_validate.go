package op

import (
	"maps"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/authn"
)

// validateACRAdvertisement rejects an acr_values_supported entry the
// built-in ACR policy cannot resolve, and an [ACRLevels] table that is
// malformed or contradicts the canonical URI mapping. A custom
// [ACRPolicy] is not inspected. A static client's DefaultACRValues must
// appear in the advertised acr_values_supported whenever one is set, and
// must be resolvable by the policy when it is a built-in one.
func (c *config) validateACRAdvertisement() error {
	var levels ACRLevels
	builtin := true
	switch p := c.effectiveACRPolicy().(type) {
	case DefaultACRPolicy:
	case ACRLevels:
		levels = p
	default:
		builtin = false
	}
	if builtin {
		if err := c.validateBuiltinACRPolicy(levels); err != nil {
			return err
		}
	}
	return c.validateStaticClientACRDefaults(levels, builtin)
}

// validateBuiltinACRPolicy checks the [ACRLevels] table and the
// advertised acr_values_supported against the built-in policy.
func (c *config) validateBuiltinACRPolicy(levels ACRLevels) error {
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

// validateStaticClientACRDefaults rejects a static client whose
// DefaultACRValues entry is not advertised, or, under a built-in policy,
// cannot be resolved by it.
func (c *config) validateStaticClientACRDefaults(levels ACRLevels, builtin bool) error {
	for i := range c.staticClients {
		client := &c.staticClients[i]
		for _, v := range client.DefaultACRValues {
			if len(c.acrValuesSupported) > 0 && !slices.Contains(c.acrValuesSupported, v) {
				return &Error{
					Code: codeConfiguration,
					Description: "static client " + client.ID + ": DefaultACRValues entry " + v +
						" is not in WithACRValuesSupported",
				}
			}
			if _, ok := levels.level(v); builtin && !ok {
				return &Error{
					Code: codeConfiguration,
					Description: "static client " + client.ID + ": DefaultACRValues entry " + v +
						" cannot be satisfied by the ACR policy; declare it with ACRLevels via WithACRPolicy",
				}
			}
		}
	}
	return nil
}
