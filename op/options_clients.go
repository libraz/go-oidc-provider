package op

import "strconv"

// WithStaticClients seeds the [Provider]'s static-client surface from
// the supplied [ClientSeed] values. Each seed is projected onto a
// [store.Client] record via its [ClientSeed.seed] method; any error
// from the projection (most commonly an empty
// [ConfidentialClient.Secret] reaching [HashClientSecret]) surfaces at
// the option site with the seed's index in the description so the
// caller can locate the offending entry.
// Repeated calls append to the configured set so embedders MAY layer
// builders (a base set plus a deployment-specific overlay) without
// duplicate-rejection. The aggregate slice feeds the orchestrator
// hookup; today the records are stored on config and consumed by the
// orchestrator wiring that lands in a follow-up.
// Stable since v0.1.
func WithStaticClients(seeds ...ClientSeed) Option {
	return optionFunc(func(c *config) error {
		if len(seeds) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithStaticClients requires at least one ClientSeed",
			}
		}
		for i, s := range seeds {
			if s == nil {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithStaticClients[" + strconv.Itoa(i) + "]: nil ClientSeed",
				}
			}
			rec, err := s.seed()
			if err != nil {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithStaticClients[" + strconv.Itoa(i) + "]: " + err.Error(),
					Cause:       err,
				}
			}
			c.staticClients = append(c.staticClients, rec)
		}
		return nil
	})
}

// WithFirstPartyClients marks the listed client_id values as first-
// party so the consent prompt is skipped for them. The auto-consent
// path is gated on the matching [store.Client.Source] being
// [store.ClientSourceStatic] or [store.ClientSourceAdmin] —
// [store.ClientSourceDynamic] (RFC 7591 self-registered) is excluded
// because dynamically-registered clients cannot be vetted as
// first-party.
// Validation:
//   - The id list MUST be non-empty.
//   - Duplicate ids within a single call are rejected; repeated calls
//     append so embedders may layer deployment-specific entries.
//   - Every advertised id MUST appear in [WithStaticClients] after
//     every option has been applied; the cross-option check runs in
//     [config.validate] so the two options are order-independent.
//   - FAPI 2.0 profiles forbid first-party auto-consent; combining
//     [WithFirstPartyClients] with [WithProfile(profile.FAPI2*)]
//     fails [New].
//
// Stable since v0.1.
func WithFirstPartyClients(ids ...string) Option {
	return optionFunc(func(c *config) error {
		if len(ids) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithFirstPartyClients requires at least one client_id",
			}
		}
		seen := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			if id == "" {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithFirstPartyClients: client_id must not be empty",
				}
			}
			if _, dup := seen[id]; dup {
				return &Error{
					Code:        codeConfiguration,
					Description: "WithFirstPartyClients: duplicate client_id " + id,
				}
			}
			seen[id] = struct{}{}
		}
		c.firstPartyClients = append(c.firstPartyClients, ids...)
		return nil
	})
}
