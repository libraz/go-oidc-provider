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
// builders (a base set plus a deployment-specific overlay); duplicate IDs in
// the aggregate set are rejected by [New]. The configured Store MUST expose
// store.StaticClientReconciler. Provider construction applies the complete
// set as one atomic, idempotent batch after every other fallible build step
// has succeeded. Existing equivalent static clients are accepted unchanged;
// metadata or secret differences return a configuration conflict rather than
// overwriting an operator-managed record.
// Stable since v1.0.
func WithStaticClients(seeds ...ClientSeed) Option {
	return optionFunc(func(c *config) error {
		if len(seeds) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithStaticClients requires at least one ClientSeed",
			}
		}
		for i, s := range seeds {
			if err := appendStaticClientSeed(c, i, s); err != nil {
				return err
			}
		}
		return nil
	})
}

func appendStaticClientSeed(c *config, index int, seed ClientSeed) error {
	if isNilLike(seed) {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithStaticClients[" + strconv.Itoa(index) + "]: nil ClientSeed",
		}
	}
	rec, err := seed.seed()
	if err != nil {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithStaticClients[" + strconv.Itoa(index) + "]: " + err.Error(),
			Cause:       err,
		}
	}
	c.staticClients = append(c.staticClients, rec)
	rememberStaticClientSecret(c, rec.ID, seed)
	return nil
}

func rememberStaticClientSecret(c *config, id string, seed ClientSeed) {
	secret, ok := staticClientPlaintext(seed)
	if !ok {
		return
	}
	if c.staticClientSecrets == nil {
		c.staticClientSecrets = make(map[string]string)
	}
	c.staticClientSecrets[id] = secret
}

func staticClientPlaintext(seed ClientSeed) (string, bool) {
	switch value := seed.(type) {
	case ConfidentialClient:
		return value.Secret, true
	case *ConfidentialClient:
		return value.Secret, true
	default:
		return "", false
	}
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
// Stable since v1.0.
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
