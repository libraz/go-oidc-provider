package op

import (
	"maps"
	"strconv"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/op/store"
)

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
// except the final subject-mode marker commit; a build that fails in that
// commit can leave the batch applied, and the next build accepts it. Existing equivalent static clients are accepted unchanged;
// metadata or secret differences return a configuration conflict rather than
// overwriting an operator-managed record.
// Stable since v1.0.
func WithStaticClients(seeds ...ClientSeed) Option {
	return optionFunc(func(c *config) error {
		if len(seeds) == 0 {
			return newConfigurationError("WithStaticClients requires at least one ClientSeed", nil)
		}
		records, plaintexts, err := collectStaticClientSeeds(seeds)
		if err != nil {
			return err
		}
		c.staticClients = append(c.staticClients, records...)
		c.recordDefaultedSeedGrants(seeds, records)
		if len(plaintexts) > 0 && c.staticClientSecrets == nil {
			c.staticClientSecrets = make(map[string]staticSeedSecrets, len(plaintexts))
		}
		maps.Copy(c.staticClientSecrets, plaintexts)
		return nil
	})
}

// WithHighEntropyClientSecrets declares that every client_secret this
// OP verifies is a machine-generated value, and switches secret
// verification off the password KDF onto a keyed hash.
//
// The default costs about 90 ms and 64 MiB per verification, because
// the stored hash is Argon2id. That expense buys resistance to offline
// guessing of a stolen hash, which is decisive for a secret a person
// chose and worth nothing for one drawn from 256 bits of randomness —
// no attacker searches that space at any per-guess cost. An OP whose
// clients all carry generated secrets is paying a password defence on
// every machine-to-machine request. With this option a verification is
// a few microseconds and allocates nothing.
//
// # What the OP requires in exchange
//
// The declaration is enforced, not trusted. [New] rejects the
// configuration when a static client still carries an Argon2id hash —
// which is what [ConfidentialClient.Secret] produces — so adopting the
// option means provisioning through [NewClientSecret] or
// [HashHighEntropyClientSecret], both of which refuse a secret short
// enough to have been typed. Dynamic registration mints in the new
// format automatically.
//
// # The migration hazard
//
// A record already in the store cannot be converted: the OP holds no
// plaintext to re-hash. Such a client keeps authenticating, at the old
// cost — and that is visible. Rejections are padded to the cost of a
// verification so an unregistered client_id cannot be told apart from
// a wrong secret, and with this option that padding is microseconds;
// a client still on the old format answers in tens of milliseconds
// and so becomes distinguishable from an unknown one. Re-provision
// every client before enabling this on a store that predates it.
//
// This is exactly why the format is not selected per client. Doing
// that would put the two costs side by side in every deployment and
// make the client's own storage format the thing the timing reveals.
//
// Stable since v1.1.
func WithHighEntropyClientSecrets() Option {
	return optionFunc(func(c *config) error {
		c.highEntropyClientSecrets = true
		return nil
	})
}

// collectStaticClientSeeds projects seeds onto store.Client records and
// captures the plaintext each seed carried, keyed by client ID. It is the
// single validation path shared by [WithStaticClients] and
// [SyncStaticClients]: a nil seed, a seed that fails its own projection
// (an empty secret, a malformed field) and a duplicate ID within seeds
// are rejected here.
func collectStaticClientSeeds(seeds []ClientSeed) (records []store.Client, plaintexts map[string]staticSeedSecrets, err error) {
	records = make([]store.Client, 0, len(seeds))
	for i, seed := range seeds {
		if nilcheck.IsNil(seed) {
			return nil, nil, newConfigurationError("WithStaticClients["+strconv.Itoa(i)+"]: nil ClientSeed", nil)
		}
		rec, seedErr := seed.seed()
		if seedErr != nil {
			return nil, nil, newConfigurationError("WithStaticClients["+strconv.Itoa(i)+"]: "+seedErr.Error(), seedErr)
		}
		records = append(records, rec)
		current, hasCurrent := staticClientPlaintext(seed)
		previous, hasPrevious := staticClientPreviousPlaintext(seed)
		if hasCurrent || hasPrevious {
			if plaintexts == nil {
				plaintexts = make(map[string]staticSeedSecrets)
			}
			plaintexts[rec.ID] = staticSeedSecrets{current: current, previous: previous}
		}
	}
	seen := make(map[string]struct{}, len(records))
	for i := range records {
		if _, dup := seen[records[i].ID]; dup {
			return nil, nil, newConfigurationError("WithStaticClients["+strconv.Itoa(i)+
				"]: duplicate client_id "+records[i].ID, nil)
		}
		seen[records[i].ID] = struct{}{}
	}
	return records, plaintexts, nil
}

// recordDefaultedSeedGrants notes the client_id of every seed that left
// GrantTypes empty; records[i] is the projection of seeds[i].
func (c *config) recordDefaultedSeedGrants(seeds []ClientSeed, records []store.Client) {
	for i, seed := range seeds {
		if !seedGrantTypesEmpty(seed) {
			continue
		}
		if c.staticClientDefaultedGrants == nil {
			c.staticClientDefaultedGrants = make(map[string]struct{})
		}
		c.staticClientDefaultedGrants[records[i].ID] = struct{}{}
	}
}

// seedGrantTypesEmpty reports whether seed left GrantTypes empty, so the
// builder applied its default grant set.
func seedGrantTypesEmpty(seed ClientSeed) bool {
	switch value := seed.(type) {
	case PublicClient:
		return len(value.GrantTypes) == 0
	case *PublicClient:
		return len(value.GrantTypes) == 0
	case ConfidentialClient:
		return len(value.GrantTypes) == 0
	case *ConfidentialClient:
		return len(value.GrantTypes) == 0
	case PrivateKeyJWTClient:
		return len(value.GrantTypes) == 0
	case *PrivateKeyJWTClient:
		return len(value.GrantTypes) == 0
	default:
		return false
	}
}

// staticClientPlaintext extracts the plaintext a seed carried, if it
// carried one at all.
//
// A [ConfidentialClient] built from SecretHash has no plaintext, and
// must not be recorded as having an empty one: startup reconciliation
// treats a remembered plaintext as "compare this against the stored
// hash", and an empty string would fail that comparison and report the
// existing record as a configuration conflict.
func staticClientPlaintext(seed ClientSeed) (string, bool) {
	switch value := seed.(type) {
	case ConfidentialClient:
		return value.Secret, value.Secret != ""
	case *ConfidentialClient:
		return value.Secret, value.Secret != ""
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
			return newConfigurationError("WithFirstPartyClients requires at least one client_id", nil)
		}
		seen := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			if id == "" {
				return newConfigurationError("WithFirstPartyClients: client_id must not be empty", nil)
			}
			if _, dup := seen[id]; dup {
				return newConfigurationError("WithFirstPartyClients: duplicate client_id "+id, nil)
			}
			seen[id] = struct{}{}
		}
		c.firstPartyClients = append(c.firstPartyClients, ids...)
		return nil
	})
}
