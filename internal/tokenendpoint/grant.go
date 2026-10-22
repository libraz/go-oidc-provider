package tokenendpoint

import (
	"context"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/op/store"
)

// grantLineage names how a non-interactive redemption's credentials
// relate to a [store.Grant]. The choice decides what revocation,
// deprovisioning and subject resolution can find, and whether
// /authorize later reads the record as the user's consent for the
// client, so every minting path states it through [newGrantID].
type grantLineage int

const (
	// grantLineageConsent records a new Grant: the user approved this
	// client at the authentication device (device_code, CIBA), so the
	// record is consent the user actually gave.
	grantLineageConsent grantLineage = iota + 1

	// grantLineageInherit issues under an existing Grant the credential
	// descends from (a token exchange's subject_token grant). No record
	// is written: one keyed to the exchanging client would satisfy that
	// client's consent check at /authorize without the user approving it.
	grantLineageInherit

	// grantLineageUnbacked allocates an identity no Grant backs. A custom
	// grant's handler, not an end user's consent, vouches for its
	// subject, so there is no consent to record and none may be implied.
	grantLineageUnbacked
)

// grantIssuance is the input to [newGrantID].
type grantIssuance struct {
	Lineage grantLineage

	// Grant is the record a grantLineageConsent redemption writes. An
	// empty ID is filled with a fresh random one; a caller that derives
	// the ID from its authorization (the device grant) may race a
	// concurrent redemption of it, so an existing record under that ID is
	// the same consent and counts as recorded.
	Grant store.Grant

	// InheritedID is the existing grant a grantLineageInherit redemption
	// issues under.
	InheritedID string
}

// newGrantID returns the grant identifier a non-interactive redemption's
// credentials are issued under, writing the Grant record only for
// [grantLineageConsent]. It is the one place the token endpoint allocates
// a grant identity, so the three lineages cannot drift apart across
// grant types.
func newGrantID(ctx context.Context, deps Deps, in grantIssuance) (string, error) {
	switch in.Lineage {
	case grantLineageConsent:
		return saveConsentGrant(ctx, deps, in.Grant)
	case grantLineageInherit:
		if in.InheritedID == "" {
			return "", errors.New("tokenendpoint: inherited grant lineage names no grant")
		}
		return in.InheritedID, nil
	case grantLineageUnbacked:
		return newJTI()
	default:
		return "", fmt.Errorf("tokenendpoint: unknown grant lineage %d", in.Lineage)
	}
}

func saveConsentGrant(ctx context.Context, deps Deps, g store.Grant) (string, error) {
	if deps.Grants == nil {
		return "", errors.New("tokenendpoint: no grant store to record the grant in")
	}
	derived := g.ID != ""
	if !derived {
		id, err := newJTI()
		if err != nil {
			return "", err
		}
		g.ID = id
	}
	now := deps.now().UTC()
	g.CreatedAt, g.UpdatedAt = now, now
	if err := deps.Grants.Save(ctx, &g); err != nil {
		if derived && errors.Is(err, store.ErrAlreadyExists) {
			return g.ID, nil
		}
		return "", fmt.Errorf("tokenendpoint: save grant: %w", err)
	}
	return g.ID, nil
}

// discardGrant deletes a grant [newGrantID] recorded for a redemption that
// issued nothing. A fault is dropped: the record then names credentials
// that were never handed out, which revocation treats like any other.
func discardGrant(ctx context.Context, deps Deps, grantID string) {
	if grantID == "" || deps.Grants == nil {
		return
	}
	_ = deps.Grants.Delete(ctx, grantID)
}
