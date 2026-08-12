package oidcdynamo

import (
	"context"
	"errors"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// grantStore holds the standing authorization a subject has given a
// client. Grants never expire on their own — they are revoked — so the
// table carries no TTL.
//
// The record carries a version because a grant is the one substore
// record the OP amends rather than replaces: a repeat authorization adds
// scopes, authorization details, and a fresh authentication context to
// whatever the grant already held. Every write advances the version, and
// a write staged inside a transaction asserts the version it amended is
// still the stored one, so two authorizations completing at once cannot
// end with one silently dropping the other's additions.
type grantStore struct {
	parent *Store
	tx     *txBuffer
}

func (s *grantStore) Save(ctx context.Context, g *store.Grant) error {
	if g == nil {
		return errors.New("oidcdynamo: nil grant")
	}
	entry, err := grantItem(g)
	if err != nil {
		return err
	}
	if s.tx != nil {
		return s.tx.putVersioned(ctx, s.parent.names.grants, g.ID, entry, attrRecordVersion)
	}
	if err := s.parent.putBumpingVersion(
		ctx, s.parent.names.grants, entry, attrRecordVersion,
	); err != nil {
		return wrapErr("grants.Save", err)
	}
	return nil
}

func (s *grantStore) Find(ctx context.Context, id string) (*store.Grant, error) {
	found, err := s.read(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("grants.Find", err)
	}
	return decodeGrant(found)
}

func (s *grantStore) read(ctx context.Context, pk string) (item, error) {
	if s.tx != nil {
		return s.tx.get(ctx, s.parent.names.grants, pk)
	}
	return s.parent.get(ctx, s.parent.names.grants, pk)
}

// FindBySubjectClient resolves the single grant a (subject, client)
// pair holds. The composite attribute exists so this is one index
// lookup rather than a subject-wide enumeration filtered in memory.
func (s *grantStore) FindBySubjectClient(ctx context.Context, subject, clientID string) (*store.Grant, error) {
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.grants, indexByClient, attrSubjectClient, subjectClientKey(subject, clientID),
	)
	if err != nil {
		return nil, wrapErr("grants.FindBySubjectClient", err)
	}
	for _, match := range matches {
		id := readS(match, attrPK)
		if id == "" {
			continue
		}
		// The index is eventually consistent; confirm against the item
		// itself before handing a grant to a consent decision.
		g, err := s.Find(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if g.Subject == subject && g.ClientID == clientID {
			return g, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *grantStore) ListBySubject(ctx context.Context, subject string) ([]*store.Grant, error) {
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.grants, indexBySubject, attrSubject, subject,
	)
	if err != nil {
		return nil, wrapErr("grants.ListBySubject", err)
	}
	out := make([]*store.Grant, 0, len(matches))
	for _, match := range matches {
		id := readS(match, attrPK)
		if id == "" {
			continue
		}
		g, err := s.Find(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if g.Subject != subject {
			continue
		}
		out = append(out, g)
	}
	return out, nil
}

func (s *grantStore) Delete(ctx context.Context, id string) error {
	if s.tx != nil {
		return s.tx.delete(s.parent.names.grants, id)
	}
	existed, err := s.parent.deleteKey(ctx, s.parent.names.grants, id)
	if err != nil {
		return wrapErr("grants.Delete", err)
	}
	if !existed {
		return store.ErrNotFound
	}
	return nil
}

// HasAny reports whether any grant exists at all. The OP asks this once
// at startup to decide whether a fresh deployment can adopt a subject
// mode, so a one-item scan is the right cost.
func (s *grantStore) HasAny(ctx context.Context) (bool, error) {
	found, err := s.parent.scanAll(ctx, s.parent.names.grants, 1)
	if err != nil {
		return false, wrapErr("grants.HasAny", err)
	}
	return len(found) > 0, nil
}

// ListClientIDsBySubject implements [store.GrantClientLister]. The
// cursor is the last client id returned, and the page is the next
// lexicographically-ordered run after it, so paging is stable even
// while grants are being created and revoked underneath it.
func (s *grantStore) ListClientIDsBySubject(
	ctx context.Context,
	subject, cursor string,
	limit int,
) (store.GrantClientPage, error) {
	if limit <= 0 {
		return store.GrantClientPage{}, errors.New("oidcdynamo: grant client page limit must be positive")
	}
	grants, err := s.ListBySubject(ctx, subject)
	if err != nil {
		return store.GrantClientPage{}, err
	}

	seen := make(map[string]struct{}, len(grants))
	ids := make([]string, 0, len(grants))
	for _, g := range grants {
		if g.ClientID <= cursor {
			continue
		}
		if _, duplicate := seen[g.ClientID]; duplicate {
			continue
		}
		seen[g.ClientID] = struct{}{}
		ids = append(ids, g.ClientID)
	}
	slices.Sort(ids)

	page := store.GrantClientPage{}
	if len(ids) > limit {
		page.ClientIDs = ids[:limit]
		page.NextCursor = ids[limit-1]
		return page, nil
	}
	page.ClientIDs = ids
	return page, nil
}

// ListSubjectsByClient implements [store.GrantSubjectLister]. The dedicated
// GSI orders grants by client id and subject, so each request asks DynamoDB
// for at most limit+1 rows. Duplicate grants for one subject are collapsed
// after the strongly-consistent re-read; when a page is filled from several
// GSI pages, each individual query remains bounded and the cursor remains a
// subject key rather than leaking grant IDs.
//
//nolint:gocognit,cyclop // Stable cursor paging needs its bounded query, live re-read, and deduplication decisions in one ordered loop.
func (s *grantStore) ListSubjectsByClient(
	ctx context.Context,
	clientID, cursor string,
	limit int,
) (store.GrantSubjectPage, error) {
	if limit <= 0 {
		return store.GrantSubjectPage{}, errors.New("oidcdynamo: grant subject page limit must be positive")
	}
	seen := make(map[string]struct{}, limit+1)
	subjects := make([]string, 0, limit+1)
	var start map[string]types.AttributeValue
	for len(subjects) <= limit {
		in := &dynamodb.QueryInput{
			TableName:              aws.String(s.parent.names.grants),
			IndexName:              aws.String(indexByClientSubject),
			KeyConditionExpression: aws.String("#client = :client"),
			ExpressionAttributeNames: map[string]string{
				"#client": attrClientID,
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":client": avS(clientID),
			},
			ExclusiveStartKey: start,
			Limit:             aws.Int32(int32(limit + 1)), //nolint:gosec // limit is bounded by the caller's int and DynamoDB accepts int32 pages.
		}
		if cursor != "" {
			in.KeyConditionExpression = aws.String("#client = :client AND #subject > :cursor")
			in.ExpressionAttributeNames["#subject"] = attrSubject
			in.ExpressionAttributeValues[":cursor"] = avS(cursor)
		}
		page, err := s.parent.api.Query(ctx, in)
		if err != nil {
			return store.GrantSubjectPage{}, wrapErr("grants.ListSubjectsByClient", err)
		}
		for _, match := range page.Items {
			id := readS(match, attrPK)
			if id == "" {
				continue
			}
			g, err := s.Find(ctx, id)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return store.GrantSubjectPage{}, err
			}
			if g.ClientID != clientID || g.Subject == "" || g.Subject <= cursor {
				continue
			}
			if _, duplicate := seen[g.Subject]; duplicate {
				continue
			}
			seen[g.Subject] = struct{}{}
			subjects = append(subjects, g.Subject)
			if len(subjects) > limit {
				break
			}
		}
		if len(subjects) > limit || len(page.LastEvaluatedKey) == 0 {
			break
		}
		start = page.LastEvaluatedKey
	}

	result := store.GrantSubjectPage{}
	if len(subjects) > limit {
		result.Subjects = subjects[:limit]
		result.NextCursor = result.Subjects[limit-1]
		return result, nil
	}
	result.Subjects = subjects
	return result, nil
}

func grantItem(g *store.Grant) (item, error) {
	entry, err := newItem(g.ID).doc(g)
	if err != nil {
		return nil, err
	}
	entry.set(attrSubject, g.Subject)
	entry.set(attrClientID, g.ClientID)
	entry.set(attrSubjectClient, subjectClientKey(g.Subject, g.ClientID))
	return entry, nil
}

// subjectClientKey builds the composite index value. The separator is a
// NUL byte so it cannot occur inside either component and two different
// pairs can never collide onto one key.
func subjectClientKey(subject, clientID string) string {
	if subject == "" && clientID == "" {
		return ""
	}
	return subject + "\x00" + clientID
}

func decodeGrant(found item) (*store.Grant, error) {
	var g store.Grant
	if err := unmarshalDoc(found, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

var (
	_ store.GrantStore         = (*grantStore)(nil)
	_ store.GrantClientLister  = (*grantStore)(nil)
	_ store.GrantSubjectLister = (*grantStore)(nil)
)
