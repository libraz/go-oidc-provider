package oidcdynamo

import (
	"context"
	"errors"

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

// assertTxOpen refuses a call made through a handle whose transaction
// has already settled.
//
// The lookups below resolve their candidates through the parent store: a
// secondary index cannot see staged writes, so the enumeration is not
// routed through the buffer and the buffer's own guard never runs for
// it. Their per-candidate re-reads are guarded, which means a settled
// handle can no longer produce a grant — but without this it would still
// answer "none" with a nil error, and a caller cannot tell that from a
// subject who has granted nothing. Keeping the two distinguishable after
// the handle settles is what [store.Tx] asks for; the alternative is a
// leaked handle that reads as an empty account.
func (s *grantStore) assertTxOpen() error {
	return s.tx.assertOpen()
}

// FindBySubjectClient resolves the grant a (subject, client) pair
// holds. The composite attribute exists so this is one index lookup
// rather than a subject-wide enumeration filtered in memory.
//
// A backend that retains superseded grants can hold several rows for the
// pair, and the newest is the one the consent gate has to see:
// [store.GrantStore.FindBySubjectClient] requires it, and returning any
// other means a repeat authorization skips the prompt on a narrower
// grant, or amends a superseded record instead of the live one. An index
// scan has no order to rely on, so the newest is chosen here rather than
// taken from whichever item the pages happened to yield first.
func (s *grantStore) FindBySubjectClient(ctx context.Context, subject, clientID string) (*store.Grant, error) {
	if err := s.assertTxOpen(); err != nil {
		return nil, err
	}
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.grants, indexByClient, attrSubjectClient, subjectClientKey(subject, clientID),
	)
	if err != nil {
		return nil, wrapErr("grants.FindBySubjectClient", err)
	}
	var newest *store.Grant
	for _, match := range matches {
		g, ok, err := s.resolveIndexMatch(ctx, match, subject, clientID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if newest == nil || g.UpdatedAt.After(newest.UpdatedAt) {
			newest = g
		}
	}
	if newest == nil {
		return nil, store.ErrNotFound
	}
	return newest, nil
}

// resolveIndexMatch re-reads one index hit by primary key and reports
// whether it really belongs to the pair. The index is eventually
// consistent, so a hit may name a row that has since moved or gone, and
// a consent decision must be made against the item itself.
func (s *grantStore) resolveIndexMatch(
	ctx context.Context,
	match item,
	subject, clientID string,
) (*store.Grant, bool, error) {
	id := readS(match, attrPK)
	if id == "" {
		return nil, false, nil
	}
	g, err := s.Find(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if g.Subject != subject || g.ClientID != clientID {
		return nil, false, nil
	}
	return g, true, nil
}

func (s *grantStore) ListBySubject(ctx context.Context, subject string) ([]*store.Grant, error) {
	if err := s.assertTxOpen(); err != nil {
		return nil, err
	}
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.grants, indexBySubjectClient, attrSubject, subject,
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

// RevokeByClient implements [store.RevokeByClient]. The dynamic
// registration cascade calls it after a client is deleted.
//
// A grant is the record of a consent given to one client, and it carries
// no revoked flag, so the cascade removes the row outright — the same
// shape the in-memory and SQL adapters take, and what "subsequent
// lookups treat the records as absent" means for this substore. Without
// it the rows would outlive the client indefinitely: the grants table is
// the one table with no TTL.
//
// The enumeration reads by_client_subject rather than by_client. The
// latter is keyed on the composite (subject, client) attribute that
// serves [grantStore.FindBySubjectClient] and cannot be queried on the
// client alone. Each candidate is re-read by primary key before it is
// removed, because the index is eventually consistent and a stale match
// would otherwise delete a row that no longer belongs to this client.
func (s *grantStore) RevokeByClient(ctx context.Context, clientID string) error {
	if err := s.assertTxOpen(); err != nil {
		return err
	}
	if clientID == "" {
		return nil
	}
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.grants, indexByClientSubject, attrClientID, clientID,
	)
	if err != nil {
		return wrapErr("grants.RevokeByClient", err)
	}
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
			return err
		}
		if g.ClientID != clientID {
			continue
		}
		if err := s.Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
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
	if err := s.assertTxOpen(); err != nil {
		return false, err
	}
	found, err := s.parent.scanAll(ctx, s.parent.names.grants, 1)
	if err != nil {
		return false, wrapErr("grants.HasAny", err)
	}
	return len(found) > 0, nil
}

// ListClientIDsBySubject implements [store.GrantClientLister]. The
// by_subject_client GSI orders a subject's grants by client id, so each
// request asks DynamoDB for at most limit+1 rows and the cursor — the last
// client id returned — becomes a sort-key bound the service applies rather
// than a filter applied after the fact. A subject that has accumulated
// years of client registrations therefore costs one bounded query per page
// instead of a full enumeration, which is the resource bound the method
// exists for. Repeat grants for one client are adjacent in that order and
// collapse after the strongly-consistent re-read; when a page is filled
// from several index pages, each individual query stays bounded.
//
//nolint:gocognit,cyclop // Stable cursor paging needs its bounded query, live re-read, and deduplication decisions in one ordered loop.
func (s *grantStore) ListClientIDsBySubject(
	ctx context.Context,
	subject, cursor string,
	limit int,
) (store.GrantClientPage, error) {
	if err := s.assertTxOpen(); err != nil {
		return store.GrantClientPage{}, err
	}
	if limit <= 0 {
		return store.GrantClientPage{}, errors.New("oidcdynamo: grant client page limit must be positive")
	}
	seen := make(map[string]struct{}, limit+1)
	ids := make([]string, 0, limit+1)
	var start map[string]types.AttributeValue
	for len(ids) <= limit {
		in := &dynamodb.QueryInput{
			TableName:              aws.String(s.parent.names.grants),
			IndexName:              aws.String(indexBySubjectClient),
			KeyConditionExpression: aws.String("#subject = :subject"),
			ExpressionAttributeNames: map[string]string{
				"#subject": attrSubject,
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":subject": avS(subject),
			},
			ExclusiveStartKey: start,
			Limit:             aws.Int32(int32(limit + 1)), //nolint:gosec // limit is bounded by the caller's int and DynamoDB accepts int32 pages.
		}
		if cursor != "" {
			in.KeyConditionExpression = aws.String("#subject = :subject AND #client > :cursor")
			in.ExpressionAttributeNames["#client"] = attrClientID
			in.ExpressionAttributeValues[":cursor"] = avS(cursor)
		}
		page, err := s.parent.api.Query(ctx, in)
		if err != nil {
			return store.GrantClientPage{}, wrapErr("grants.ListClientIDsBySubject", err)
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
				return store.GrantClientPage{}, err
			}
			if g.Subject != subject || g.ClientID == "" || g.ClientID <= cursor {
				continue
			}
			if _, duplicate := seen[g.ClientID]; duplicate {
				continue
			}
			seen[g.ClientID] = struct{}{}
			ids = append(ids, g.ClientID)
			if len(ids) > limit {
				break
			}
		}
		if len(ids) > limit || len(page.LastEvaluatedKey) == 0 {
			break
		}
		start = page.LastEvaluatedKey
	}

	result := store.GrantClientPage{}
	if len(ids) > limit {
		result.ClientIDs = ids[:limit]
		result.NextCursor = result.ClientIDs[limit-1]
		return result, nil
	}
	result.ClientIDs = ids
	return result, nil
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
	if err := s.assertTxOpen(); err != nil {
		return store.GrantSubjectPage{}, err
	}
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
	// The client id is the sort key of by_subject_client, and DynamoDB
	// does not index an item whose key attribute is absent. A grant with
	// no client would be readable by id and invisible to every
	// subject-wide enumeration, so it is refused at the write instead.
	if g.ClientID == "" {
		return nil, errors.New("oidcdynamo: grant missing ClientID")
	}
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
	_ store.RevokeByClient     = (*grantStore)(nil)
)
