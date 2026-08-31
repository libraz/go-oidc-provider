package oidcdynamo

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/libraz/go-oidc-provider/op/store"
)

// sessionStore holds browser sessions. Sessions sit outside the
// transactional cluster by design: the OP tolerates session loss as a
// re-login event and never pairs a session write with a token-endpoint
// commit.
type sessionStore struct {
	parent *Store
}

func (s *sessionStore) Save(ctx context.Context, sess *store.Session) error {
	if sess == nil {
		return errors.New("oidcdynamo: nil session")
	}
	entry, err := newItem(sess.ID).doc(sess)
	if err != nil {
		return err
	}
	entry.expires(sess.ExpiresAt)
	entry.set(attrChooserGroup, sess.ChooserGroupID)
	if err := s.parent.overwrite(ctx, s.parent.names.sessions, entry); err != nil {
		return wrapErr("sessions.Save", err)
	}
	return nil
}

func (s *sessionStore) Find(ctx context.Context, id string) (*store.Session, error) {
	found, err := s.parent.getLive(ctx, s.parent.names.sessions, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, wrapErr("sessions.Find", err)
	}
	return decodeSession(found)
}

// touchAttempts bounds how often Touch re-reads and retries after
// finding the item changed under it. Each retry costs one read and one
// conditional write and rebuilds the replacement from what is stored
// now, so a handful absorbs an ordinary interleaved Save while still
// failing rather than looping under a writer that never stops.
const touchAttempts = 3

// Touch extends a live session. It refuses to resurrect an expired or
// absent one: the condition is what keeps a request that raced with
// expiry from writing the session back into existence.
//
// The record is a single JSON document, so the two fields
// [store.SessionStore.Touch] sets cannot be updated in place — the
// replacement is derived from what was read. The write is therefore
// conditioned on the stored document still being that one: without it,
// the extension would put back everything the snapshot held and undo a
// step-up's ACR or an account switch's ChooserGroupID that landed in
// between, along with the chooser-group index entry derived from it. A
// document that changed is re-read and the extension applied again, and
// a caller that keeps losing gets [store.ErrConflict] rather than a
// stale overwrite.
func (s *sessionStore) Touch(ctx context.Context, id string, expiresAt, updatedAt time.Time) error {
	for attempt := range touchAttempts {
		err := s.touchOnce(ctx, id, expiresAt, updatedAt)
		if !errors.Is(err, store.ErrConflict) || attempt == touchAttempts-1 {
			return err
		}
	}
	return store.ErrConflict
}

func (s *sessionStore) touchOnce(ctx context.Context, id string, expiresAt, updatedAt time.Time) error {
	found, err := s.parent.getLive(ctx, s.parent.names.sessions, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.ErrNotFound
		}
		return wrapErr("sessions.Touch", err)
	}
	current, err := decodeSession(found)
	if err != nil {
		return err
	}
	current.ExpiresAt = expiresAt
	current.UpdatedAt = updatedAt

	entry, err := newItem(current.ID).doc(current)
	if err != nil {
		return err
	}
	entry.expires(expiresAt)
	entry.set(attrChooserGroup, current.ChooserGroupID)

	_, err = s.parent.api.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.parent.names.sessions),
		Item:      entry,
		ConditionExpression: aws.String(
			"attribute_exists(#pk) AND (#exp = :zero OR #exp >= :now) AND #doc = :expected",
		),
		ExpressionAttributeNames: map[string]string{
			"#pk":  attrPK,
			"#exp": attrExpiresAt,
			"#doc": attrDoc,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":zero":     avN(0),
			":now":      avTime(s.parent.now()),
			":expected": found[attrDoc],
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			// Either the session went away or somebody else wrote it. The
			// read decides which, so a caller cannot mistake a lost race
			// for a session that ended.
			if _, findErr := s.Find(ctx, id); errors.Is(findErr, store.ErrNotFound) {
				return store.ErrNotFound
			} else if findErr != nil {
				return findErr
			}
			return store.ErrConflict
		}
		return wrapErr("sessions.Touch", err)
	}
	return nil
}

// Delete removes the session and reports whether what it removed was
// live. An expired item is absent on every read path, and TTL
// reclamation is asynchronous, so answering from mere presence would
// make the result depend on when DynamoDB got around to the row.
func (s *sessionStore) Delete(ctx context.Context, id string) error {
	live, err := s.parent.deleteLiveKey(ctx, s.parent.names.sessions, id)
	if err != nil {
		return wrapErr("sessions.Delete", err)
	}
	if !live {
		return store.ErrNotFound
	}
	return nil
}

// ListByChooserGroup returns every live session sharing a chooser
// group. The index read is eventually consistent, so each hit is
// re-read by primary key: the account chooser must not offer a session
// that has already been signed out.
func (s *sessionStore) ListByChooserGroup(ctx context.Context, groupID string) ([]*store.Session, error) {
	if groupID == "" {
		return nil, nil
	}
	matches, err := s.parent.queryIndex(
		ctx, s.parent.names.sessions, indexByChooserGroup, attrChooserGroup, groupID,
	)
	if err != nil {
		return nil, wrapErr("sessions.ListByChooserGroup", err)
	}
	out := make([]*store.Session, 0, len(matches))
	for _, match := range matches {
		id := readS(match, attrPK)
		if id == "" {
			continue
		}
		sess, err := s.Find(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if sess.ChooserGroupID != groupID {
			continue
		}
		out = append(out, sess)
	}
	return out, nil
}

func decodeSession(found item) (*store.Session, error) {
	var sess store.Session
	if err := unmarshalDoc(found, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

var _ store.SessionStore = (*sessionStore)(nil)
