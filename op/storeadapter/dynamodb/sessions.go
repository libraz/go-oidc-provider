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
	if err := s.parent.put(ctx, s.parent.names.sessions, entry); err != nil {
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

// Touch extends a live session. It refuses to resurrect an expired or
// absent one: the condition is what keeps a request that raced with
// expiry from writing the session back into existence.
func (s *sessionStore) Touch(ctx context.Context, id string, expiresAt, updatedAt time.Time) error {
	current, err := s.Find(ctx, id)
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
		TableName:           aws.String(s.parent.names.sessions),
		Item:                entry,
		ConditionExpression: aws.String("attribute_exists(#pk) AND (#exp = :zero OR #exp >= :now)"),
		ExpressionAttributeNames: map[string]string{
			"#pk":  attrPK,
			"#exp": attrExpiresAt,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":zero": avN(0),
			":now":  avTime(s.parent.now()),
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return store.ErrNotFound
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
		ctx, s.parent.names.sessions, indexByChooserGroup, attrChooserGroup, groupID)
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
