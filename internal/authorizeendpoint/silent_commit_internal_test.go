package authorizeendpoint

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

type lostCommitAckStore struct{ store.Transactional }

func (s lostCommitAckStore) BeginTx(ctx context.Context) (store.Tx, error) {
	tx, err := s.Transactional.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return lostCommitAckTx{Tx: tx}, nil
}

type lostCommitAckTx struct{ store.Tx }

func (tx lostCommitAckTx) Commit() error {
	if err := tx.Tx.Commit(); err != nil {
		return err
	}
	return errors.New("injected lost commit acknowledgement")
}

type fixedAuthorizeClock time.Time

func (c fixedAuthorizeClock) Now() time.Time { return time.Time(c) }

func TestMintAndRedirect_LostCommitAckRecoversCommittedCodeAndPAR(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	clock := fixedAuthorizeClock(now)
	backing := inmem.New(inmem.WithClock(clock))
	grant := &store.Grant{
		ID:        "grant-silent",
		Subject:   "user-1",
		ClientID:  "client-1",
		Scope:     []string{"openid"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := backing.Grants().Save(context.Background(), grant); err != nil {
		t.Fatalf("Save grant: %v", err)
	}
	const requestURI = "urn:ietf:params:oauth:request_uri:lost-ack"
	if err := backing.PushedAuthRequests().Save(context.Background(), &store.PushedAuthRequest{
		URI:       requestURI,
		ClientID:  "client-1",
		RawParams: []byte("client_id=client-1"),
		ExpiresAt: now.Add(time.Minute),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("Save PAR: %v", err)
	}
	req := &authorize.Request{
		ClientID:            "client-1",
		ResponseType:        "code",
		RedirectURI:         "https://rp.example.com/cb",
		State:               "state-1",
		Scope:               []string{"openid"},
		PARRequestURI:       requestURI,
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
	}
	client := &store.Client{ID: "client-1"}
	active := &sessions.Active{Session: &store.Session{
		ID:             "session-1",
		Subject:        "user-1",
		ChooserGroupID: "group-1",
	}}
	deps := resolved{Deps: Deps{
		Codes:        backing.AuthorizationCodes(),
		Grants:       backing.Grants(),
		PARs:         backing.PushedAuthRequests(),
		Transactions: lostCommitAckStore{Transactional: backing},
		Clock:        clock,
		AuthCodeTTL:  time.Minute,
		Issuer:       "https://op.example.com",
	}}
	httpReq := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://op.example.com/authorize",
		http.NoBody,
	)
	recorder := httptest.NewRecorder()
	mintAndRedirect(
		recorder,
		httpReq,
		deps,
		req,
		client,
		active,
		authorizeHint{decision: decisionMint, grant: grant},
	)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	codeID := location.Query().Get("code")
	if codeID == "" {
		t.Fatalf("lost-ACK recovery did not return code: %q", location.String())
	}
	code, err := backing.AuthorizationCodes().Find(context.Background(), codeID)
	if err != nil {
		t.Fatalf("Find recovered code: %v", err)
	}
	if code.GrantID != grant.ID {
		t.Fatalf("code GrantID=%q want %q", code.GrantID, grant.ID)
	}
	if _, err := backing.PushedAuthRequests().Consume(
		context.Background(),
		requestURI,
	); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("PAR after recovered commit: want ErrAlreadyConsumed, got %v", err)
	}
}
