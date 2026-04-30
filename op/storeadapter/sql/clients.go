package oidcsql

import (
	"context"
	databasesql "database/sql"
	"encoding/json"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

type clientStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newClientStore(s *Store, tx *databasesql.Tx) *clientStore {
	return &clientStore{parent: s, tx: tx}
}

func (s *clientStore) runner() runner { return pickRunner(s.parent, s.tx) }

// clientColumns is the canonical column ordering used by INSERT and
// SELECT. Declared once so the two paths can never drift; the column
// names themselves are static (not derived from any caller input) and
// are baked into the prebuilt query templates by [buildQueries].
//
//nolint:gochecknoglobals // immutable column manifest.
var clientColumns = []string{
	"id",
	"redirect_uris",
	"post_logout_redirect_uris",
	"backchannel_logout_uri",
	"backchannel_logout_session_required",
	"grant_types",
	"response_types",
	"scopes",
	"token_endpoint_auth_method",
	"secret_hash",
	"public_client",
	"source",
	"application_type",
	"subject_type",
	"id_token_signed_response_alg",
	"introspection_signed_response_alg",
	"sector_identifier_uri",
	"client_name",
	"client_uri",
	"logo_uri",
	"policy_uri",
	"tos_uri",
	"jwks_uri",
	"jwks",
	"contacts",
	"default_max_age",
	"require_auth_time",
	"default_acr_values",
	"initiate_login_uri",
	"request_uris",
	"request_object_signing_alg",
}

// clientArgs returns the bind arguments for an INSERT/UPDATE in the
// order declared by clientColumns.
func clientArgs(c *store.Client) []any {
	var jwks any
	if len(c.JWKs) > 0 {
		jwks = []byte(c.JWKs)
	}
	var defaultMaxAge any
	if c.DefaultMaxAge != nil {
		defaultMaxAge = *c.DefaultMaxAge
	}
	return []any{
		c.ID,
		encodeStrings(c.RedirectURIs),
		encodeStrings(c.PostLogoutRedirectURIs),
		c.BackchannelLogoutURI,
		boolToInt64(c.BackchannelLogoutSessionRequired),
		encodeStrings(c.GrantTypes),
		encodeStrings(c.ResponseTypes),
		encodeStrings(c.Scopes),
		c.TokenEndpointAuthMethod,
		c.SecretHash,
		boolToInt64(c.PublicClient),
		string(c.Source),
		c.ApplicationType,
		c.SubjectType,
		c.IDTokenSignedResponseAlg,
		c.IntrospectionSignedResponseAlg,
		c.SectorIdentifierURI,
		c.ClientName,
		c.ClientURI,
		c.LogoURI,
		c.PolicyURI,
		c.TosURI,
		c.JWKsURI,
		jwks,
		encodeStrings(c.Contacts),
		defaultMaxAge,
		boolToInt64(c.RequireAuthTime),
		encodeStrings(c.DefaultACRValues),
		c.InitiateLoginURI,
		encodeStrings(c.RequestURIs),
		c.RequestObjectSigningAlg,
	}
}

// scanClient consumes a *Row or *Rows in the column order declared
// by clientColumns and reconstructs a [store.Client].
func scanClient(scan func(...any) error) (*store.Client, error) {
	var (
		c                                                                                              store.Client
		redirectURIs, postLogout, grantTypes, responseTypes, scopes, contacts, defaultACR, requestURIs []byte
		jwks                                                                                           []byte
		sessionRequired, publicClient, requireAuthTime                                                 int64
		defaultMaxAge                                                                                  databasesql.NullInt64
		source                                                                                         string
	)
	err := scan(
		&c.ID,
		&redirectURIs,
		&postLogout,
		&c.BackchannelLogoutURI,
		&sessionRequired,
		&grantTypes,
		&responseTypes,
		&scopes,
		&c.TokenEndpointAuthMethod,
		&c.SecretHash,
		&publicClient,
		&source,
		&c.ApplicationType,
		&c.SubjectType,
		&c.IDTokenSignedResponseAlg,
		&c.IntrospectionSignedResponseAlg,
		&c.SectorIdentifierURI,
		&c.ClientName,
		&c.ClientURI,
		&c.LogoURI,
		&c.PolicyURI,
		&c.TosURI,
		&c.JWKsURI,
		&jwks,
		&contacts,
		&defaultMaxAge,
		&requireAuthTime,
		&defaultACR,
		&c.InitiateLoginURI,
		&requestURIs,
		&c.RequestObjectSigningAlg,
	)
	if err != nil {
		return nil, err
	}
	c.BackchannelLogoutSessionRequired = int64ToBool(sessionRequired)
	c.PublicClient = int64ToBool(publicClient)
	c.RequireAuthTime = int64ToBool(requireAuthTime)
	c.Source = store.ClientSource(source)
	if defaultMaxAge.Valid {
		v := defaultMaxAge.Int64
		c.DefaultMaxAge = &v
	}
	if len(jwks) > 0 {
		c.JWKs = json.RawMessage(append([]byte(nil), jwks...))
	}
	if c.RedirectURIs, err = decodeStrings(redirectURIs); err != nil {
		return nil, err
	}
	if c.PostLogoutRedirectURIs, err = decodeStrings(postLogout); err != nil {
		return nil, err
	}
	if c.GrantTypes, err = decodeStrings(grantTypes); err != nil {
		return nil, err
	}
	if c.ResponseTypes, err = decodeStrings(responseTypes); err != nil {
		return nil, err
	}
	if c.Scopes, err = decodeStrings(scopes); err != nil {
		return nil, err
	}
	if c.Contacts, err = decodeStrings(contacts); err != nil {
		return nil, err
	}
	if c.DefaultACRValues, err = decodeStrings(defaultACR); err != nil {
		return nil, err
	}
	if c.RequestURIs, err = decodeStrings(requestURIs); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *clientStore) GetClient(ctx context.Context, id string) (*store.Client, error) {
	row := s.runner().QueryRowContext(ctx, s.parent.queries.clientGet, id)
	c, err := scanClient(row.Scan)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, wrapErr("clients.GetClient", err)
	}
	return c, nil
}

func (s *clientStore) Register(ctx context.Context, c *store.Client) error {
	_, err := s.runner().ExecContext(ctx, s.parent.queries.clientInsert, clientArgs(c)...)
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyExists
		}
		return wrapErr("clients.Register", err)
	}
	return nil
}

func (s *clientStore) Update(ctx context.Context, c *store.Client) error {
	args := clientArgs(c)
	// Drop the leading id arg (already in clientArgs[0]) and append
	// it as the trailing WHERE bind. clientColumns[0] == "id".
	// args[1:] is a fresh subslice the caller does not retain, so the
	// in-place append is safe.
	bind := append(args[1:], c.ID) //nolint:gocritic // see comment.
	res, err := s.runner().ExecContext(ctx, s.parent.queries.clientUpdate, bind...)
	if err != nil {
		return wrapErr("clients.Update", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("clients.Update.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *clientStore) Delete(ctx context.Context, id string) error {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.clientDelete, id)
	if err != nil {
		return wrapErr("clients.Delete", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return wrapErr("clients.Delete.RowsAffected", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}
