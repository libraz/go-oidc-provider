//go:build example

// schema.go — the hand-rolled DDL plus the encoding / time / digest
// helpers the substore implementations share.
//
// CUSTOM NAMING CONVENTION
//
// Every table is prefixed "vault_" and every column uses a vocabulary
// that is deliberately unlike the OP's bundled oidc_* schema:
//
//	store concept            this schema's name
//	-----------------------  -------------------------
//	subject                  principal
//	client_id                relying_party
//	authorization code id    token_secret_digest (in vault_grant_codes)
//	refresh token id         token_secret_digest (in vault_renewal_slips)
//	refresh chain pointer    parent_secret_digest
//	PAR request_uri          handle_digest
//	scope                    requested_scope (JSON array)
//	expires_at               expires_epoch (unix seconds)
//	consumed_at              consumed_epoch (nullable unix seconds)
//	created_at               issued_epoch
//	grant id                 ledger_id
//	jti                      ticket_id
//
// The OP observes none of these names. Only the substore code in this
// module maps the rows onto the store.* structs the library consumes.
// This is the whole point of the example: nothing in go-oidc-provider
// cares what the physical schema is called.

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	databasesql "database/sql"
	"encoding/hex"
	"encoding/json"
	"time"
)

// schemaDDL is the complete hand-rolled schema. The statements are
// applied verbatim by scratchStore.Migrate at boot.
const schemaDDL = `
CREATE TABLE IF NOT EXISTS vault_relying_parties (
    relying_party     TEXT PRIMARY KEY,
    redirect_targets  TEXT NOT NULL,
    permitted_scope   TEXT NOT NULL,
    is_public         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_principals (
    principal       TEXT PRIMARY KEY,
    login_handle    TEXT NOT NULL,
    secret_phc      BLOB NOT NULL,
    display_name    TEXT,
    contact_email   TEXT,
    last_touched    INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS vault_principals_handle ON vault_principals (login_handle);

CREATE TABLE IF NOT EXISTS vault_grant_codes (
    token_secret_digest  TEXT PRIMARY KEY,
    relying_party        TEXT NOT NULL,
    principal            TEXT NOT NULL,
    ledger_id            TEXT NOT NULL,
    return_target        TEXT NOT NULL,
    requested_scope      TEXT NOT NULL,
    resource_hint        TEXT NOT NULL,
    pkce_challenge       TEXT NOT NULL,
    pkce_method          TEXT NOT NULL,
    nonce_echo           TEXT NOT NULL,
    state_echo           TEXT NOT NULL,
    dpop_thumb           TEXT NOT NULL,
    expires_epoch        INTEGER NOT NULL,
    consumed_epoch       INTEGER,
    issued_epoch         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_renewal_slips (
    token_secret_digest  TEXT PRIMARY KEY,
    relying_party        TEXT NOT NULL,
    principal            TEXT NOT NULL,
    principal_is_wire    INTEGER NOT NULL,
    ledger_id            TEXT NOT NULL,
    requested_scope      TEXT NOT NULL,
    resource_hint        TEXT NOT NULL,
    origin_kind          TEXT NOT NULL,
    auth_epoch           INTEGER NOT NULL,
    acr_value            TEXT NOT NULL,
    amr_values           TEXT NOT NULL,
    authorization_detail TEXT NOT NULL,
    access_token_extra   TEXT NOT NULL,
    -- The pointer to this token's predecessor, held as the same digest the
    -- predecessor's own row is keyed by. A chain pointer is not a bearer
    -- credential: it only ever travels between this store and the OP's
    -- replay-revocation walk, which resolves it through
    -- store.RefreshChainResolver rather than the credential lookup. Storing
    -- it hashed is therefore free, and it is what keeps every superseded
    -- generation's raw secret out of the database — a dump of this table
    -- yields no value that can be presented as a refresh token.
    parent_secret_digest TEXT,
    -- The sealed token response the OP re-emits when a client retries a
    -- rotation it never received. It lives on the successor row, keyed by
    -- the predecessor's digest, so the successor insert and the cache
    -- write are one statement — which is the condition
    -- store.RefreshRetryResponseStore attaches to exposing the interface
    -- at all. The bytes are already encrypted by the token endpoint and
    -- this store never looks inside them.
    --
    -- Living on the successor row also means the row's own expires_epoch
    -- is NOT the retention bound: the interface caps the response at the
    -- predecessor's refresh-token lifetime, which is the earlier of the
    -- two, so the read joins back to the predecessor row rather than
    -- trusting the row it reads from (see refreshRetrySelect).
    retry_sealed         BLOB,
    dpop_thumb           TEXT NOT NULL,
    mtls_thumb           TEXT NOT NULL,
    nonce_echo           TEXT NOT NULL,
    is_void              INTEGER NOT NULL,
    expires_epoch        INTEGER NOT NULL,
    consumed_epoch       INTEGER,
    issued_epoch         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_consent_ledger (
    ledger_id        TEXT PRIMARY KEY,
    principal        TEXT NOT NULL,
    relying_party    TEXT NOT NULL,
    requested_scope  TEXT NOT NULL,
    claim_consent    TEXT NOT NULL,
    auth_epoch       INTEGER NOT NULL,
    acr_class        TEXT NOT NULL,
    amr_methods      TEXT NOT NULL,
    rich_details     TEXT NOT NULL,
    issued_epoch     INTEGER NOT NULL,
    touched_epoch    INTEGER NOT NULL,
    is_revoked       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_pushed_handles (
    handle_digest    TEXT PRIMARY KEY,
    relying_party    TEXT NOT NULL,
    raw_blob         BLOB NOT NULL,
    expires_epoch    INTEGER NOT NULL,
    consumed_epoch   INTEGER,
    issued_epoch     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_browser_seats (
    seat_id          TEXT PRIMARY KEY,
    principal        TEXT NOT NULL,
    auth_epoch       INTEGER NOT NULL,
    amr_methods      TEXT NOT NULL,
    acr_class        TEXT NOT NULL,
    chooser_band     TEXT NOT NULL,
    expires_epoch    INTEGER NOT NULL,
    issued_epoch     INTEGER NOT NULL,
    touched_epoch    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_flow_scratch (
    scratch_id       TEXT PRIMARY KEY,
    relying_party    TEXT NOT NULL,
    flow_step        TEXT NOT NULL,
    driver_blob      BLOB NOT NULL,
    expires_epoch    INTEGER NOT NULL,
    issued_epoch     INTEGER NOT NULL,
    touched_epoch    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_seen_tickets (
    ticket_digest    TEXT PRIMARY KEY,
    expires_epoch    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_wire_tokens (
    ticket_id        TEXT PRIMARY KEY,
    ledger_id        TEXT NOT NULL,
    principal        TEXT NOT NULL,
    relying_party    TEXT NOT NULL,
    granted_scope    TEXT NOT NULL,
    issued_epoch     INTEGER NOT NULL,
    expires_epoch    INTEGER NOT NULL,
    is_void          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_op_notes (
    note_key    TEXT PRIMARY KEY,
    note_value  TEXT NOT NULL
);
`

// querier is the minimal surface a substore needs from the database.
// Every substore is constructed against a querier so the same code
// runs directly on the database or inside a transaction; scratchStore
// hands out db-bound substores (see dbQuerier) while scratchTx hands out
// tx-bound ones (see txQuerier).
//
// A single-row query returns a scanner rather than *sql.Row because
// *sql.Row keeps its failure in an unexported field, so a wrapper has no
// way to report one of its own through it — which is what a settled
// transaction has to do.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (databasesql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*databasesql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) scanner
}

// dbQuerier adapts *sql.DB to querier. Outside a transaction there is
// nothing to guard; the wrapper exists so a single-row query returns the
// same scanner on both paths.
type dbQuerier struct{ db *databasesql.DB }

func (q dbQuerier) ExecContext(ctx context.Context, query string, args ...any) (databasesql.Result, error) {
	return q.db.ExecContext(ctx, query, args...)
}

func (q dbQuerier) QueryContext(ctx context.Context, query string, args ...any) (*databasesql.Rows, error) {
	return q.db.QueryContext(ctx, query, args...)
}

func (q dbQuerier) QueryRowContext(ctx context.Context, query string, args ...any) scanner {
	return q.db.QueryRowContext(ctx, query, args...)
}

// digest hashes a bearer secret to the value stored on disk. SHA-256
// without a pepper matches the inmem reference; a production backend
// SHOULD HMAC with a server-side pepper.
func digest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// constantTimeMatch compares two digests in constant time relative to
// their length, so a future refactor that scans a slice instead of
// keying a map still fails closed against a timing oracle.
func constantTimeMatch(stored, presented string) bool {
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
}

// digestNullable maps a *string holding a raw bearer ID to the nullable
// bind value the schema expects: nil stays nil (NULL parent pointer),
// otherwise the digest is returned. Callers pass a RAW value here — the
// parent pointer read back out of storage is already a digest and must
// not be hashed a second time, or the chain would no longer link up.
func digestNullable(s *string) any {
	if s == nil {
		return nil
	}
	d := digest(*s)
	return d
}

func encodeStrings(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func decodeStrings(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

func encodeMap(v map[string]any) string {
	if len(v) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func decodeMap(s string) map[string]any {
	if s == "" || s == "{}" {
		return nil
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

func encodeObjectArray(v []map[string]any) string {
	if len(v) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func decodeObjectArray(s string) []map[string]any {
	if s == "" || s == "[]" {
		return nil
	}
	var out []map[string]any
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// epochOf renders a wall-clock time as unix seconds. The zero time
// maps to 0 so "no expiry" / "never consumed" stays distinguishable.
func epochOf(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeOf(epoch int64) time.Time {
	if epoch == 0 {
		return time.Time{}
	}
	return time.Unix(epoch, 0)
}

func epochPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Unix()
}

func timePtr(epoch *int64) *time.Time {
	if epoch == nil {
		return nil
	}
	t := time.Unix(*epoch, 0)
	return &t
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// expiredStrict reports whether t is strictly before now. The zero
// time means "no expiry" and is never treated as expired.
func expiredStrict(t, now time.Time) bool {
	if t.IsZero() {
		return false
	}
	return t.Before(now)
}
