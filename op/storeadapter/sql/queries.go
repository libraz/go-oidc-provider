package oidcsql

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// queries is the package-internal SQL template registry. Every string
// here is built ONCE at [Store] construction time by [buildQueries] and
// then read-only for the lifetime of the Store. Substores reach the
// templates through `s.parent.queries.X`; they never assemble SQL
// themselves.
//
// This file is the only file in the package that interpolates table
// names into SQL strings. The discipline is enforced by:
//   - encapsulation (the [nameMap] type and the queries struct are
//     unexported, so no external code can construct or mutate them);
//   - validation (every [nameMap] field is re-validated on entry to
//     [buildQueries], independent of the [WithNaming] gate);
//   - audit (every produced query string is scanned for SQL-injection
//     metacharacters before [buildQueries] returns);
//   - a static AST test (TestQueriesAreSoleSQLBuilder) that asserts no
//     other .go file in the package concatenates a [nameMap] field into
//     a string.
type queries struct {
	// clients
	clientGet    string
	clientInsert string
	clientUpdate string
	clientDelete string

	// authorization codes
	authCodeSave    string
	authCodeFind    string
	authCodeConsume string

	// refresh tokens
	refreshSave                string
	refreshFind                string
	refreshConsume             string
	refreshRevokeChainUpdate   string
	refreshRevokeChainChildren string
	refreshRevokeByGrant       string
	refreshRevokeByClient      string
	grantDeleteByClient        string

	// access tokens
	accessTokenRegister      string
	accessTokenFind          string
	accessTokenRevokeByJTI   string
	accessTokenRevokeByGrant string
	accessTokenGC            string

	// opaque access tokens
	opaqueAccessTokenSave          string
	opaqueAccessTokenFind          string
	opaqueAccessTokenRevokeByID    string
	opaqueAccessTokenRevokeByGrant string
	opaqueAccessTokenGC            string

	// grant revocation (ADR 0025)
	grantTombstoneUpsert string
	grantTombstoneFind   string
	grantTombstoneGC     string
	revokedJTIInsert     string
	revokedJTIFind       string
	revokedJTIGC         string

	// grants
	grantSave                string
	grantFind                string
	grantFindBySubjectClient string
	grantListBySubject       string
	grantDelete              string
	grantHasAny              string

	// sessions
	sessionSave               string
	sessionFind               string
	sessionTouch              string
	sessionDelete             string
	sessionListByChooserGroup string

	// pushed authorization requests
	parSave    string
	parFind    string
	parConsume string

	// interactions
	interactionSave   string
	interactionFind   string
	interactionDelete string

	// consumed JTIs
	jtiMark string
	jtiHas  string
	jtiGC   string

	// users
	userFindBySubject    string
	userFindByUsername   string
	userReadPasswordHash string
	userPut              string
	userPutWithPassword  string

	// initial access tokens
	iatPut                 string
	iatGetByHash           string
	iatIncrementUsesRead   string
	iatIncrementUsesUpdate string
	iatDelete              string

	// registration access tokens
	ratPut           string
	ratGetByClientID string
	ratDelete        string

	// op metadata
	metadataGet string
	metadataSet string

	// device codes (RFC 8628)
	deviceCodeSave            string
	deviceCodeFind            string
	deviceCodeFindByUserCode  string
	deviceCodeApprove         string
	deviceCodeDeny            string
	deviceCodeRecordPoll      string
	deviceCodeConsume         string
	deviceCodeStrikeIncrement string
	deviceCodeStrikeRead      string
	deviceCodeViolationIncr   string
	deviceCodeViolationRead   string

	// CIBA requests (OpenID Connect CIBA Core 1.0)
	cibaSave          string
	cibaFind          string
	cibaApprove       string
	cibaDeny          string
	cibaRecordPoll    string
	cibaConsume       string
	cibaViolationIncr string
	cibaViolationRead string
}

// buildQueries assembles every SQL template the adapter needs for the
// supplied dialect and validated table-name map. The function fails
// closed: any value in n that does not satisfy [validateIdentifier]
// causes a non-nil error and an empty queries result.
//
// This is the single ingress for SQL string concatenation in the
// package. Reviewers can audit the entire SQL surface by reading this
// function alone.
func buildQueries(d Dialect, n nameMap) (queries, error) {
	// Layer 4: re-validate every name even though [applyOverrides]
	// already validated. The defence-in-depth catches a future code
	// path that constructs a [nameMap] without going through the
	// public [WithNaming] gate.
	if err := n.validateAll(); err != nil {
		return queries{}, fmt.Errorf("oidcsql: build queries: %w", err)
	}

	clientCols := joinColumns(clientColumns)
	clientPlaceholders := placeholders(len(clientColumns))
	clientUpdateSets := updateSetList(clientColumns, "id")

	const deviceCodeCols = "id, client_id, user_code, subject, scope, resource, dpop_jkt, mtls_cert_thumbprint, poll_interval, status, auth_time, deny_reason, user_code_strikes, poll_violations, last_polled_at, expires_at, issued_at"
	// notExpiredGuard tails every device-code and CIBA state-transition
	// query so an expired-but-not-yet-collected row behaves identically
	// to a missing one (ErrNotFound), matching the strict-less-than
	// expiry semantic the inmem reference and contract harness pin. A
	// zero expires_at opts out of expiry.
	const notExpiredGuard = " AND (expires_at = 0 OR expires_at >= ?)"
	const cibaCols = "id, client_id, subject, scope, resource, acr_values, binding_message, user_code, dpop_jkt, mtls_cert_thumbprint, poll_interval, status, auth_time, deny_reason, poll_violations, last_polled_at, expires_at, issued_at"

	q := queries{
		// clients
		clientGet: d.rebind(
			"SELECT " + clientCols + " FROM " + n.clients + " WHERE id = ?"),
		clientInsert: d.rebind(
			"INSERT INTO " + n.clients + " (" + clientCols + ") VALUES (" + clientPlaceholders + ")"),
		clientUpdate: d.rebind(
			"UPDATE " + n.clients + " SET " + clientUpdateSets + " WHERE id = ?"),
		clientDelete: d.rebind(
			"DELETE FROM " + n.clients + " WHERE id = ?"),

		// authorization codes
		authCodeSave: d.rebind(
			"INSERT INTO " + n.authCodes +
				" (id, client_id, grant_id, subject, redirect_uri, scope, resource, code_challenge, code_challenge_method, nonce, state, dpop_jkt, expires_at, consumed_at, created_at)" +
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
		authCodeFind: d.rebind(
			"SELECT id, client_id, grant_id, subject, redirect_uri, scope, resource, code_challenge, code_challenge_method, nonce, state, dpop_jkt, expires_at, consumed_at, created_at" +
				" FROM " + n.authCodes + " WHERE id = ?"),
		authCodeConsume: d.rebind(
			"UPDATE " + n.authCodes + " SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL"),

		// refresh tokens
		refreshSave: d.rebind(
			"INSERT INTO " + n.refreshes +
				" (id, client_id, grant_id, parent_id, subject, scope, resource, dpop_jkt, mtls_cert_thumbprint, nonce, revoked, expires_at, consumed_at, created_at)" +
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
		refreshFind: d.rebind(
			"SELECT id, client_id, subject, grant_id, scope, resource, parent_id, consumed_at, expires_at, created_at, dpop_jkt, mtls_cert_thumbprint, nonce, revoked" +
				" FROM " + n.refreshes + " WHERE id = ?"),
		refreshConsume: d.rebind(
			"UPDATE " + n.refreshes + " SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL"),
		refreshRevokeChainUpdate: d.rebind(
			"UPDATE " + n.refreshes + " SET consumed_at = COALESCE(consumed_at, ?), revoked = 1 WHERE id = ?"),
		refreshRevokeChainChildren: d.rebind(
			"SELECT id FROM " + n.refreshes + " WHERE parent_id = ?"),
		refreshRevokeByGrant: d.rebind(
			"UPDATE " + n.refreshes + " SET consumed_at = COALESCE(consumed_at, ?), revoked = 1 WHERE grant_id = ?"),
		refreshRevokeByClient: d.rebind(
			"UPDATE " + n.refreshes + " SET consumed_at = COALESCE(consumed_at, ?), revoked = 1 WHERE client_id = ?"),
		grantDeleteByClient: d.rebind(
			"DELETE FROM " + n.grants + " WHERE client_id = ?"),

		// access tokens
		accessTokenRegister: d.rebind(
			"INSERT INTO " + n.accessTokens +
				" (jti, grant_id, subject, client_id, scopes, issued_at, expires_at, revoked)" +
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
		accessTokenFind: d.rebind(
			"SELECT jti, grant_id, subject, client_id, scopes, issued_at, expires_at, revoked" +
				" FROM " + n.accessTokens + " WHERE jti = ?"),
		accessTokenRevokeByJTI: d.rebind(
			"UPDATE " + n.accessTokens + " SET revoked = 1 WHERE jti = ?"),
		accessTokenRevokeByGrant: d.rebind(
			"UPDATE " + n.accessTokens + " SET revoked = 1 WHERE grant_id = ? AND revoked = 0"),
		accessTokenGC: d.rebind(
			"DELETE FROM " + n.accessTokens + " WHERE expires_at < ?"),

		// opaque access tokens (ADR 0024). The PK is the SHA-256 digest
		// of the raw bearer ID; callers hash before binding so the raw
		// secret never touches the wire to the database.
		opaqueAccessTokenSave: d.rebind(
			"INSERT INTO " + n.opaqueAccessTokens +
				" (token_hash, grant_id, subject, client_id, audience, scope, acr, amr, auth_time, dpop_jkt, mtls_cert_thumb, issued_at, expires_at, revoked)" +
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
		opaqueAccessTokenFind: d.rebind(
			"SELECT token_hash, grant_id, subject, client_id, audience, scope, acr, amr, auth_time, dpop_jkt, mtls_cert_thumb, issued_at, expires_at, revoked" +
				" FROM " + n.opaqueAccessTokens + " WHERE token_hash = ?"),
		opaqueAccessTokenRevokeByID: d.rebind(
			"UPDATE " + n.opaqueAccessTokens + " SET revoked = 1 WHERE token_hash = ?"),
		opaqueAccessTokenRevokeByGrant: d.rebind(
			"UPDATE " + n.opaqueAccessTokens + " SET revoked = 1 WHERE grant_id = ? AND revoked = 0"),
		opaqueAccessTokenGC: d.rebind(
			"DELETE FROM " + n.opaqueAccessTokens + " WHERE expires_at < ?"),

		// grant revocation (ADR 0025). Two physical tables share one
		// substore: oidc_grant_revocations holds per-grant tombstones,
		// oidc_revoked_jtis holds the per-JTI denylist for RFC 7009
		// single-AT revocation. RevokeGrant is idempotent — a second
		// call against the same grant_id extends expires_at to
		// max(existing, supplied) and leaves revoked_at unchanged so
		// the verifier's iat <= revoked_at rule keeps its meaning
		// across retries. RevokeJTI is idempotent in the simpler shape
		// (a second insert is a no-op).
		grantTombstoneUpsert: d.rebind(
			"INSERT INTO " + n.grantTombstones +
				" (grant_id, revoked_at, expires_at, reason)" +
				" VALUES (?, ?, ?, ?)" + d.upsertAlias() +
				d.upsertOnConflict("grant_id",
					"revoked_at="+d.greatestExpr(d.excludedRef("revoked_at"), "revoked_at")+
						", expires_at="+d.greatestExpr(d.excludedRef("expires_at"), "expires_at"))),
		grantTombstoneFind: d.rebind(
			"SELECT revoked_at FROM " + n.grantTombstones + " WHERE grant_id = ?"),
		grantTombstoneGC: d.rebind(
			"DELETE FROM " + n.grantTombstones + " WHERE expires_at > 0 AND expires_at < ?"),
		revokedJTIInsert: d.rebind(
			"INSERT INTO " + n.revokedJTIs +
				" (jti, grant_id, expires_at)" +
				" VALUES (?, ?, ?)" + d.upsertAlias() +
				d.upsertDoNothing("jti")),
		revokedJTIFind: d.rebind(
			"SELECT expires_at FROM " + n.revokedJTIs + " WHERE jti = ?"),
		revokedJTIGC: d.rebind(
			"DELETE FROM " + n.revokedJTIs + " WHERE expires_at > 0 AND expires_at < ?"),

		// grants (upsert keyed on id)
		grantSave: d.rebind(
			"INSERT INTO " + n.grants +
				" (id, subject, client_id, scope, claims, auth_time, acr, amr, authorization_details, created_at, updated_at)" +
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" + d.upsertAlias() +
				d.upsertOnConflict("id",
					"subject="+d.excludedRef("subject")+
						", client_id="+d.excludedRef("client_id")+
						", scope="+d.excludedRef("scope")+
						", claims="+d.excludedRef("claims")+
						", auth_time="+d.excludedRef("auth_time")+
						", acr="+d.excludedRef("acr")+
						", amr="+d.excludedRef("amr")+
						", authorization_details="+d.excludedRef("authorization_details")+
						", updated_at="+d.excludedRef("updated_at"))),
		grantFind: d.rebind(
			"SELECT id, subject, client_id, scope, claims, auth_time, acr, amr, authorization_details, created_at, updated_at" +
				" FROM " + n.grants + " WHERE id = ?"),
		grantFindBySubjectClient: d.rebind(
			"SELECT id, subject, client_id, scope, claims, auth_time, acr, amr, authorization_details, created_at, updated_at" +
				" FROM " + n.grants +
				" WHERE subject = ? AND client_id = ? ORDER BY updated_at DESC LIMIT 1"),
		grantListBySubject: d.rebind(
			"SELECT id, subject, client_id, scope, claims, auth_time, acr, amr, authorization_details, created_at, updated_at" +
				" FROM " + n.grants + " WHERE subject = ?"),
		grantDelete: d.rebind(
			"DELETE FROM " + n.grants + " WHERE id = ?"),
		grantHasAny: "SELECT 1 FROM " + n.grants + " LIMIT 1",

		// sessions (upsert keyed on id)
		sessionSave: d.rebind(
			"INSERT INTO " + n.sessions +
				" (id, subject, auth_time, amr, acr, chooser_group_id, expires_at, created_at, updated_at)" +
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)" + d.upsertAlias() +
				d.upsertOnConflict("id",
					"subject="+d.excludedRef("subject")+
						", auth_time="+d.excludedRef("auth_time")+
						", amr="+d.excludedRef("amr")+
						", acr="+d.excludedRef("acr")+
						", chooser_group_id="+d.excludedRef("chooser_group_id")+
						", expires_at="+d.excludedRef("expires_at")+
						", updated_at="+d.excludedRef("updated_at"))),
		sessionFind: d.rebind(
			"SELECT id, subject, auth_time, amr, acr, chooser_group_id, expires_at, created_at, updated_at" +
				" FROM " + n.sessions + " WHERE id = ?"),
		sessionTouch: d.rebind(
			"UPDATE " + n.sessions + " SET expires_at = ?, updated_at = ? WHERE id = ?"),
		sessionDelete: d.rebind(
			"DELETE FROM " + n.sessions + " WHERE id = ?"),
		sessionListByChooserGroup: d.rebind(
			"SELECT id, subject, auth_time, amr, acr, chooser_group_id, expires_at, created_at, updated_at" +
				" FROM " + n.sessions + " WHERE chooser_group_id = ?"),

		// PAR
		parSave: d.rebind(
			"INSERT INTO " + n.pars +
				" (uri, client_id, raw_params, expires_at, consumed_at, created_at)" +
				" VALUES (?, ?, ?, ?, ?, ?)"),
		parFind: d.rebind(
			"SELECT uri, client_id, raw_params, expires_at, consumed_at, created_at" +
				" FROM " + n.pars + " WHERE uri = ?"),
		parConsume: d.rebind(
			"UPDATE " + n.pars + " SET consumed_at = ? WHERE uri = ? AND consumed_at IS NULL"),

		// interactions (upsert keyed on id)
		interactionSave: d.rebind(
			"INSERT INTO " + n.interactions +
				" (id, client_id, step, raw_state, expires_at, created_at, updated_at)" +
				" VALUES (?, ?, ?, ?, ?, ?, ?)" + d.upsertAlias() +
				d.upsertOnConflict("id",
					"client_id="+d.excludedRef("client_id")+
						", step="+d.excludedRef("step")+
						", raw_state="+d.excludedRef("raw_state")+
						", expires_at="+d.excludedRef("expires_at")+
						", updated_at="+d.excludedRef("updated_at"))),
		interactionFind: d.rebind(
			"SELECT id, client_id, step, raw_state, expires_at, created_at, updated_at" +
				" FROM " + n.interactions + " WHERE id = ?"),
		interactionDelete: d.rebind(
			"DELETE FROM " + n.interactions + " WHERE id = ?"),

		// consumed JTIs
		jtiMark: d.rebind(
			"INSERT INTO " + n.jtis + " (jti, expires_at) VALUES (?, ?)"),
		jtiHas: d.rebind(
			"SELECT expires_at FROM " + n.jtis + " WHERE jti = ?"),
		jtiGC: d.rebind(
			"DELETE FROM " + n.jtis + " WHERE expires_at < ?"),

		// users
		userFindBySubject: d.rebind(
			"SELECT subject, claims, updated_at FROM " + n.users + " WHERE subject = ?"),
		userFindByUsername: d.rebind(
			"SELECT subject, claims, updated_at FROM " + n.users + " WHERE username = ?"),
		userReadPasswordHash: d.rebind(
			"SELECT password_hash FROM " + n.users + " WHERE subject = ?"),
		userPut: d.rebind(
			"INSERT INTO " + n.users + " (subject, claims, updated_at) VALUES (?, ?, ?)" +
				d.upsertAlias() +
				d.upsertOnConflict("subject",
					"claims="+d.excludedRef("claims")+
						", updated_at="+d.excludedRef("updated_at"))),
		userPutWithPassword: d.rebind(
			"INSERT INTO " + n.users + " (subject, claims, updated_at, username, password_hash) VALUES (?, ?, ?, ?, ?)" +
				d.upsertAlias() +
				d.upsertOnConflict("subject",
					"claims="+d.excludedRef("claims")+
						", updated_at="+d.excludedRef("updated_at")+
						", username="+d.excludedRef("username")+
						", password_hash="+d.excludedRef("password_hash"))),

		// initial access tokens
		iatPut: d.rebind(
			"INSERT INTO " + n.iats +
				" (id, hashed_value, max_uses, uses, allowed_scopes, tag, expires_at, created_at)" +
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
		iatGetByHash: d.rebind(
			"SELECT id, hashed_value, max_uses, uses, allowed_scopes, tag, expires_at, created_at" +
				" FROM " + n.iats + " WHERE hashed_value = ?"),
		iatIncrementUsesRead: d.rebind(
			"SELECT max_uses, uses FROM " + n.iats + " WHERE id = ?"),
		iatIncrementUsesUpdate: d.rebind(
			"UPDATE " + n.iats + " SET uses = ? WHERE id = ? AND uses = ?"),
		iatDelete: d.rebind(
			"DELETE FROM " + n.iats + " WHERE id = ?"),

		// registration access tokens
		ratPut: d.rebind(
			"INSERT INTO " + n.rats +
				" (client_id, hashed_value, created_at) VALUES (?, ?, ?)" + d.upsertAlias() +
				d.upsertOnConflict("client_id",
					"hashed_value="+d.excludedRef("hashed_value")+
						", created_at="+d.excludedRef("created_at"))),
		ratGetByClientID: d.rebind(
			"SELECT client_id, hashed_value, created_at FROM " + n.rats + " WHERE client_id = ?"),
		ratDelete: d.rebind(
			"DELETE FROM " + n.rats + " WHERE client_id = ?"),

		// op metadata
		metadataGet: d.rebind(
			"SELECT meta_value FROM " + n.metadata + " WHERE meta_key = ?"),
		metadataSet: d.rebind(
			"INSERT INTO " + n.metadata + " (meta_key, meta_value) VALUES (?, ?)" + d.upsertAlias() +
				d.upsertOnConflict("meta_key", "meta_value="+d.excludedRef("meta_value"))),

		// device codes (RFC 8628). The id column holds the SHA-256
		// digest of the wire device_code; the substore hashes before
		// every bind so the raw bearer secret never reaches the DB.
		deviceCodeSave: d.rebind(
			"INSERT INTO " + n.deviceCodes + " (" + deviceCodeCols + ")" +
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
		deviceCodeFind: d.rebind(
			"SELECT " + deviceCodeCols + " FROM " + n.deviceCodes + " WHERE id = ?"),
		deviceCodeFindByUserCode: d.rebind(
			"SELECT " + deviceCodeCols + " FROM " + n.deviceCodes + " WHERE user_code = ?"),
		deviceCodeApprove: d.rebind(
			"UPDATE " + n.deviceCodes + " SET status = ?, subject = ?, auth_time = ?" +
				" WHERE id = ? AND status = ?" + notExpiredGuard),
		deviceCodeDeny: d.rebind(
			"UPDATE " + n.deviceCodes + " SET status = ?, deny_reason = ?" +
				" WHERE id = ? AND status = ?" + notExpiredGuard),
		deviceCodeRecordPoll: d.rebind(
			"UPDATE " + n.deviceCodes +
				" SET last_polled_at = ?, poll_interval = CASE WHEN ? > poll_interval THEN ? ELSE poll_interval END" +
				" WHERE id = ?" + notExpiredGuard),
		deviceCodeConsume: d.rebind(
			"UPDATE " + n.deviceCodes + " SET status = ? WHERE id = ? AND status = ?" + notExpiredGuard),
		deviceCodeStrikeIncrement: d.rebind(
			"UPDATE " + n.deviceCodes + " SET user_code_strikes = user_code_strikes + 1" +
				" WHERE id = ? AND user_code_strikes < 255" + notExpiredGuard),
		deviceCodeStrikeRead: d.rebind(
			"SELECT user_code_strikes FROM " + n.deviceCodes + " WHERE id = ?" + notExpiredGuard),
		deviceCodeViolationIncr: d.rebind(
			"UPDATE " + n.deviceCodes + " SET poll_violations = poll_violations + 1" +
				" WHERE id = ? AND poll_violations < 255" + notExpiredGuard),
		deviceCodeViolationRead: d.rebind(
			"SELECT poll_violations FROM " + n.deviceCodes + " WHERE id = ?" + notExpiredGuard),

		// CIBA requests (OpenID Connect CIBA Core 1.0). The id column
		// holds the SHA-256 digest of the wire auth_req_id; the substore
		// hashes before every bind so the raw bearer secret never
		// reaches the DB.
		cibaSave: d.rebind(
			"INSERT INTO " + n.cibaRequests + " (" + cibaCols + ")" +
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
		cibaFind: d.rebind(
			"SELECT " + cibaCols + " FROM " + n.cibaRequests + " WHERE id = ?"),
		cibaApprove: d.rebind(
			"UPDATE " + n.cibaRequests + " SET status = ?, subject = ?, auth_time = ?" +
				" WHERE id = ? AND status = ?" + notExpiredGuard),
		cibaDeny: d.rebind(
			"UPDATE " + n.cibaRequests + " SET status = ?, deny_reason = ?" +
				" WHERE id = ? AND status = ?" + notExpiredGuard),
		cibaRecordPoll: d.rebind(
			"UPDATE " + n.cibaRequests + " SET last_polled_at = ? WHERE id = ?" + notExpiredGuard),
		cibaConsume: d.rebind(
			"UPDATE " + n.cibaRequests + " SET status = ? WHERE id = ? AND status = ?" + notExpiredGuard),
		cibaViolationIncr: d.rebind(
			"UPDATE " + n.cibaRequests + " SET poll_violations = poll_violations + 1" +
				" WHERE id = ? AND poll_violations < 255" + notExpiredGuard),
		cibaViolationRead: d.rebind(
			"SELECT poll_violations FROM " + n.cibaRequests + " WHERE id = ?" + notExpiredGuard),
	}

	// Layer 6: scan every produced query for SQL-injection
	// metacharacters and structural surprises. The check is
	// belt-and-braces: validateAll already rejects names containing
	// any of these bytes, but a future templated literal that smuggles
	// one in would surface here at construction time rather than as a
	// production runtime bug.
	if err := auditQueries(q); err != nil {
		return queries{}, fmt.Errorf("oidcsql: query audit: %w", err)
	}
	return q, nil
}

// joinColumns renders cols as a comma-separated list. The argument is
// always a package-private static slice; column names never come from
// caller input.
func joinColumns(cols []string) string {
	return strings.Join(cols, ", ")
}

// placeholders returns "?, ?, ..., ?" with n entries. The caller-side
// rebind step rewrites the result for engines that require positional
// markers.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	out := make([]byte, 0, n*3)
	for i := range n {
		if i > 0 {
			out = append(out, ',', ' ')
		}
		out = append(out, '?')
	}
	return string(out)
}

// updateSetList renders "col1 = ?, col2 = ?, ..." for every column in
// cols except those listed in skip. The skipped columns are typically
// primary-key columns referenced in the WHERE clause.
func updateSetList(cols []string, skip ...string) string {
	skipSet := make(map[string]struct{}, len(skip))
	for _, s := range skip {
		skipSet[s] = struct{}{}
	}
	var b strings.Builder
	for _, c := range cols {
		if _, omit := skipSet[c]; omit {
			continue
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(c)
		b.WriteString(" = ?")
	}
	return b.String()
}

// auditQueries scans every string field on q for empty values and for
// SQL-injection metacharacters. It is invoked from [buildQueries] as
// Layer 6 of the defence and from tests as a regression net.
//
// The audit walks the struct via reflection so a new query field added
// later is picked up automatically.
func auditQueries(q queries) error {
	v := reflect.ValueOf(q)
	t := v.Type()
	for i := range v.NumField() {
		field := t.Field(i)
		if v.Field(i).Kind() != reflect.String {
			continue
		}
		s := v.Field(i).String()
		if s == "" {
			return fmt.Errorf("query field %s is empty", field.Name)
		}
		if err := auditQueryString(s); err != nil {
			return fmt.Errorf("query field %s: %w", field.Name, err)
		}
	}
	return nil
}

// auditQueryString rejects a built query that contains characters or
// sequences that should never appear in this adapter's SQL: the
// adapter's queries never embed string literals, comments, or
// terminating semicolons; every value is bound through a placeholder.
//
// The check is intentionally strict — if a future change introduces a
// legitimate use of one of these bytes (e.g., embedding a JSON literal
// into a SELECT), the review surfaces here before the change can ship.
func auditQueryString(s string) error {
	if strings.Contains(s, "'") {
		return errors.New("contains single quote (use bind parameters instead of string literals)")
	}
	if strings.Contains(s, "\"") {
		return errors.New("contains double quote")
	}
	if strings.Contains(s, "`") {
		return errors.New("contains backtick")
	}
	if strings.Contains(s, ";") {
		return errors.New("contains semicolon (queries must be a single statement)")
	}
	if strings.Contains(s, "--") {
		return errors.New("contains line comment")
	}
	if strings.Contains(s, "/*") || strings.Contains(s, "*/") {
		return errors.New("contains block comment")
	}
	if strings.ContainsRune(s, 0) {
		return errors.New("contains NUL byte")
	}
	return nil
}
