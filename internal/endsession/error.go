package endsession

// Failure descriptions emitted on the error path. The list is closed:
// every helper that calls writeLogoutError pulls its description from
// here so the wire surface is auditable. Callers MUST NOT compose
// dynamic strings — they would expose attacker-supplied parameters
// through the static-error page.
const (
	// descMethodNotAllowed is rendered on requests that arrive with a
	// method other than GET / POST.
	descMethodNotAllowed = "method not allowed"

	// descContentTypeRequired is rendered on POST requests whose
	// Content-Type is not application/x-www-form-urlencoded.
	descContentTypeRequired = "content-type must be application/x-www-form-urlencoded"

	// descMalformedForm is rendered when ParseForm fails on a POST
	// request body (over the size cap, malformed encoding, etc.).
	descMalformedForm = "malformed form body"

	// descIDTokenInvalid is rendered when id_token_hint fails to
	// parse, carries an unknown kid, or fails signature verification.
	// The single message conflates the failure modes intentionally so
	// the response is not an oracle for the sub-cause.
	descIDTokenInvalid = "invalid id_token_hint"

	// descClientIDDisagrees is rendered when both id_token_hint and
	// client_id are supplied but the parameter does not equal the
	// token's "aud" claim.
	descClientIDDisagrees = "client_id and id_token_hint disagree"

	// descPostLogoutRequiresClient is rendered when
	// post_logout_redirect_uri is supplied but no id_token_hint or
	// client_id is present to resolve the owning client.
	descPostLogoutRequiresClient = "post_logout_redirect_uri requires a client"

	// descPostLogoutNotRegistered is rendered when
	// post_logout_redirect_uri is not in the resolved client's
	// [op/store.Client.PostLogoutRedirectURIs] allowlist.
	descPostLogoutNotRegistered = "post_logout_redirect_uri is not registered"

	// descClientNotFound is rendered when the supplied client_id does
	// not match any registered client. Conflated with
	// descIDTokenInvalid in the wire response to avoid an existence
	// oracle, but kept distinct here so log analysis can tell them
	// apart.
	descClientNotFound = "invalid client"
)
