package authorizeendpoint

// MaxCommitAttempts exposes the bound the shared conflict retry enforces
// so the package's black-box tests can pin the number of attempts to the
// value the implementation uses instead of restating the literal.
const MaxCommitAttempts = maxCommitAttempts

// SessionCookieRefreshInterval exposes how long a session cookie's
// browser lifetime must have run before a read-only authorization
// request re-seals it. Tests use it so the boundary they drive is the
// production one rather than a transcribed duration.
const SessionCookieRefreshInterval = sessionCookieRefreshInterval
