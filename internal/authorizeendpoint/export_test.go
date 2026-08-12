package authorizeendpoint

// MaxCompletionAttempts exposes the bound the completion retry loop
// enforces so the package's black-box tests can pin the number of
// attempts to the value the implementation uses instead of restating
// the literal.
const MaxCompletionAttempts = maxCompletionAttempts
