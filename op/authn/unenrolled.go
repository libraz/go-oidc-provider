package authn

// UnenrolledPolicy is what a one-of step does when the subject has none
// of its factors enrolled.
type UnenrolledPolicy int

const (
	// UnenrolledDeny ends the attempt with a not-enrolled abort.
	UnenrolledDeny UnenrolledPolicy = iota

	// UnenrolledSkip passes over the step without completing it, so it
	// raises neither the level nor the amr.
	UnenrolledSkip
)
