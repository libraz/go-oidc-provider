package tokenexchange

// buildActChain assembles the act claim object the issued token will
// carry. Three modes per RFC 8693 §1.3 / §4.1:
//
//   - delegation: subject + actor distinct identities. The new act
//     entry names the actor; any prior chain on the actor's token is
//     preserved as nested act under the new entry.
//   - impersonation: actor absent but the calling client is acting
//     on behalf of the subject. The new act entry names the calling
//     client; any prior chain on the subject_token is preserved as
//     nested act.
//   - self-exchange: the calling client matches the subject_token's
//     original client. No new act entry is added; the chain is
//     preserved verbatim.
//
// The returned slice has two members:
//
//   - act:   the act value to stamp on the issued token (nil when
//     self-exchange and the original token had no chain).
//   - depth: the resulting nested-level count. Five is the maximum;
//     anything above is rejected by the caller.
func buildActChain(subjectToken TokenView, actorToken *TokenView, callingClientID string) (map[string]any, int) {
	if actorToken != nil {
		// Delegation. Outer act names the actor; nested act preserves
		// the actor token's prior chain.
		entry := map[string]any{"sub": actorToken.Subject}
		if actorToken.Act != nil {
			entry["act"] = actorToken.Act
		}
		return entry, depthOfAct(entry)
	}
	if callingClientID == subjectToken.ClientID {
		// Self-exchange: leave the chain untouched.
		return subjectToken.Act, depthOfAct(subjectToken.Act)
	}
	// Impersonation: outer act names the calling client; nested act
	// preserves the subject token's prior chain.
	entry := map[string]any{"sub": callingClientID}
	if subjectToken.Act != nil {
		entry["act"] = subjectToken.Act
	}
	return entry, depthOfAct(entry)
}

// depthOfAct walks the nested act structure and returns the number of
// levels. A nil input returns zero. The function is iterative so a
// cyclic act (which the verifier would reject as malformed JWT but
// which a hand-crafted fixture could still feed in) terminates at the
// MaxActChainDepth cap rather than recursing forever.
func depthOfAct(act map[string]any) int {
	depth := 0
	cur := act
	for cur != nil {
		depth++
		if depth > MaxActChainDepth {
			return depth
		}
		nested, ok := cur["act"].(map[string]any)
		if !ok {
			break
		}
		cur = nested
	}
	return depth
}
