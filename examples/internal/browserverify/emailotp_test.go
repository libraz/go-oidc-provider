//go:build browserverify

package browserverify

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// mailedCodeRE matches the code a demo delivery hook prints as it
// "sends". Only a demo can be driven this way: a real [op.EmailDelivery]
// hands the code to a provider and the harness has no inbox to read, so
// an example that mails for real is a manual walkthrough by construction.
var mailedCodeRE = regexp.MustCompile(`code=([0-9]{4,10})`)

// recoveryCodeRE matches one XXXXX-XXXXX recovery code. The alphabet is
// Crockford base32 — I, L, O and U are deliberately absent, so the class
// is narrower than A-Z and a five-run of any other letters is not a code.
var recoveryCodeRE = regexp.MustCompile(`\b[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}\b`)

// codeScraper answers the one-time-code prompts of an example whose codes
// exist only in its output: the recovery sheet printed once at startup,
// and the e-mail codes written as the demo hook sends them.
type codeScraper struct {
	logPath string
	// recovery is the batch read from the startup banner, in printed
	// order; spent counts how many of them a run has already used. Both
	// outlive a retried round-trip, because a consumed recovery code
	// stays consumed and offering it again would read as a wrong code.
	recovery []string
	spent    int
	// lastTOTPWindow is the RFC 6238 counter the driver most recently
	// answered a prompt with, so a run that answers two TOTP prompts does
	// not present the same code twice.
	lastTOTPWindow int64
}

// freshTOTPCode returns a code the verifier will accept, waiting out the
// window if the driver already spent one in it.
//
// A TOTP store advances its last-accepted counter past every code it
// takes, so replaying the current window is refused — correctly, since
// that is the replay the counter exists to stop. The step-up example
// answers two TOTP prompts back to back, so whether they land in the same
// 30-second window is a matter of when the test happened to start. Sitting
// out the window makes that deterministic instead of leaving the gate to
// decide by coin flip.
func (c *codeScraper) freshTOTPCode(secret string) (string, error) {
	const step = 30
	for time.Now().Unix()/step <= c.lastTOTPWindow {
		time.Sleep(time.Second)
	}
	now := time.Now()
	code, err := totpCode(secret, now)
	if err != nil {
		return "", err
	}
	c.lastTOTPWindow = now.Unix() / step
	return code, nil
}

// mailedCode returns the most recent code in the example's log. The
// delivery hook writes it while handling the send prompt, so it is
// normally on disk before the verify prompt renders; the retry covers the
// flush lag between the two. Re-reading the last code on every call is
// what makes a re-prompt work: a rejected code triggers no new send, so
// the same code is still the live one.
func (c *codeScraper) mailedCode() (string, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(c.logPath)
		if err == nil {
			if m := mailedCodeRE.FindAllSubmatch(data, -1); len(m) > 0 {
				return string(m[len(m)-1][1]), nil
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no mailed code in %s; the delivery hook logged nothing", c.logPath)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// nextRecoveryCode hands out the next unused code from the scraped batch.
// Codes are single-use, so a run that reaches the fallback more than once
// must present a different one each time.
func (c *codeScraper) nextRecoveryCode() (string, error) {
	if c.spent >= len(c.recovery) {
		return "", fmt.Errorf("the example asked for recovery code %d but the batch holds %d", c.spent+1, len(c.recovery))
	}
	code := c.recovery[c.spent]
	c.spent++
	return code, nil
}

// scrapeRecoveryCodes reads the display-once batch out of the example's
// startup banner. The banner is printed before the OP listener comes up,
// so it is on disk by the time readiness passes; the short retry covers
// the flush lag.
func scrapeRecoveryCodes(t *testing.T, logPath string) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(logPath)
		if err == nil {
			if codes := uniqueStrings(recoveryCodeRE.FindAllString(string(data), -1)); len(codes) > 0 {
				return codes
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no recovery codes found in example log %s:\n%s", logPath, data)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// wrongOTP returns a code the verifier must reject, derived from a valid
// one by advancing every digit. Keeping the length and shape means the
// rejection comes from the comparison rather than from a format check —
// a malformed string would be refused by a step that never looked at the
// stored code at all, which is not the failure the fallback reacts to.
func wrongOTP(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for _, r := range code {
		if r >= '0' && r <= '9' {
			b.WriteRune('0' + (r-'0'+1)%10)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
