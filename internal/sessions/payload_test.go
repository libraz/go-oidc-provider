package sessions_test

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
)

func newCookieCodec(tb testing.TB) *cookie.Codec {
	tb.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		tb.Fatalf("rand: %v", err)
	}
	c, err := cookie.NewCodec(k)
	if err != nil {
		tb.Fatalf("cookie.NewCodec: %v", err)
	}
	return c
}

func newSessionCodec(tb testing.TB) *sessions.Codec {
	tb.Helper()
	c, err := sessions.NewCodec(newCookieCodec(tb))
	if err != nil {
		tb.Fatalf("NewCodec: %v", err)
	}
	return c
}

func TestNewCodec_RejectsNilInner(t *testing.T) {
	t.Parallel()

	if _, err := sessions.NewCodec(nil); err == nil {
		t.Error("NewCodec accepted nil cookie codec")
	}
}

func TestPayload_RoundTrip(t *testing.T) {
	t.Parallel()

	c := newSessionCodec(t)
	in := sessions.Payload{
		ChooserGroupID:   "cg-abc",
		CurrentSessionID: "sid-1",
		IssuedAt:         time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC).Unix(),
	}
	value, err := c.Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := c.Decode(value)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out != in {
		t.Errorf("got %+v want %+v", out, in)
	}
}

func TestPayload_Encode_RejectsMissingFields(t *testing.T) {
	t.Parallel()

	c := newSessionCodec(t)
	cases := map[string]sessions.Payload{
		"missing_chooser": {CurrentSessionID: "s", IssuedAt: 1},
		"missing_session": {ChooserGroupID: "c", IssuedAt: 1},
		"missing_iat":     {ChooserGroupID: "c", CurrentSessionID: "s"},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := c.Encode(p); err == nil {
				t.Error("Encode accepted incomplete payload")
			}
		})
	}
}

func TestPayload_Decode_RejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()

	c := newSessionCodec(t)
	value, err := c.Encode(sessions.Payload{
		ChooserGroupID:   "cg",
		CurrentSessionID: "s",
		IssuedAt:         100,
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	bad := []byte(value)
	// Mutate a region of the cookie value beyond the nonce so the AAD
	// authentication fails.
	if len(bad) > 30 {
		bad[len(bad)-3] ^= 0x01
	}
	if _, err := c.Decode(string(bad)); !errors.Is(err, sessions.ErrCookieInvalid) {
		t.Errorf("err=%v want ErrCookieInvalid", err)
	}
}

func TestPayload_Decode_RejectsCrossAudCookie(t *testing.T) {
	t.Parallel()

	// A payload sealed with a different AAD ("interaction" cookie) must
	// not authenticate against the session codec — even when the codec
	// shares the same underlying cookie.Codec.
	inner := newCookieCodec(t)
	otherAAD, err := inner.Seal(
		[]byte(`{"cg":"a","sid":"b","iat":1}`),
		[]byte("oidc-interaction"),
	)
	if err != nil {
		t.Fatalf("Seal cross-aud: %v", err)
	}
	c, err := sessions.NewCodec(inner)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if _, err := c.Decode(otherAAD); !errors.Is(err, sessions.ErrCookieInvalid) {
		t.Errorf("err=%v want ErrCookieInvalid", err)
	}
}

func TestPayload_IssuedAtTime(t *testing.T) {
	t.Parallel()

	p := sessions.Payload{IssuedAt: 1714114800}
	got := p.IssuedAtTime()
	if got.Location() != time.UTC {
		t.Errorf("Location=%v want UTC", got.Location())
	}
	if got.Unix() != 1714114800 {
		t.Errorf("Unix()=%d", got.Unix())
	}
}
