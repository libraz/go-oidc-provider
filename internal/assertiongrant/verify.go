package assertiongrant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// maxLifetime bounds how far in the future exp may sit. The leeway is added
// on top so an assertion minted with exp = iat+5m by a peer whose clock runs
// slightly ahead is not refused.
const maxLifetime = clientauth.MaxAssertionLifetime

// maxNumericDate (9999-12-31T23:59:59Z) bounds a NumericDate before it is
// converted to an integer, so an absurd value cannot overflow.
const maxNumericDate = 253402300799

// leeway is the skew tolerance on exp / nbf / iat, shared with client
// assertions because both are minted on a peer's clock.
const leeway = clientauth.DefaultAssertionLeeway

// replayKeyPrefix keeps jwt-bearer jti markers apart from the client
// assertion namespace in the shared ConsumedJTIStore.
const replayKeyPrefix = "jwtbearer:"

// Verifier verifies jwt-bearer assertions against a fixed issuer set. It is
// safe for concurrent use.
type Verifier struct {
	issuers  map[string]Issuer
	keys     *rpjwks.Fetcher
	jtis     store.ConsumedJTIStore
	clock    timex.Clock
	opIssuer string
	tokenURL string
}

// New returns a [Verifier] for cfg.
func New(cfg Config) (*Verifier, error) {
	if cfg.KeySource == nil || cfg.JTIs == nil || cfg.OPIssuer == "" {
		return nil, errors.New("assertiongrant: KeySource, JTIs and OPIssuer are required")
	}
	if len(cfg.Issuers) == 0 {
		return nil, errors.New("assertiongrant: at least one issuer is required")
	}
	issuers := make(map[string]Issuer, len(cfg.Issuers))
	for _, iss := range cfg.Issuers {
		if iss.Issuer == "" {
			return nil, errors.New("assertiongrant: issuer must not be empty")
		}
		if _, dup := issuers[iss.Issuer]; dup {
			return nil, fmt.Errorf("assertiongrant: duplicate issuer %q", iss.Issuer)
		}
		issuers[iss.Issuer] = iss
	}
	return &Verifier{
		issuers:  issuers,
		keys:     cfg.KeySource,
		jtis:     cfg.JTIs,
		clock:    timex.OrSystem(cfg.Clock),
		opIssuer: cfg.OPIssuer,
		tokenURL: cfg.TokenEndpointURL,
	}, nil
}

// PeekIssuer returns the unverified iss of raw, so a caller can apply a
// per-issuer policy (the allowed-client list) before [Verifier.Verify]
// consumes the jti. It verifies nothing; a failure is an [*Error] with
// [ReasonParse] or [ReasonIssuer].
func PeekIssuer(raw string) (string, error) {
	jws, _, err := jose.ParseSigned(raw)
	if err != nil {
		return "", reject(ReasonParse, err)
	}
	return unverifiedIssuer(jws.UnsafePayloadWithoutVerification())
}

// Verify runs the verification stages on raw for the authenticated client.
func (v *Verifier) Verify(ctx context.Context, raw string, client ClientContext) (*Result, error) {
	// parse: compact JWS only, alg inside the project allow-list, no crit.
	jws, _, err := jose.ParseSigned(raw)
	if err != nil {
		return nil, reject(ReasonParse, err)
	}

	// issuer: read iss unverified only to pick the keys it must verify under.
	issName, err := unverifiedIssuer(jws.UnsafePayloadWithoutVerification())
	if err != nil {
		return nil, err
	}
	iss, ok := v.issuers[issName]
	if !ok {
		return nil, reject(ReasonIssuer, errors.New("issuer is not trusted"))
	}

	// typ: per profile, so no other JWT type can stand in for an assertion.
	typ, hasTyp := jws.Signatures[0].Protected.ExtraHeaders["typ"]
	if err := checkTyp(iss.Profile, typ, hasTyp); err != nil {
		return nil, reject(ReasonTyp, err)
	}

	// signature: the issuer's keys, one fresh refetch on a kid miss.
	payload, err := v.keys.ResolveForKID(ctx, iss.JWKS, iss.JWKSURI, jws)
	if err != nil {
		if rpjwks.IsKeySourceUnavailable(err) {
			return nil, fmt.Errorf("%w: %w", ErrKeySourceUnavailable, err)
		}
		return nil, reject(ReasonSignature, err)
	}

	c, err := decodeClaims(payload)
	if err != nil {
		return nil, reject(ReasonClaims, err)
	}
	now := v.clock.Now()
	if err := v.checkClaims(iss.Profile, c, now); err != nil {
		return nil, reject(ReasonClaims, err)
	}

	all, err := c.all()
	if err != nil {
		return nil, reject(ReasonClaims, err)
	}
	res := &Result{
		Subject: Subject{
			Issuer:   issName,
			Subject:  c.sub,
			ClientID: client.ID,
			Claims:   all,
		},
		Profile:   iss.Profile,
		ExpiresAt: c.exp,
	}
	if iss.Profile == ProfileIDJAG {
		scopes, resources, err := checkIDJAG(c, client)
		if err != nil {
			return nil, reject(ReasonIDJAG, err)
		}
		res.Scopes, res.Resources = scopes, resources
	}

	// replay: last, so only an otherwise-acceptable assertion is consumed.
	if err := v.markJTI(ctx, issName, c); err != nil {
		return nil, err
	}
	return res, nil
}

func reject(reason Reason, err error) *Error {
	return &Error{Reason: reason, Err: err}
}

// unverifiedIssuer reads iss from an unverified payload; it must be a
// non-empty string.
func unverifiedIssuer(payload []byte) (string, error) {
	var head struct {
		Iss json.RawMessage `json:"iss"`
	}
	if err := json.Unmarshal(payload, &head); err != nil {
		return "", reject(ReasonParse, fmt.Errorf("payload is not a JSON object: %w", err))
	}
	iss, ok := stringClaim(head.Iss)
	if !ok || iss == "" {
		return "", reject(ReasonIssuer, errors.New("iss missing or not a string"))
	}
	return iss, nil
}

// checkTyp applies the profile's typ rule: ID-JAG requires oauth-id-jag+jwt
// (with or without the application/ prefix); plain JWT admits only an absent
// typ or JWT.
func checkTyp(p Profile, typ any, present bool) error {
	s, isString := typ.(string)
	if present && !isString {
		return errors.New("typ is not a string")
	}
	switch p {
	case ProfileIDJAG:
		if s == jose.TypIDJAG || s == "application/"+jose.TypIDJAG {
			return nil
		}
		return fmt.Errorf("typ %q is not %s", s, jose.TypIDJAG)
	case ProfileJWT:
		if !present || jose.IsTypJWT(s) {
			return nil
		}
		return fmt.Errorf("typ %q is not JWT", s)
	default:
		return errors.New("unknown profile")
	}
}

// claims is the decoded payload: the raw members the stages check, from which
// the full claim map handed to the subject resolver is built once the checks
// pass.
type claims struct {
	raw map[string]json.RawMessage

	sub string
	exp time.Time
}

func decodeClaims(payload []byte) (*claims, error) {
	c := &claims{}
	if err := json.Unmarshal(payload, &c.raw); err != nil {
		return nil, fmt.Errorf("payload is not a JSON object: %w", err)
	}
	return c, nil
}

// all decodes every member into the generic claim map. Each member already
// parsed as JSON, so a decode fault is not expected; it is reported anyway.
func (c *claims) all() (map[string]any, error) {
	out := make(map[string]any, len(c.raw))
	for name, raw := range c.raw {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("claim %q: %w", name, err)
		}
		out[name] = v
	}
	return out, nil
}

// checkClaims enforces sub, aud, exp, nbf and iat.
func (v *Verifier) checkClaims(p Profile, c *claims, now time.Time) error {
	sub, ok := stringClaim(c.raw["sub"])
	if !ok || sub == "" {
		return errors.New("sub missing, empty or not a string")
	}
	c.sub = sub

	aud, err := jose.DecodeAudience(c.raw["aud"])
	if err != nil {
		return err
	}
	if !v.audienceAccepted(p, aud) {
		return errors.New("aud does not name this authorization server")
	}

	exp, err := checkExp(c.raw["exp"], now)
	if err != nil {
		return err
	}
	c.exp = exp

	if err := checkNotBefore(c.raw["nbf"], now); err != nil {
		return err
	}
	return checkIssuedAt(c.raw["iat"], p, now)
}

// checkExp validates exp and returns it.
func checkExp(raw json.RawMessage, now time.Time) (time.Time, error) {
	exp, present, err := numericDate(raw)
	if err != nil || !present {
		return time.Time{}, errors.New("exp missing or not a positive NumericDate")
	}
	if !now.Add(-leeway).Before(exp) {
		return time.Time{}, errors.New("assertion expired")
	}
	if exp.After(now.Add(maxLifetime + leeway)) {
		return time.Time{}, errors.New("exp is too far in the future")
	}
	return exp, nil
}

// checkNotBefore validates the optional nbf claim.
func checkNotBefore(raw json.RawMessage, now time.Time) error {
	nbf, present, err := numericDate(raw)
	if err != nil {
		return fmt.Errorf("nbf: %w", err)
	}
	if present && nbf.After(now.Add(leeway)) {
		return errors.New("assertion not yet valid")
	}
	return nil
}

// checkIssuedAt validates iat, which the ID-JAG profile requires.
func checkIssuedAt(raw json.RawMessage, p Profile, now time.Time) error {
	iat, present, err := numericDate(raw)
	if err != nil {
		return fmt.Errorf("iat: %w", err)
	}
	if !present && p == ProfileIDJAG {
		return errors.New("iat is required")
	}
	if present && iat.After(now.Add(leeway)) {
		return errors.New("iat is in the future")
	}
	return nil
}

// audienceAccepted applies the profile's aud rule. Plain JWT accepts the
// issuer or the token endpoint URL anywhere in the array (RFC 7523 §3);
// ID-JAG accepts only the issuer, as a string or a one-element array.
func (v *Verifier) audienceAccepted(p Profile, aud []string) bool {
	if p == ProfileIDJAG {
		return len(aud) == 1 && aud[0] == v.opIssuer
	}
	for _, a := range aud {
		if a == v.opIssuer || (v.tokenURL != "" && a == v.tokenURL) {
			return true
		}
	}
	return false
}

// checkIDJAG enforces the ID-JAG redemption rules (draft-06 §4.4.1) and
// returns the scope and resource claims.
func checkIDJAG(c *claims, client ClientContext) ([]string, []string, error) {
	clientID, ok := stringClaim(c.raw["client_id"])
	if !ok || clientID == "" || clientID != client.ID {
		return nil, nil, errors.New("client_id does not name the authenticated client")
	}
	// Multi-tenancy is not supported; ignoring the claims would break the
	// iss+tenant+sub uniqueness the draft relies on.
	for _, name := range []string{"tenant", "aud_tenant"} {
		if _, present := c.raw[name]; present {
			return nil, nil, fmt.Errorf("%s claim is not supported", name)
		}
	}

	scopes, err := checkIDJAGScope(c.raw["scope"], client)
	if err != nil {
		return nil, nil, err
	}
	resources, err := checkIDJAGResource(c.raw["resource"], client)
	if err != nil {
		return nil, nil, err
	}

	if raw, present := c.raw["cnf"]; present {
		if err := checkConfirmation(raw, client.Binding); err != nil {
			return nil, nil, err
		}
	}
	return scopes, resources, nil
}

// checkIDJAGScope parses the optional scope claim and requires it to cover
// every scope the client requested.
func checkIDJAGScope(raw json.RawMessage, client ClientContext) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	s, ok := stringClaim(raw)
	if !ok {
		return nil, errors.New("scope is not a string")
	}
	scopes := strings.Fields(s)
	for _, want := range client.RequestedScopes {
		if !slices.Contains(scopes, want) {
			return nil, fmt.Errorf("requested scope %q is not granted by the assertion", want)
		}
	}
	return scopes, nil
}

// checkIDJAGResource parses the optional resource claim and requires every
// value to be registered for the client.
func checkIDJAGResource(raw json.RawMessage, client ClientContext) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	rs, err := stringOrArray(raw)
	if err != nil {
		return nil, fmt.Errorf("resource: %w", err)
	}
	for _, r := range rs {
		if !slices.Contains(client.Resources, r) {
			return nil, fmt.Errorf("resource %q is not registered for the client", r)
		}
	}
	return rs, nil
}

// checkConfirmation requires cnf to carry exactly one method, jkt or
// x5t#S256, matching the request's binding.
func checkConfirmation(raw json.RawMessage, b Binding) error {
	var cnf map[string]json.RawMessage
	if err := json.Unmarshal(raw, &cnf); err != nil || cnf == nil {
		return errors.New("cnf is not an object")
	}
	if len(cnf) != 1 {
		return errors.New("cnf must carry exactly one confirmation method")
	}
	var method, want string
	for k := range cnf {
		method = k
	}
	switch method {
	case tokens.CnfJKT:
		want = b.DPoPJKT
	case tokens.CnfX5tS256:
		want = b.X5TS256
	default:
		return fmt.Errorf("cnf method %q is not supported", method)
	}
	got, ok := stringClaim(cnf[method])
	if !ok || got == "" {
		return fmt.Errorf("cnf.%s is not a string", method)
	}
	if want == "" || got != want {
		return fmt.Errorf("cnf.%s does not match the request binding", method)
	}
	return nil
}

// markJTI consumes the assertion's jti. A store failure other than replay is
// a server-side fault and is returned unwrapped by [*Error].
func (v *Verifier) markJTI(ctx context.Context, iss string, c *claims) error {
	jti, ok := stringClaim(c.raw["jti"])
	if !ok || jti == "" || len(jti) > jose.MaxJTILen {
		return reject(ReasonReplay, errors.New("jti missing, empty, oversized or not a string"))
	}
	key := clientauth.ReplayKey(replayKeyPrefix, iss, jti)
	if err := v.jtis.Mark(ctx, key, c.exp.Add(leeway)); err != nil {
		if errors.Is(err, store.ErrAlreadyConsumed) {
			return reject(ReasonReplay, errors.New("jti already consumed"))
		}
		return fmt.Errorf("assertiongrant: jti store: %w", err)
	}
	return nil
}

// stringClaim decodes raw as a JSON string; absent or non-string is !ok.
func stringClaim(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// stringOrArray decodes a string or an array of strings, rejecting empty
// members.
func stringOrArray(raw json.RawMessage) ([]string, error) {
	if s, ok := stringClaim(raw); ok {
		if s == "" {
			return nil, errors.New("empty value")
		}
		return []string{s}, nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, errors.New("not a string or an array of strings")
	}
	if slices.Contains(arr, "") {
		return nil, errors.New("empty member")
	}
	return arr, nil
}

// numericDate decodes an RFC 7519 NumericDate. Absent (or JSON null) is
// present=false; a non-number, zero, negative or non-finite value is an error.
func numericDate(raw json.RawMessage) (time.Time, bool, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return time.Time{}, false, nil
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil {
		return time.Time{}, true, errors.New("not a number")
	}
	if f <= 0 || math.IsInf(f, 0) || math.IsNaN(f) || f > maxNumericDate {
		return time.Time{}, true, errors.New("not a positive NumericDate")
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC(), true, nil
}
