package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/remotecache"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// ErrUnavailable reports that a document could not be resolved because the
// process-wide fetch capacity was exhausted. It is local pressure, not a
// verdict on the client, so it is neither cached nor folded into
// [store.ErrNotFound].
var ErrUnavailable = errors.New("cimd: client metadata document resolution unavailable")

// Config wires the decorator. Inner and Validate are required.
type Config struct {
	// Inner is the registered-client store consulted first.
	Inner store.ClientStore

	// Validate turns a fetched document into a client record, rejecting it
	// when the document breaks the draft's or the OP's rules. An error that
	// implements ErrorCode() string supplies the audit error_code.
	Validate func(raw []byte, url string) (*store.Client, error)

	// Allow, when non-nil, is consulted with the client_id URL on every
	// resolution, cache hits included. false treats the client as unknown.
	Allow func(ctx context.Context, clientID string) bool

	// AllowPrivate admits the http scheme and private / loopback targets.
	// Dev and test only.
	AllowPrivate bool

	// Audit receives the cimd.* events. nil discards them.
	Audit audit.Emitter

	// Clock drives cache expiry and Expires-header arithmetic.
	Clock timex.Clock

	// Resources is stamped onto every resolved client as its RFC 8707
	// resource allowlist.
	Resources []string

	// PublicScopes bounds the scopes a resolved client may request.
	PublicScopes []string

	// Test seams: a shorter fetch timeout and a DNS lookup override.
	timeout    time.Duration
	lookupHook func(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Store is the [store.ClientStore] decorator [New] returns.
type Store struct {
	cfg    Config
	audit  audit.Emitter
	clock  timex.Clock
	client *securefetch.Client
	cache  *remotecache.Cache[*store.Client]
	loads  remotecache.LoadGate
}

var _ store.ClientStore = (*Store)(nil)

// New builds the decorator. Build it once per Provider: the cache and the
// singleflight it carries are only effective when every endpoint shares them.
func New(cfg Config) *Store {
	clock := timex.OrSystem(cfg.Clock)
	emitter := audit.OrDiscard(cfg.Audit)
	timeout := securefetch.DefaultTimeout
	if cfg.timeout > 0 {
		timeout = cfg.timeout
	}
	return &Store{
		cfg:    cfg,
		audit:  emitter,
		clock:  clock,
		client: securefetch.NewClient(fetchPolicy(cfg.AllowPrivate, timeout, cfg.lookupHook)),
		cache: remotecache.New[*store.Client](remotecache.Config{
			Clock:       clock,
			TTL:         maxDocumentTTL,
			NegativeTTL: remotecache.DefaultNegativeTTL,
			MaxEntries:  cacheMaxEntries,
			ShouldCacheError: func(err error) bool {
				return !errors.Is(err, remotecache.ErrOverloaded)
			},
		}),
		loads: remotecache.SharedLoadGate(remotecache.DefaultMaxInflight),
	}
}

// GetClient resolves id from the inner store, falling back to the client ID
// metadata document when id is a conforming URL the inner store does not know.
// The returned record is a copy the caller may mutate.
func (s *Store) GetClient(ctx context.Context, id string) (*store.Client, error) {
	c, err := s.cfg.Inner.GetClient(ctx, id)
	if !errors.Is(err, store.ErrNotFound) {
		return c, err
	}
	if !validClientIDURL(id, s.cfg.AllowPrivate) {
		return nil, err
	}
	if s.cfg.Allow != nil && !s.cfg.Allow(ctx, id) {
		s.audit.Emit(ctx, audit.Event{
			Name:     string(auditevent.AuditCIMDClientDenied),
			Level:    audit.LevelWarn,
			Message:  "client ID metadata document URL refused by the Allow hook",
			ClientID: id,
		})
		return nil, fmt.Errorf("%w: client_id metadata document URL not allowed", store.ErrNotFound)
	}
	client, err := s.cache.LoadTTL(ctx, id, func(ctx context.Context, _ *store.Client, _ bool) (*store.Client, time.Duration, error) {
		return s.load(ctx, id)
	})
	var failure *fetchFailure
	switch {
	case err == nil:
		return client.Clone(), nil
	case errors.Is(err, remotecache.ErrOverloaded):
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	case errors.As(err, &failure):
		return nil, fmt.Errorf("%w: %w", store.ErrNotFound, failure)
	default:
		return nil, err
	}
}

// load performs one fetch-and-validate under the shared load gate. Audit
// events fire here, once per upstream fetch, not once per cached answer.
func (s *Store) load(ctx context.Context, id string) (*store.Client, time.Duration, error) {
	release, err := s.loads.Acquire(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer release()

	body, header, reason := fetchDocument(ctx, s.client, id)
	if reason != "" {
		return nil, 0, s.fail(ctx, id, reason, "")
	}
	if !json.Valid(body) {
		return nil, 0, s.fail(ctx, id, reasonJSON, "")
	}
	client, err := s.cfg.Validate(body, id)
	if err != nil || client == nil {
		return nil, 0, s.fail(ctx, id, reasonValidation, validationCode(err))
	}
	client.Source = store.ClientSourceMetadataDocument
	client.Resources = slices.Clone(s.cfg.Resources)
	client.Scopes = s.boundScopes(client.Scopes)
	s.audit.Emit(ctx, audit.Event{
		Name:     string(auditevent.AuditCIMDFetched),
		Level:    audit.LevelInfo,
		Message:  "client ID metadata document fetched and validated",
		ClientID: id,
	})
	return client, documentTTL(header, s.clock.Now()), nil
}

// boundScopes limits the document's declared scopes to the OP's public ones;
// a document declaring none gets every public scope.
func (s *Store) boundScopes(declared []string) []string {
	if len(declared) == 0 {
		return slices.Clone(s.cfg.PublicScopes)
	}
	var out []string
	for _, scope := range declared {
		if slices.Contains(s.cfg.PublicScopes, scope) && !slices.Contains(out, scope) {
			out = append(out, scope)
		}
	}
	return out
}

// fail records a cimd.fetch_failed event and returns the loader error.
func (s *Store) fail(ctx context.Context, id, reason, code string) error {
	extras := map[string]any{"reason": reason}
	if code != "" {
		extras["error_code"] = code
	}
	s.audit.Emit(ctx, audit.Event{
		Name:     string(auditevent.AuditCIMDFetchFailed),
		Level:    audit.LevelWarn,
		Message:  "client ID metadata document could not be used",
		ClientID: id,
		Extras:   extras,
	})
	return &fetchFailure{reason: reason}
}
