package metrics

import (
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/internal/auditevent"
)

// issuerLabel is the constant label every metric carries. It is the
// per-Provider distinguisher that lets two Providers share one
// registry; see [Options.Issuer].
const issuerLabel = "issuer"

// Options configures the [Collector] at construction time.
// StaticClientIDs is a bounded set the wire layer consults to gate the
// client_id label value against caller-controlled input — see the
// package doc for the cardinality rationale.
type Options struct {
	// StaticClientIDs is the set of client_id values that are safe to
	// emit as a label value. Membership is checked exactly; missing
	// entries collapse onto the empty client_id label so dynamic-DCR
	// clients cannot blow up label cardinality.
	StaticClientIDs map[string]struct{}

	// Issuer is the OP issuer URL. It is stamped on every metric as a
	// constant label so a process running more than one Provider can
	// point them all at a single registry: the descriptors differ by
	// label value rather than by name, so the metric names stay stable
	// and existing dashboards keep resolving. Cardinality is bounded by
	// the number of Providers in the process, not by request input.
	//
	// Two Providers with the same Issuer on the same registry remain a
	// collision, which is the intended reading: one issuer is one OP.
	Issuer string
}

// Collector bundles the Prometheus collectors the OP registers. The
// struct is constructed once at [op.New] and reused for the lifetime
// of the [op.Provider]; only its registration state changes after
// construction ([Collector.Unregister] / [Collector.Register]), the
// metric values themselves are never replaced.
type Collector struct {
	opts                      Options
	registry                  *prometheus.Registry
	collectors                []prometheus.Collector
	mu                        sync.Mutex
	registered                bool
	tokenIssued               *prometheus.CounterVec
	tokensRefreshed           *prometheus.CounterVec
	loginAttempts             *prometheus.CounterVec
	refreshReplay             prometheus.Counter
	codeReplay                prometheus.Counter
	clientAuthnFailures       *prometheus.CounterVec
	dcrEvents                 *prometheus.CounterVec
	deviceAuthorizationEvents *prometheus.CounterVec
	deviceCodeEvents          *prometheus.CounterVec
	cibaEvents                *prometheus.CounterVec
	tokenExchangeEvents       *prometheus.CounterVec
	customGrantEvents         *prometheus.CounterVec
	backChannelLogout         *prometheus.CounterVec
	logoutFailures            *prometheus.CounterVec
	introspectionErrors       prometheus.Counter
	tokenRevokeFailures       *prometheus.CounterVec
	dpopLooseMethodCase       prometheus.Counter
	keyRetiredKidPresented    prometheus.Counter
}

// New constructs a [Collector] and registers every metric on reg. A
// nil reg is rejected because the package contract requires the
// embedder to own the registry; re-registration of the same issuer is
// reported as the standard [prometheus.AlreadyRegisteredError] so the
// caller can decide whether to swap registries or surface the
// misconfiguration.
//
// Registration is all-or-nothing: if any collector is refused, the
// ones already accepted are unregistered before the error returns, so
// a failed call leaves reg exactly as it was found.
func New(reg *prometheus.Registry, opts Options) (*Collector, error) {
	if reg == nil {
		return nil, errors.New("metrics: registry is required")
	}
	constLabels := prometheus.Labels{issuerLabel: opts.Issuer}
	c := &Collector{opts: opts, registry: reg}
	c.tokenIssued = c.counterVec(constLabels, auditevent.MetricTokenIssued,
		"Number of refresh tokens initially issued (not rotated), partitioned by the grant that created the chain and by (static-seed) client_id.",
		"grant_type", "client_id")
	c.tokensRefreshed = c.counterVec(constLabels, auditevent.MetricTokensRefreshed,
		"Number of refresh-token rotations completed by the token endpoint, partitioned by (static-seed) client_id.",
		"client_id")
	c.loginAttempts = c.counterVec(constLabels, auditevent.MetricLoginAttempts,
		"Number of login and MFA attempts processed by the authentication flow, partitioned by result and factor.",
		"factor", "result")
	c.refreshReplay = c.counter(constLabels, auditevent.MetricRefreshReplay,
		"Number of refresh-token replay events detected by the rotation chain.")
	c.codeReplay = c.counter(constLabels, auditevent.MetricCodeReplay,
		"Number of authorization-code replay events detected at the token endpoint.")
	c.clientAuthnFailures = c.counterVec(constLabels, auditevent.MetricClientAuthnFailures,
		"Number of pre-issuance client-authentication failures, partitioned by auth_method and short reason code.",
		"auth_method", "reason")
	c.dcrEvents = c.counterVec(constLabels, auditevent.MetricDCR,
		"Dynamic Client Registration events, partitioned by the event sub-name (the audit name with the dcr. prefix stripped).",
		"event")
	c.deviceAuthorizationEvents = c.counterVec(constLabels, auditevent.MetricDeviceAuthorization,
		"Device-authorization endpoint outcomes, partitioned by the event sub-name (the audit name with the device_authorization. prefix stripped).",
		"event")
	c.deviceCodeEvents = c.counterVec(constLabels, auditevent.MetricDeviceCode,
		"Device-code lifecycle events (verification, token exchange, revocation), partitioned by the event sub-name (the audit name with the device_code. prefix stripped).",
		"event")
	c.cibaEvents = c.counterVec(constLabels, auditevent.MetricCIBA,
		"CIBA flow events, partitioned by the event sub-name (the audit name with the ciba. prefix stripped).",
		"event")
	c.tokenExchangeEvents = c.counterVec(constLabels, auditevent.MetricTokenExchange,
		"Token-exchange (RFC 8693) outcomes, partitioned by the event sub-name (the audit name with the token_exchange. prefix stripped).",
		"event")
	c.customGrantEvents = c.counterVec(constLabels, auditevent.MetricCustomGrant,
		"Custom-grant dispatcher outcomes, partitioned by the event sub-name.",
		"event")
	c.backChannelLogout = c.counterVec(constLabels, auditevent.MetricBackChannelLogout,
		"Back-channel logout delivery and target-resolution outcomes, partitioned by result.",
		"result")
	c.logoutFailures = c.counterVec(constLabels, auditevent.MetricLogoutFailures,
		"Logout persistence failures, partitioned by failed side effect.",
		"kind")
	c.introspectionErrors = c.counter(constLabels, auditevent.MetricIntrospectionErrors,
		"Number of pre-authentication failures observed at the /introspect endpoint.")
	c.tokenRevokeFailures = c.counterVec(constLabels, auditevent.MetricTokenRevokeFailures,
		"Token-revocation side-effect failures, partitioned by failed stage (token, refresh chain, refresh grant, or prior access token).",
		"kind")
	c.dpopLooseMethodCase = c.counter(constLabels, auditevent.MetricDPoPLooseMethodCase,
		"Number of DPoP proofs admitted under the opt-in case-folded htm bridge.")
	c.keyRetiredKidPresented = c.counter(constLabels, auditevent.MetricKeyRetiredKidPresented,
		"Number of verifications that named a kid past its retirement deadline (rotation-after-leak forge attempt signal).")
	if err := registerAll(reg, c.collectors); err != nil {
		return nil, err
	}
	c.registered = true
	return c, nil
}

// counter creates a plain counter for metric and records it for registration.
func (c *Collector) counter(constLabels prometheus.Labels, metric auditevent.Metric, help string) prometheus.Counter { //nolint:ireturn // prometheus.NewCounter returns the interface.
	col := prometheus.NewCounter(prometheus.CounterOpts{
		Name:        auditevent.MetricName(metric),
		Help:        help,
		ConstLabels: constLabels,
	})
	c.collectors = append(c.collectors, col)
	return col
}

// counterVec creates a labelled counter for metric and records it for registration.
func (c *Collector) counterVec(constLabels prometheus.Labels, metric auditevent.Metric, help string, labels ...string) *prometheus.CounterVec {
	col := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        auditevent.MetricName(metric),
		Help:        help,
		ConstLabels: constLabels,
	}, labels)
	c.collectors = append(c.collectors, col)
	return col
}

// registerAll registers every collector on reg, all-or-nothing: on the
// first refusal the ones already accepted are unregistered and the error
// is returned, so a failed call leaves reg exactly as it was found.
func registerAll(reg *prometheus.Registry, collectors []prometheus.Collector) error {
	for i, col := range collectors {
		if err := reg.Register(col); err != nil {
			// The embedder owns reg and may keep using it after the error.
			for _, done := range collectors[:i] {
				reg.Unregister(done)
			}
			return err
		}
	}
	return nil
}

// Register re-registers every collector of c on the registry it owns,
// after a prior [Collector.Unregister]. It is all-or-nothing in the same
// way as [New]: on a refusal the collectors already re-added are removed
// again and the error is returned, leaving c unregistered. Calling it
// while c is registered is a no-op returning nil.
//
// The metric values survive the round trip: the same collector values
// are re-added, so counters resume where they stopped.
func (c *Collector) Register() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.registered {
		return nil
	}
	if err := registerAll(c.registry, c.collectors); err != nil {
		return err
	}
	c.registered = true
	return nil
}

// Unregister removes every collector registered by c from the registry it
// owns. It is safe to call more than once (including from competing rollback
// paths); it acts only while c is registered and returns whether at least
// one collector was removed. A false return means that c was already
// unregistered, or that none of its collectors were still on the registry.
//
// The op constructor should call c.Unregister from its rollback path after a
// later construction step fails. Collectors owned by another constructor are
// never touched because this method only retains c's exact collector values.
func (c *Collector) Unregister() (removed bool) {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.registered {
		return false
	}
	c.registered = false
	for _, collector := range c.collectors {
		if c.registry.Unregister(collector) {
			removed = true
		}
	}
	return removed
}

// clientIDLabel returns id when it is a known static client and ""
// otherwise. The empty bucket is the cardinality-safe sink for
// dynamic-DCR clients.
func (c *Collector) clientIDLabel(id string) string {
	if id == "" {
		return ""
	}
	if _, ok := c.opts.StaticClientIDs[id]; ok {
		return id
	}
	return ""
}
