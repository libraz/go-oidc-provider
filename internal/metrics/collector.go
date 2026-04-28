package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

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
}

// Collector bundles the Prometheus collectors the OP registers. The
// struct is constructed once at [op.New] and reused for the lifetime
// of the [op.Provider]; mutation after construction is forbidden.
type Collector struct {
	opts          Options
	tokenIssued   *prometheus.CounterVec
	loginAttempts *prometheus.CounterVec
	refreshReplay prometheus.Counter
	codeReplay    prometheus.Counter
}

// New constructs a [Collector] and registers every metric on reg. A
// nil reg is rejected because the package contract requires the
// embedder to own the registry; re-registration is reported as the
// standard [prometheus.AlreadyRegisteredError] so the caller can
// decide whether to swap registries or surface the misconfiguration.
func New(reg *prometheus.Registry, opts Options) (*Collector, error) {
	if reg == nil {
		return nil, errors.New("metrics: registry is required")
	}
	c := &Collector{
		opts: opts,
		tokenIssued: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oidc_token_issued_total",
				Help: "Number of access / refresh / id tokens issued by the OP, partitioned by grant_type and (static-seed) client_id.",
			},
			[]string{"grant_type", "client_id"},
		),
		loginAttempts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oidc_login_attempts_total",
				Help: "Number of login attempts processed by the authenticator chain, partitioned by result and authenticator label.",
			},
			[]string{"result", "authenticator"},
		),
		refreshReplay: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "oidc_refresh_replay_detected_total",
				Help: "Number of refresh-token replay events detected by the rotation chain.",
			},
		),
		codeReplay: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "oidc_code_replay_detected_total",
				Help: "Number of authorization-code replay events detected at the token endpoint.",
			},
		),
	}
	collectors := []prometheus.Collector{
		c.tokenIssued,
		c.loginAttempts,
		c.refreshReplay,
		c.codeReplay,
	}
	for _, col := range collectors {
		if err := reg.Register(col); err != nil {
			return nil, err
		}
	}
	return c, nil
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
