package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
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
// of the [op.Provider]; mutation after construction is forbidden.
type Collector struct {
	opts                      Options
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
	c := &Collector{
		opts: opts,
		tokenIssued: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_token_issued_total",
				Help:        "Number of access / refresh / id tokens issued by the OP, partitioned by grant_type and (static-seed) client_id.",
				ConstLabels: constLabels,
			},
			[]string{"grant_type", "client_id"},
		),
		tokensRefreshed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_tokens_refreshed_total",
				Help:        "Number of refresh-token rotations completed by the token endpoint, partitioned by (static-seed) client_id.",
				ConstLabels: constLabels,
			},
			[]string{"client_id"},
		),
		loginAttempts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_login_attempts_total",
				Help:        "Number of login attempts processed by the authenticator chain, partitioned by result and authenticator label.",
				ConstLabels: constLabels,
			},
			[]string{"result", "authenticator"},
		),
		refreshReplay: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name:        "oidc_refresh_replay_detected_total",
				Help:        "Number of refresh-token replay events detected by the rotation chain.",
				ConstLabels: constLabels,
			},
		),
		codeReplay: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name:        "oidc_code_replay_detected_total",
				Help:        "Number of authorization-code replay events detected at the token endpoint.",
				ConstLabels: constLabels,
			},
		),
		clientAuthnFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_client_authn_failures_total",
				Help:        "Number of pre-issuance client-authentication failures, partitioned by auth_method and short reason code.",
				ConstLabels: constLabels,
			},
			[]string{"auth_method", "reason"},
		),
		dcrEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_dcr_events_total",
				Help:        "Dynamic Client Registration events, partitioned by the event sub-name (the audit name with the dcr. prefix stripped).",
				ConstLabels: constLabels,
			},
			[]string{"event"},
		),
		deviceAuthorizationEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_device_authorization_events_total",
				Help:        "Device-authorization endpoint outcomes, partitioned by the event sub-name (the audit name with the device_authorization. prefix stripped).",
				ConstLabels: constLabels,
			},
			[]string{"event"},
		),
		deviceCodeEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_device_code_events_total",
				Help:        "Device-code lifecycle events (verification, token exchange, revocation), partitioned by the event sub-name (the audit name with the device_code. prefix stripped).",
				ConstLabels: constLabels,
			},
			[]string{"event"},
		),
		cibaEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_ciba_events_total",
				Help:        "CIBA flow events, partitioned by the event sub-name (the audit name with the ciba. prefix stripped).",
				ConstLabels: constLabels,
			},
			[]string{"event"},
		),
		tokenExchangeEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_token_exchange_events_total",
				Help:        "Token-exchange (RFC 8693) outcomes, partitioned by the event sub-name (the audit name with the token_exchange. prefix stripped).",
				ConstLabels: constLabels,
			},
			[]string{"event"},
		),
		customGrantEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_custom_grant_events_total",
				Help:        "Custom-grant dispatcher outcomes, partitioned by the event sub-name.",
				ConstLabels: constLabels,
			},
			[]string{"event"},
		),
		backChannelLogout: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_back_channel_logout_total",
				Help:        "Back-channel logout delivery and target-resolution outcomes, partitioned by result.",
				ConstLabels: constLabels,
			},
			[]string{"result"},
		),
		logoutFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_logout_failures_total",
				Help:        "Logout persistence failures, partitioned by failed side effect.",
				ConstLabels: constLabels,
			},
			[]string{"kind"},
		),
		introspectionErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name:        "oidc_introspection_errors_total",
				Help:        "Number of pre-authentication failures observed at the /introspect endpoint.",
				ConstLabels: constLabels,
			},
		),
		tokenRevokeFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "oidc_token_revoke_failures_total",
				Help:        "Silent token-revocation failures (token, refresh chain, refresh grant) where the wire response succeeded but the side effect did not.",
				ConstLabels: constLabels,
			},
			[]string{"kind"},
		),
		dpopLooseMethodCase: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name:        "oidc_dpop_loose_method_case_admitted_total",
				Help:        "Number of DPoP proofs admitted under the opt-in case-folded htm bridge.",
				ConstLabels: constLabels,
			},
		),
		keyRetiredKidPresented: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name:        "oidc_key_retired_kid_presented_total",
				Help:        "Number of verifications that named a kid past its retirement deadline (rotation-after-leak forge attempt signal).",
				ConstLabels: constLabels,
			},
		),
	}
	collectors := []prometheus.Collector{
		c.tokenIssued,
		c.tokensRefreshed,
		c.loginAttempts,
		c.refreshReplay,
		c.codeReplay,
		c.clientAuthnFailures,
		c.dcrEvents,
		c.deviceAuthorizationEvents,
		c.deviceCodeEvents,
		c.cibaEvents,
		c.tokenExchangeEvents,
		c.customGrantEvents,
		c.backChannelLogout,
		c.logoutFailures,
		c.introspectionErrors,
		c.tokenRevokeFailures,
		c.dpopLooseMethodCase,
		c.keyRetiredKidPresented,
	}
	registered := make([]prometheus.Collector, 0, len(collectors))
	for _, col := range collectors {
		if err := reg.Register(col); err != nil {
			// Roll back so a rejected collector cannot leave a partially
			// populated registry behind: the embedder owns reg and may
			// keep using it after New reports the misconfiguration.
			for _, done := range registered {
				reg.Unregister(done)
			}
			return nil, err
		}
		registered = append(registered, col)
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
