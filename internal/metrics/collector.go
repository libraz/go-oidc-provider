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
	backChannelLogout         *prometheus.CounterVec
	introspectionErrors       prometheus.Counter
	tokenRevokeFailures       *prometheus.CounterVec
	dpopLooseMethodCase       prometheus.Counter
	keyRetiredKidPresented    prometheus.Counter
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
		tokensRefreshed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oidc_tokens_refreshed_total",
				Help: "Number of refresh-token rotations completed by the token endpoint, partitioned by (static-seed) client_id.",
			},
			[]string{"client_id"},
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
		clientAuthnFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oidc_client_authn_failures_total",
				Help: "Number of pre-issuance client-authentication failures, partitioned by auth_method and short reason code.",
			},
			[]string{"auth_method", "reason"},
		),
		dcrEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oidc_dcr_events_total",
				Help: "Dynamic Client Registration events, partitioned by the event sub-name (the audit name with the dcr. prefix stripped).",
			},
			[]string{"event"},
		),
		deviceAuthorizationEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oidc_device_authorization_events_total",
				Help: "Device-authorization endpoint outcomes, partitioned by the event sub-name (the audit name with the device_authorization. prefix stripped).",
			},
			[]string{"event"},
		),
		deviceCodeEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oidc_device_code_events_total",
				Help: "Device-code lifecycle events (verification, token exchange, revocation), partitioned by the event sub-name (the audit name with the device_code. prefix stripped).",
			},
			[]string{"event"},
		),
		cibaEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oidc_ciba_events_total",
				Help: "CIBA flow events, partitioned by the event sub-name (the audit name with the ciba. prefix stripped).",
			},
			[]string{"event"},
		),
		tokenExchangeEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oidc_token_exchange_events_total",
				Help: "Token-exchange (RFC 8693) outcomes, partitioned by the event sub-name (the audit name with the token_exchange. prefix stripped).",
			},
			[]string{"event"},
		),
		backChannelLogout: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oidc_back_channel_logout_total",
				Help: "Back-channel logout delivery outcomes, partitioned by result (delivered, failed, no_sessions_for_subject).",
			},
			[]string{"result"},
		),
		introspectionErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "oidc_introspection_errors_total",
				Help: "Number of pre-authentication failures observed at the /introspect endpoint.",
			},
		),
		tokenRevokeFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "oidc_token_revoke_failures_total",
				Help: "Silent token-revocation failures (token, refresh chain, refresh grant) where the wire response succeeded but the side effect did not.",
			},
			[]string{"kind"},
		),
		dpopLooseMethodCase: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "oidc_dpop_loose_method_case_admitted_total",
				Help: "Number of DPoP proofs admitted under the opt-in case-folded htm bridge.",
			},
		),
		keyRetiredKidPresented: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "oidc_key_retired_kid_presented_total",
				Help: "Number of verifications that named a kid past its retirement deadline (rotation-after-leak forge attempt signal).",
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
		c.backChannelLogout,
		c.introspectionErrors,
		c.tokenRevokeFailures,
		c.dpopLooseMethodCase,
		c.keyRetiredKidPresented,
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
