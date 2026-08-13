package metrics_test

import (
	"context"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/metrics"
	"github.com/libraz/go-oidc-provider/op/store"
)

// recordingEmitter is a test stub that captures every event it
// receives. The mutex makes the table-driven concurrency check below
// reliable on -race.
type recordingEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingEmitter) Emit(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingEmitter) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.Event, len(r.events))
	copy(out, r.events)
	return out
}

// testIssuer is the issuer every collector built by newTestCollector
// carries. The constructor stamps it as a constant label on every
// metric, so counterValue folds it into the expected label set rather
// than making each assertion site repeat it. The label itself is
// asserted directly in TestCollector_New_IssuerConstLabelEmitted.
const testIssuer = "https://idp.example.test"

// counterValue scans families for the metric with the matching name
// and label set, returning its current value. The helper isolates the
// dto.Metric inspection loop from the assertion sites below.
func counterValue(t *testing.T, families []*dto.MetricFamily, name string, labels map[string]string) float64 {
	t.Helper()
	want := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		want[k] = v
	}
	want["issuer"] = testIssuer
	labels = want
	for _, fam := range families {
		if fam.GetName() != name {
			continue
		}
		for _, m := range fam.GetMetric() {
			if labelsMatch(m.GetLabel(), labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func labelsMatch(have []*dto.LabelPair, want map[string]string) bool {
	if len(have) != len(want) {
		return false
	}
	for _, lp := range have {
		if want[lp.GetName()] != lp.GetValue() {
			return false
		}
	}
	return true
}

// newTestCollector builds a collector against a fresh registry and
// returns both. The registry is the surface every test inspects via
// Gather; the collector is the bridge target.
func newTestCollector(t *testing.T, opts metrics.Options) (*metrics.Collector, *prometheus.Registry) {
	t.Helper()
	if opts.Issuer == "" {
		opts.Issuer = testIssuer
	}
	reg := prometheus.NewRegistry()
	c, err := metrics.New(reg, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, reg
}

func TestBridge_TokenIssued_StaticClientLabelEmitted(t *testing.T) {
	t.Parallel()

	c, reg := newTestCollector(t, metrics.Options{
		StaticClientIDs: map[string]struct{}{"client-1": {}},
	})
	rec := &recordingEmitter{}
	b := metrics.NewBridge(c, rec)

	b.Emit(context.Background(), audit.Event{
		Name:     "token.issued",
		ClientID: "client-1",
		// This is the production auth-code shape: the typed origin names
		// the grant, while the remaining Extras carry audit context.
		Extras: map[string]any{
			"grant_id":                    "grant-1",
			"offline_access":              false,
			"ttl_bucket":                  "default",
			auditevent.ExtraRefreshOrigin: store.RefreshOriginAuthCode,
		},
	})

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := counterValue(t, families, "oidc_token_issued_total", map[string]string{
		"grant_type": "authorization_code",
		"client_id":  "client-1",
	})
	if got != 1 {
		t.Fatalf("counter = %v, want 1", got)
	}
	if len(rec.snapshot()) != 1 {
		t.Fatalf("downstream emitter saw %d events, want 1", len(rec.snapshot()))
	}
}

func TestBridge_TokenIssued_DynamicClientCollapsesToEmpty(t *testing.T) {
	t.Parallel()

	c, reg := newTestCollector(t, metrics.Options{
		StaticClientIDs: map[string]struct{}{"client-1": {}},
	})
	b := metrics.NewBridge(c, nil)

	b.Emit(context.Background(), audit.Event{
		Name:     "token.issued",
		ClientID: "dynamic-99",
		Extras: map[string]any{
			"grant_id":                    "grant-2",
			"offline_access":              true,
			"ttl_bucket":                  "offline",
			auditevent.ExtraRefreshOrigin: store.RefreshOriginAuthCode,
		},
	})

	families, _ := reg.Gather()
	got := counterValue(t, families, "oidc_token_issued_total", map[string]string{
		"grant_type": "authorization_code",
		"client_id":  "",
	})
	if got != 1 {
		t.Fatalf("counter = %v, want 1", got)
	}
	leaked := counterValue(t, families, "oidc_token_issued_total", map[string]string{
		"grant_type": "authorization_code",
		"client_id":  "dynamic-99",
	})
	if leaked != 0 {
		t.Fatalf("dynamic client_id leaked into label: counter = %v", leaked)
	}
}

// TestBridge_TokenIssued_GrantTypeFollowsChainOrigin pins the invariant
// that makes the counter usable for per-grant alerting: every increment
// carries the grant that actually created the chain. A redemption filed
// under another grant's label is doubly wrong — it invents issuance on a
// grant that ran nothing and hides the grant that ran.
func TestBridge_TokenIssued_GrantTypeFollowsChainOrigin(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		origin store.RefreshTokenOrigin
		want   string
	}{
		{"authorization_code", store.RefreshOriginAuthCode, "authorization_code"},
		{"device_code", store.RefreshOriginDeviceCode, "device_code"},
		{"ciba", store.RefreshOriginCIBA, "ciba"},
		{"custom_grant", store.RefreshOriginCustomGrant, "custom_grant"},
		{"unregistered_origin", store.RefreshTokenOrigin("not_a_grant"), "unknown"},
		{"legacy_record_without_origin", "", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, reg := newTestCollector(t, metrics.Options{})
			metrics.NewBridge(c, nil).Emit(context.Background(), audit.Event{
				Name:   "token.issued",
				Extras: map[string]any{auditevent.ExtraRefreshOrigin: tc.origin},
			})
			families, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather: %v", err)
			}
			if got := counterValue(t, families, "oidc_token_issued_total", map[string]string{
				"grant_type": tc.want,
				"client_id":  "",
			}); got != 1 {
				t.Fatalf("oidc_token_issued_total{grant_type=%q} = %v, want 1", tc.want, got)
			}
			if tc.want == "authorization_code" {
				return
			}
			// The collapse this guards against is one-directional: an
			// origin the bridge cannot resolve must not be absorbed by
			// the busiest series.
			if got := counterValue(t, families, "oidc_token_issued_total", map[string]string{
				"grant_type": "authorization_code",
				"client_id":  "",
			}); got != 0 {
				t.Fatalf("origin %q collapsed onto authorization_code: counter = %v", tc.origin, got)
			}
		})
	}
}

// TestBridge_TokenIssued_UntypedOriginCannotForgeGrantType keeps the
// label sourced from the OP's own typed value. Extras is a free-form map
// whose other keys carry request-derived data, so a string that names a
// grant must not be able to move the counter into that grant's series.
func TestBridge_TokenIssued_UntypedOriginCannotForgeGrantType(t *testing.T) {
	t.Parallel()

	c, reg := newTestCollector(t, metrics.Options{})
	metrics.NewBridge(c, nil).Emit(context.Background(), audit.Event{
		Name: "token.issued",
		Extras: map[string]any{
			"grant_type":                  "refresh_token",
			auditevent.ExtraRefreshOrigin: string(store.RefreshOriginDeviceCode),
		},
	})
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	if got := counterValue(t, families, "oidc_token_issued_total", map[string]string{
		"grant_type": "unknown",
		"client_id":  "",
	}); got != 1 {
		t.Fatalf("unknown grant_type counter=%v want 1", got)
	}
	for _, forged := range []string{"refresh_token", "device_code", "authorization_code"} {
		if got := counterValue(t, families, "oidc_token_issued_total", map[string]string{
			"grant_type": forged,
			"client_id":  "",
		}); got != 0 {
			t.Fatalf("forged grant_type %q counter=%v want 0", forged, got)
		}
	}
}

func TestBridge_LoginAttempts_TableDriven(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		event      audit.Event
		wantResult string
		wantFactor string
	}{
		{
			name: "success_with_factor",
			event: audit.Event{
				Name:   "login.success",
				Extras: map[string]any{"factor": "password"},
			},
			wantResult: "success",
			wantFactor: "password",
		},
		{
			name: "failed_with_factor",
			event: audit.Event{
				Name:   "login.failed",
				Extras: map[string]any{"factor": "totp"},
			},
			wantResult: "failed",
			wantFactor: "totp",
		},
		{
			name: "success_without_extras",
			event: audit.Event{
				Name: "login.success",
			},
			wantResult: "success",
			wantFactor: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, reg := newTestCollector(t, metrics.Options{})
			b := metrics.NewBridge(c, nil)
			b.Emit(context.Background(), tc.event)

			families, _ := reg.Gather()
			got := counterValue(t, families, "oidc_login_attempts_total", map[string]string{
				"factor": tc.wantFactor,
				"result": tc.wantResult,
			})
			if got != 1 {
				t.Fatalf("counter = %v, want 1", got)
			}
		})
	}
}

func TestBridge_MFAAttemptsUseSameLoginCounter(t *testing.T) {
	t.Parallel()

	c, reg := newTestCollector(t, metrics.Options{})
	b := metrics.NewBridge(c, nil)
	b.Emit(context.Background(), audit.Event{
		Name:   string(auditevent.AuditMFASuccess),
		Extras: map[string]any{"factor": "totp"},
	})
	b.Emit(context.Background(), audit.Event{
		Name:   string(auditevent.AuditMFAFailed),
		Extras: map[string]any{"factor": "totp"},
	})

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, result := range []string{"success", "failed"} {
		if got := counterValue(t, families, "oidc_login_attempts_total", map[string]string{
			"factor": "totp",
			"result": result,
		}); got != 1 {
			t.Errorf("MFA %s counter = %v, want 1", result, got)
		}
	}
}

func TestBridge_ReplayCounters(t *testing.T) {
	t.Parallel()

	c, reg := newTestCollector(t, metrics.Options{})
	b := metrics.NewBridge(c, nil)

	b.Emit(context.Background(), audit.Event{Name: "refresh.replay_detected"})
	b.Emit(context.Background(), audit.Event{Name: "code.replay_detected"})

	families, _ := reg.Gather()
	for _, name := range []string{
		"oidc_refresh_replay_detected_total",
		"oidc_code_replay_detected_total",
	} {
		got := counterValue(t, families, name, map[string]string{})
		if got != 1 {
			t.Errorf("%s = %v, want 1", name, got)
		}
	}
}

func TestBridge_UnrelatedEvent_ForwardedWithoutMetric(t *testing.T) {
	t.Parallel()

	c, reg := newTestCollector(t, metrics.Options{})
	rec := &recordingEmitter{}
	b := metrics.NewBridge(c, rec)

	b.Emit(context.Background(), audit.Event{Name: "account.created"})

	families, _ := reg.Gather()
	for _, fam := range families {
		for _, m := range fam.GetMetric() {
			if m.GetCounter().GetValue() != 0 {
				t.Errorf("metric %s saw a mutation it should not have", fam.GetName())
			}
		}
	}
	if len(rec.snapshot()) != 1 {
		t.Fatalf("downstream emitter saw %d events, want 1", len(rec.snapshot()))
	}
	if rec.snapshot()[0].Name != "account.created" {
		t.Fatalf("forwarded event = %q, want account.created", rec.snapshot()[0].Name)
	}
}

func TestBridge_NilNext_AcceptsAndDoesNotPanic(t *testing.T) {
	t.Parallel()

	c, _ := newTestCollector(t, metrics.Options{})
	b := metrics.NewBridge(c, nil)

	b.Emit(context.Background(), audit.Event{Name: "refresh.replay_detected"})
	// reaching here without panic is the assertion; the discard
	// downstream is internal so there is nothing else to inspect.
}

func TestBridge_TokenRefreshed_StaticClientLabelEmitted(t *testing.T) {
	t.Parallel()

	c, reg := newTestCollector(t, metrics.Options{
		StaticClientIDs: map[string]struct{}{"client-1": {}},
	})
	b := metrics.NewBridge(c, nil)

	b.Emit(context.Background(), audit.Event{
		Name:     "token.refreshed",
		ClientID: "client-1",
	})
	b.Emit(context.Background(), audit.Event{
		Name:     "token.refreshed",
		ClientID: "dynamic-99",
	})

	families, _ := reg.Gather()
	if got := counterValue(t, families, "oidc_tokens_refreshed_total", map[string]string{"client_id": "client-1"}); got != 1 {
		t.Errorf("static client counter = %v, want 1", got)
	}
	if got := counterValue(t, families, "oidc_tokens_refreshed_total", map[string]string{"client_id": ""}); got != 1 {
		t.Errorf("dynamic client (empty bucket) counter = %v, want 1", got)
	}
	if leaked := counterValue(t, families, "oidc_tokens_refreshed_total", map[string]string{"client_id": "dynamic-99"}); leaked != 0 {
		t.Errorf("dynamic client_id leaked into label: counter = %v", leaked)
	}
}

func TestBridge_ClientAuthnFailure_LabelsFromExtras(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		extras     map[string]any
		wantMethod string
		wantReason string
	}{
		{
			name: "with_method_and_reason",
			extras: map[string]any{
				"method": "client_secret_basic",
				"reason": "invalid_client_credentials",
			},
			wantMethod: "client_secret_basic",
			wantReason: "invalid_client_credentials",
		},
		{
			name:       "missing_method_collapses_to_empty",
			extras:     map[string]any{"reason": "no_credentials"},
			wantMethod: "",
			wantReason: "no_credentials",
		},
		{
			name:       "non_string_extras_collapse_to_empty",
			extras:     map[string]any{"method": 42, "reason": []string{"foo"}},
			wantMethod: "",
			wantReason: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, reg := newTestCollector(t, metrics.Options{})
			b := metrics.NewBridge(c, nil)
			b.Emit(context.Background(), audit.Event{
				Name:   "client_authn.failure",
				Extras: tc.extras,
			})
			families, _ := reg.Gather()
			got := counterValue(t, families, "oidc_client_authn_failures_total", map[string]string{
				"auth_method": tc.wantMethod,
				"reason":      tc.wantReason,
			})
			if got != 1 {
				t.Fatalf("counter = %v, want 1", got)
			}
		})
	}
}

func TestBridge_PrefixDispatch_TableDriven(t *testing.T) {
	t.Parallel()

	cases := []struct {
		eventName  string
		metricName string
		wantEvent  string
	}{
		// DCR
		{"dcr.client.registered", "oidc_dcr_events_total", "client.registered"},
		{"dcr.client.deleted", "oidc_dcr_events_total", "client.deleted"},
		{"dcr.iat.invalid", "oidc_dcr_events_total", "iat.invalid"},
		{"dcr.iat.expired", "oidc_dcr_events_total", "iat.expired"},
		{"dcr.rat.invalid", "oidc_dcr_events_total", "rat.invalid"},
		{"dcr.metadata.validation_failed", "oidc_dcr_events_total", "metadata.validation_failed"},
		{"dcr.open_registration_used", "oidc_dcr_events_total", "open_registration_used"},
		// Device authorization
		{"device_authorization.issued", "oidc_device_authorization_events_total", "issued"},
		{"device_authorization.rejected", "oidc_device_authorization_events_total", "rejected"},
		{"device_authorization.unbound_rejected", "oidc_device_authorization_events_total", "unbound_rejected"},
		// Device code
		{"device_code.token.issued", "oidc_device_code_events_total", "token.issued"},
		{"device_code.token.rejected", "oidc_device_code_events_total", "token.rejected"},
		{"device_code.token.slow_down", "oidc_device_code_events_total", "token.slow_down"},
		{"device_code.verification.approved", "oidc_device_code_events_total", "verification.approved"},
		{"device_code.verification.denied", "oidc_device_code_events_total", "verification.denied"},
		{"device_code.verification.user_code_brute_force", "oidc_device_code_events_total", "verification.user_code_brute_force"},
		{"device_code.revoked", "oidc_device_code_events_total", "revoked"},
		// CIBA
		{"ciba.authorization.issued", "oidc_ciba_events_total", "authorization.issued"},
		{"ciba.authorization.rejected", "oidc_ciba_events_total", "authorization.rejected"},
		{"ciba.authorization.unbound_rejected", "oidc_ciba_events_total", "authorization.unbound_rejected"},
		{"ciba.token.issued", "oidc_ciba_events_total", "token.issued"},
		{"ciba.token.rejected", "oidc_ciba_events_total", "token.rejected"},
		{"ciba.token.slow_down", "oidc_ciba_events_total", "token.slow_down"},
		{"ciba.poll_abuse.lockout", "oidc_ciba_events_total", "poll_abuse.lockout"},
		{"ciba.poll_observation.failed", "oidc_ciba_events_total", "poll_observation.failed"},
		{"ciba.auth_device.approved", "oidc_ciba_events_total", "auth_device.approved"},
		{"ciba.auth_device.denied", "oidc_ciba_events_total", "auth_device.denied"},
		// Token exchange
		{"token_exchange.granted", "oidc_token_exchange_events_total", "granted"},
		{"token_exchange.policy_denied", "oidc_token_exchange_events_total", "policy_denied"},
		{"token_exchange.policy_error", "oidc_token_exchange_events_total", "policy_error"},
		{"token_exchange.scope_inflation_blocked", "oidc_token_exchange_events_total", "scope_inflation_blocked"},
		{"token_exchange.audience_blocked", "oidc_token_exchange_events_total", "audience_blocked"},
		{"token_exchange.subject_token_invalid", "oidc_token_exchange_events_total", "subject_token_invalid"},
		// Back-channel logout (prefix dispatch)
		{"logout.back_channel.delivered", "oidc_back_channel_logout_total", "delivered"},
		{"logout.back_channel.failed", "oidc_back_channel_logout_total", "failed"},
	}
	for _, tc := range cases {
		t.Run(tc.eventName, func(t *testing.T) {
			t.Parallel()
			c, reg := newTestCollector(t, metrics.Options{})
			b := metrics.NewBridge(c, nil)
			b.Emit(context.Background(), audit.Event{Name: tc.eventName})
			families, _ := reg.Gather()
			got := counterValue(t, families, tc.metricName, map[string]string{"event": tc.wantEvent})
			if got != 1 {
				// back_channel_logout_total uses "result" rather than "event"
				if tc.metricName == "oidc_back_channel_logout_total" {
					got = counterValue(t, families, tc.metricName, map[string]string{"result": tc.wantEvent})
					if got == 1 {
						return
					}
				}
				t.Fatalf("%s{event=%q} = %v, want 1", tc.metricName, tc.wantEvent, got)
			}
		})
	}
}

func TestBridge_UnknownNamesAreForwardOnly(t *testing.T) {
	t.Parallel()

	cases := []struct {
		eventName  string
		metricName string
		labelName  string
	}{
		{"dcr.attacker_controlled_1", "oidc_dcr_events_total", "event"},
		{"device_authorization.attacker_controlled_2", "oidc_device_authorization_events_total", "event"},
		{"device_code.attacker_controlled_3", "oidc_device_code_events_total", "event"},
		{"ciba.attacker_controlled_4", "oidc_ciba_events_total", "event"},
		{"token_exchange.attacker_controlled_5", "oidc_token_exchange_events_total", "event"},
		{"logout.back_channel.attacker_controlled_6", "oidc_back_channel_logout_total", "result"},
	}
	for _, tc := range cases {
		t.Run(tc.eventName, func(t *testing.T) {
			t.Parallel()
			c, reg := newTestCollector(t, metrics.Options{})
			b := metrics.NewBridge(c, nil)
			for range 100 {
				b.Emit(context.Background(), audit.Event{Name: tc.eventName})
			}
			families, _ := reg.Gather()
			got := counterValue(t, families, tc.metricName, map[string]string{tc.labelName: "unknown"})
			if got != 0 {
				t.Fatalf("%s{%s=unknown} = %v, want 0", tc.metricName, tc.labelName, got)
			}
		})
	}
}

func TestBridge_CatalogMetricProjectionIsUnique(t *testing.T) {
	t.Parallel()

	for _, definition := range auditevent.Catalog() {
		if definition.Metric == auditevent.MetricNone {
			continue
		}
		t.Run(string(definition.Name), func(t *testing.T) {
			t.Parallel()
			c, reg := newTestCollector(t, metrics.Options{})
			bridge := metrics.NewBridge(c, nil)
			bridge.Emit(context.Background(), audit.Event{
				Name: string(definition.Name),
				Extras: map[string]any{
					auditevent.ExtraRefreshOrigin: store.RefreshOriginAuthCode,
					"factor":                      "password",
					"method":                      "client_secret_basic",
					"reason":                      "invalid_client_credentials",
				},
			})

			families, err := reg.Gather()
			if err != nil {
				t.Fatalf("Gather: %v", err)
			}
			metricName := auditevent.MetricName(definition.Metric)
			labels := catalogMetricLabels(definition)
			if got := counterValue(t, families, metricName, labels); got != 1 {
				t.Fatalf("%s%v = %v, want 1", metricName, labels, got)
			}
			if got := positiveCounterCount(families); got != 1 {
				t.Fatalf("positive counters = %d, want exactly 1", got)
			}
		})
	}
}

func catalogMetricLabels(definition auditevent.Definition) map[string]string {
	switch definition.Metric {
	case auditevent.MetricTokenIssued:
		return map[string]string{"grant_type": "authorization_code", "client_id": ""}
	case auditevent.MetricTokensRefreshed:
		return map[string]string{"client_id": ""}
	case auditevent.MetricLoginAttempts:
		return map[string]string{"factor": "password", "result": definition.Label}
	case auditevent.MetricClientAuthnFailures:
		return map[string]string{"auth_method": "client_secret_basic", "reason": "invalid_client_credentials"}
	case auditevent.MetricDCR,
		auditevent.MetricDeviceAuthorization,
		auditevent.MetricDeviceCode,
		auditevent.MetricCIBA,
		auditevent.MetricTokenExchange,
		auditevent.MetricCustomGrant:
		return map[string]string{"event": definition.Label}
	case auditevent.MetricBackChannelLogout:
		return map[string]string{"result": definition.Label}
	case auditevent.MetricLogoutFailures, auditevent.MetricTokenRevokeFailures:
		return map[string]string{"kind": definition.Label}
	case auditevent.MetricRefreshReplay,
		auditevent.MetricCodeReplay,
		auditevent.MetricIntrospectionErrors,
		auditevent.MetricDPoPLooseMethodCase,
		auditevent.MetricKeyRetiredKidPresented,
		auditevent.MetricNone:
		return map[string]string{}
	}
	return map[string]string{}
}

func positiveCounterCount(families []*dto.MetricFamily) int {
	var count int
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			if metric.GetCounter().GetValue() > 0 {
				count++
			}
		}
	}
	return count
}

func TestBridge_BackChannelLogout_NoSessions_RoutesToResultLabel(t *testing.T) {
	t.Parallel()

	c, reg := newTestCollector(t, metrics.Options{})
	b := metrics.NewBridge(c, nil)

	b.Emit(context.Background(), audit.Event{Name: "bcl.no_sessions_for_subject"})

	families, _ := reg.Gather()
	got := counterValue(t, families, "oidc_back_channel_logout_total", map[string]string{
		"result": "no_sessions_for_subject",
	})
	if got != 1 {
		t.Fatalf("counter = %v, want 1", got)
	}
}

func TestBridge_TokenRevokeFailures_KindLabel(t *testing.T) {
	t.Parallel()

	cases := []struct {
		eventName string
		wantKind  string
	}{
		{"token.revoke_failed", "token"},
		{"refresh.chain_revoke_failed", "refresh_chain"},
		{"refresh.grant_revoke_failed", "refresh_grant"},
	}
	for _, tc := range cases {
		t.Run(tc.eventName, func(t *testing.T) {
			t.Parallel()
			c, reg := newTestCollector(t, metrics.Options{})
			b := metrics.NewBridge(c, nil)
			b.Emit(context.Background(), audit.Event{Name: tc.eventName})
			families, _ := reg.Gather()
			got := counterValue(t, families, "oidc_token_revoke_failures_total", map[string]string{
				"kind": tc.wantKind,
			})
			if got != 1 {
				t.Fatalf("counter = %v, want 1", got)
			}
		})
	}
}

func TestBridge_ScalarCounters(t *testing.T) {
	t.Parallel()

	cases := []struct {
		eventName  string
		metricName string
	}{
		{"introspection.error", "oidc_introspection_errors_total"},
		{"dpop.loose_method_case_admitted", "oidc_dpop_loose_method_case_admitted_total"},
		{"key.retired_kid_presented", "oidc_key_retired_kid_presented_total"},
	}
	for _, tc := range cases {
		t.Run(tc.eventName, func(t *testing.T) {
			t.Parallel()
			c, reg := newTestCollector(t, metrics.Options{})
			b := metrics.NewBridge(c, nil)
			b.Emit(context.Background(), audit.Event{Name: tc.eventName})
			families, _ := reg.Gather()
			got := counterValue(t, families, tc.metricName, map[string]string{})
			if got != 1 {
				t.Fatalf("counter = %v, want 1", got)
			}
		})
	}
}
