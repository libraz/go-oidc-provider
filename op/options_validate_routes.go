package op

import (
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/protectedresource"
	"github.com/libraz/go-oidc-provider/internal/ssf"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
)

type configuredEndpoint struct {
	name  string
	value string
}

type routeReservation struct {
	name   string
	path   string
	prefix bool
}

// validateEndpointRouting rejects paths that net/http cannot route
// predictably and detects conflicts in the route set that this exact
// configuration enables. The check runs before buildRouter so an embedder
// always receives a configuration error instead of an http.ServeMux panic.
func (c *config) validateEndpointRouting() error {
	if err := c.validateConfiguredRoutePaths(); err != nil {
		return err
	}
	return validateRouteCollisions(c.activeRouteReservations())
}

func (c *config) validateConfiguredRoutePaths() error {
	if err := validateConfiguredRoutePath("WithMountPrefix", c.mountPrefix, true); err != nil {
		return err
	}
	if p := issuerPath(c.issuer); p != "" {
		if err := validateConfiguredRoutePath("WithIssuer path", p, false); err != nil {
			return err
		}
	}
	for _, endpoint := range c.configuredEndpoints() {
		if err := validateConfiguredRoutePath("WithEndpoints."+endpoint.name, endpoint.value, false); err != nil {
			return err
		}
	}
	if c.spaUISet {
		if err := validateConfiguredRoutePath("WithSPAUI.LoginMount", c.spaUI.LoginMount, false); err != nil {
			return err
		}
	}

	return nil
}

func validateRouteCollisions(routes []routeReservation) error {
	for i := range routes {
		for j := i + 1; j < len(routes); j++ {
			if routesConflict(routes[i], routes[j]) {
				return newConfigurationError("route collision between "+routes[i].name+" ("+routes[i].path+
					") and "+routes[j].name+" ("+routes[j].path+")", nil)
			}
		}
	}
	return nil
}

func (c *config) configuredEndpoints() []configuredEndpoint {
	return []configuredEndpoint{
		{name: "Discovery", value: c.endpoints.Discovery},
		{name: "JWKS", value: c.endpoints.JWKS},
		{name: "Authorize", value: c.endpoints.Authorize},
		{name: "Token", value: c.endpoints.Token},
		{name: "UserInfo", value: c.endpoints.UserInfo},
		{name: "EndSession", value: c.endpoints.EndSession},
		{name: "Introspect", value: c.endpoints.Introspect},
		{name: "Revoke", value: c.endpoints.Revoke},
		{name: "PAR", value: c.endpoints.PAR},
		{name: "Interaction", value: c.endpoints.Interaction},
		{name: "Session", value: c.endpoints.Session},
		{name: "Register", value: c.endpoints.Register},
		{name: "DeviceAuthorization", value: c.endpoints.DeviceAuthorization},
		{name: "Backchannel", value: c.endpoints.Backchannel},
		{name: "GrantManagement", value: c.endpoints.GrantManagement},
		{name: "SSFConfiguration", value: c.endpoints.SSFConfiguration},
		{name: "SSFStatus", value: c.endpoints.SSFStatus},
		{name: "SSFVerify", value: c.endpoints.SSFVerify},
		{name: "SSFPoll", value: c.endpoints.SSFPoll},
	}
}

func validateConfiguredRoutePath(name, value string, allowRoot bool) error {
	description := name + " must be a clean absolute path without query, fragment, wildcard, or percent-encoding"
	if value == "" || !strings.HasPrefix(value, "/") {
		return newConfigurationError(description, nil)
	}
	if (!allowRoot && value == "/") ||
		strings.ContainsAny(value, "?#{}%\\") ||
		path.Clean(value) != value {
		return newConfigurationError(description, nil)
	}
	for _, r := range value {
		if r <= ' ' || r == 0x7f {
			return newConfigurationError(description, nil)
		}
	}
	u, err := url.ParseRequestURI(value)
	if err != nil || u.IsAbs() || u.Host != "" || u.RawQuery != "" || u.Fragment != "" {
		return newConfigurationError(description, err)
	}
	return nil
}

func (c *config) activeRouteReservations() []routeReservation {
	routes := []routeReservation{
		{name: "WithEndpoints.Discovery", path: discoveryEndpointPath(c)},
		{name: "WithEndpoints.JWKS", path: protocolEndpointPath(c, c.endpoints.JWKS)},
		{name: "WithEndpoints.Token", path: protocolEndpointPath(c, c.endpoints.Token)},
		{name: "WithEndpoints.UserInfo", path: protocolEndpointPath(c, c.endpoints.UserInfo)},
	}
	authorizeEnabled := grantsRequireAuthorizeEndpoint(c.grants)
	if authorizeEnabled {
		routes = append(routes,
			routeReservation{name: "WithEndpoints.Authorize", path: protocolEndpointPath(c, c.endpoints.Authorize)},
			routeReservation{name: "WithEndpoints.EndSession", path: protocolEndpointPath(c, c.endpoints.EndSession)},
			// Session is a public endpoint namespace reserved for the
			// interaction API. Reserve it even while its individual
			// operations remain owned by the interaction handler so an
			// override cannot be shadowed by another endpoint.
			routeReservation{name: "WithEndpoints.Session", path: protocolEndpointPath(c, c.endpoints.Session), prefix: true},
		)
		if c.spaUISet {
			routes = append(routes, routeReservation{
				name: "WithSPAUI.LoginMount", path: c.spaUI.LoginMount, prefix: true,
			})
		} else {
			routes = append(routes, routeReservation{
				name: "WithEndpoints.Interaction",
				path: protocolEndpointPath(c, c.endpoints.Interaction), prefix: true,
			})
		}
	}
	if featureEnabled(c.features, feature.PAR) {
		routes = append(routes, routeReservation{name: "WithEndpoints.PAR", path: protocolEndpointPath(c, c.endpoints.PAR)})
	}
	if featureEnabled(c.features, feature.Introspect) {
		routes = append(routes, routeReservation{name: "WithEndpoints.Introspect", path: protocolEndpointPath(c, c.endpoints.Introspect)})
	}
	if featureEnabled(c.features, feature.Revoke) {
		routes = append(routes, routeReservation{name: "WithEndpoints.Revoke", path: protocolEndpointPath(c, c.endpoints.Revoke)})
	}
	if c.dcr != nil {
		routes = append(routes, routeReservation{name: "WithEndpoints.Register", path: protocolEndpointPath(c, c.endpoints.Register), prefix: true})
	}
	if c.grantEnabled(grant.DeviceCode) {
		routes = append(routes, routeReservation{name: "WithEndpoints.DeviceAuthorization", path: protocolEndpointPath(c, c.endpoints.DeviceAuthorization)})
	}
	if c.grantEnabled(grant.CIBA) {
		routes = append(routes, routeReservation{name: "WithEndpoints.Backchannel", path: protocolEndpointPath(c, c.endpoints.Backchannel)})
	}
	if c.grantManagementEnabled {
		routes = append(routes, routeReservation{name: "WithEndpoints.GrantManagement", path: protocolEndpointPath(c, c.endpoints.GrantManagement), prefix: true})
	}
	if c.sharedSignals {
		routes = append(routes,
			routeReservation{name: "WithEndpoints.SSFConfiguration", path: protocolEndpointPath(c, c.endpoints.SSFConfiguration)},
			routeReservation{name: "WithEndpoints.SSFStatus", path: protocolEndpointPath(c, c.endpoints.SSFStatus)},
			routeReservation{name: "WithEndpoints.SSFVerify", path: protocolEndpointPath(c, c.endpoints.SSFVerify)},
			routeReservation{name: "WithEndpoints.SSFPoll", path: protocolEndpointPath(c, c.endpoints.SSFPoll), prefix: true},
		)
		// The metadata sits at the host root like RFC 9728's, so it is
		// reserved by absolute path. The issuer has already been validated.
		if wellKnown, err := ssf.WellKnownPath(c.issuer); err == nil {
			routes = append(routes, routeReservation{name: "WithSharedSignals metadata", path: wellKnown})
		}
	}
	for i := range c.protectedResources {
		routes = append(routes, routeReservation{
			name: "WithProtectedResources[" + strconv.Itoa(i) + "]",
			path: protectedresource.WellKnownPath(c.protectedResources[i].Resource),
		})
	}
	return routes
}

func routesConflict(a, b routeReservation) bool {
	if a.path == b.path {
		return true
	}
	return a.prefix && strings.HasPrefix(b.path, a.path+"/") ||
		b.prefix && strings.HasPrefix(a.path, b.path+"/")
}
