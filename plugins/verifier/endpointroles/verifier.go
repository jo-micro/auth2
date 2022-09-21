package endpointroles

import (
	"context"

	"go-micro.dev/v4/errors"
	"go-micro.dev/v4/server"
	"jochum.dev/jo-micro/auth2"
	"jochum.dev/jo-micro/auth2/internal/ilogger"
)

type EndpointRolesVerifier struct {
	rules   map[string]Rule
	options Options
}

func NewVerifier(opts ...Option) *EndpointRolesVerifier {
	options := NewOptions(opts...)

	return &EndpointRolesVerifier{
		rules:   make(map[string]Rule, 0),
		options: options,
	}
}

func (v *EndpointRolesVerifier) AddRules(rules ...Rule) {
	for _, rule := range rules {
		v.rules[rule.Endpoint] = rule
	}
}

func (v *EndpointRolesVerifier) Verify(ctx context.Context, u *auth2.User, req server.Request) error {
	if ep, ok := v.rules[req.Endpoint()]; ok {
		if auth2.IntersectsRoles(u, ep.RolesDeny...) {
			ilogger.Logrus().WithField("endpoint", req.Endpoint()).WithField("rolesDeny", ep.RolesDeny).WithField("userRoles", u.Roles).Debug("Unauthorized")
			return errors.Unauthorized("auth2/plugins/verifier/endpointroles/EndpointRolesVerifier.Verify|Denied by rule", "Unauthorized")
		}
		if auth2.IntersectsRoles(u, ep.RolesAllow...) {
			ilogger.Logrus().WithField("endpoint", req.Endpoint()).WithField("rolesAllow", ep.RolesAllow).WithField("userRoles", u.Roles).Trace("Authorized")
			// Allowed by role
			return nil
		}

		if v.options.DefaultDeny {
			ilogger.Logrus().WithField("endpoint", req.Endpoint()).Debug("DefaultDeny: not in RolesAllow/Deny")
			return errors.Unauthorized("auth2/plugins/verifier/endpointroles/EndpointRolesVerifier.Verify|No matching Role", "Unauthorized")
		}
	}

	if !v.options.DefaultDeny {
		ilogger.Logrus().WithField("endpoint", req.Endpoint()).Trace("DefaultAllow: no rule")
		return nil
	}

	ilogger.Logrus().WithField("endpoint", req.Endpoint()).Debug("DefaultDeny: no rule")
	return errors.Unauthorized("auth2/plugins/verifier/endpointroles/EndpointRolesVerifier.Verify|No rule for EP", "Unauthorized")
}
