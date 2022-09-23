package endpointroles

import (
	"context"

	"go-micro.dev/v4/errors"
	"go-micro.dev/v4/server"
	"jochum.dev/jo-micro/auth2"

	"github.com/sirupsen/logrus"
)

type EndpointRolesVerifier struct {
	rules         map[string]Rule
	endpointnames []string
	options       Options
}

func NewVerifier(opts ...Option) *EndpointRolesVerifier {
	options := NewOptions(opts...)

	return &EndpointRolesVerifier{
		rules:         make(map[string]Rule, 0),
		endpointnames: []string{},
		options:       options,
	}
}

func (v *EndpointRolesVerifier) AddRules(rules ...Rule) {
	for _, rule := range rules {
		v.endpointnames = append(v.endpointnames, rule.Endpoint)
		v.rules[rule.Endpoint] = rule
	}
}

func (v *EndpointRolesVerifier) logrus() *logrus.Logger {
	if v.options.Logrus == nil {
		return logrus.StandardLogger()
	}

	return v.options.Logrus
}

func (v *EndpointRolesVerifier) Verify(ctx context.Context, u *auth2.User, req server.Request) error {
	if ep, ok := v.rules[req.Endpoint()]; ok {
		if auth2.IntersectsRoles(u, ep.RolesDeny...) {
			v.logrus().WithField("endpoint", req.Endpoint()).WithField("rolesDeny", ep.RolesDeny).WithField("userRoles", u.Roles).Debug("Unauthorized")
			return errors.Unauthorized("auth2/plugins/verifier/endpointroles/EndpointRolesVerifier.Verify|Denied by rule", "Unauthorized")
		}
		if auth2.IntersectsRoles(u, ep.RolesAllow...) {
			v.logrus().WithField("endpoint", req.Endpoint()).WithField("rolesAllow", ep.RolesAllow).WithField("userRoles", u.Roles).Trace("Authorized")
			// Allowed by role
			return nil
		}

		if v.options.DefaultDeny {
			v.logrus().WithField("endpoint", req.Endpoint()).WithField("user_roles", u.Roles).WithField("roles_allow", ep.RolesAllow).Debug("DefaultDeny: No matching role")
			return errors.Unauthorized("auth2/plugins/verifier/endpointroles/EndpointRolesVerifier.Verify|No matching role", "Unauthorized")
		}
	}

	if !v.options.DefaultDeny {
		v.logrus().WithField("endpoint", req.Endpoint()).WithField("endpoints", v.endpointnames).Trace("DefaultAllow: No rule")
		return nil
	}

	v.logrus().WithField("endpoint", req.Endpoint()).WithField("endpoints", v.endpointnames).Debug("DefaultDeny: no rule")
	return errors.Unauthorized("auth2/plugins/verifier/endpointroles/EndpointRolesVerifier.Verify|No rule", "Unauthorized")
}
