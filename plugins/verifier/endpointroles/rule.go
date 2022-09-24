package endpointroles

import (
	"jochum.dev/jo-micro/auth2"
	"jochum.dev/jo-micro/auth2/shared/sutil"
)

// Add this on every Server that exposes RouterClientService
var RouterRule = NewRule(
	Endpoint("RouterClientService.Routes"),
	RolesAllow([]string{auth2.ROLE_SERVICE}),
)

type Rule struct {
	Endpoint   string
	RolesAllow []string
	RolesDeny  []string
}

type RuleOption func(e *Rule)

func Endpoint(n interface{}) RuleOption {
	return func(e *Rule) {
		e.Endpoint = sutil.ReflectFunctionName(n)
	}
}

func RolesAllow(n []string) RuleOption {
	return func(e *Rule) {
		e.RolesAllow = n
	}
}

func RolesDeny(n []string) RuleOption {
	return func(e *Rule) {
		e.RolesDeny = n
	}
}

func NewRule(opts ...RuleOption) Rule {
	ep := Rule{
		RolesAllow: []string{},
		RolesDeny:  []string{},
	}
	for _, o := range opts {
		o(&ep)
	}
	return ep
}
