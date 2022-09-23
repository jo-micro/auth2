package auth2

import (
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"go-micro.dev/v4"
	"go-micro.dev/v4/errors"
)

type InitOptions struct {
	CliContext *cli.Context
	Service    micro.Service
	Logrus     *logrus.Logger
}

type InitOption func(o *InitOptions)

func CliContext(n *cli.Context) InitOption {
	return func(o *InitOptions) {
		o.CliContext = n
	}
}

func Service(n micro.Service) InitOption {
	return func(o *InitOptions) {
		o.Service = n
	}
}

func Logrus(n *logrus.Logger) InitOption {
	return func(o *InitOptions) {
		o.Logrus = n
	}
}

func NewInitOptions(opts ...InitOption) (InitOptions, error) {
	options := InitOptions{}
	for _, o := range opts {
		o(&options)
	}

	// Make CliContext() required
	if options.CliContext == nil {
		return options, errors.InternalServerError("auth2.NewInitOptions:no cli.Context", "no cli.Context hase been given")
	}

	return options, nil
}
