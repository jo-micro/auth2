package endpointroles

import "github.com/sirupsen/logrus"

type Options struct {
	DefaultDeny bool
	Logrus      *logrus.Logger
}

type Option func(o *Options)

func NoDefaultDeny() Option {
	return func(o *Options) {
		o.DefaultDeny = false
	}
}

func WithLogrus(n *logrus.Logger) Option {
	return func(o *Options) {
		o.Logrus = n
	}
}

func NewOptions(opts ...Option) Options {
	options := Options{
		DefaultDeny: true,
	}
	for _, o := range opts {
		o(&options)
	}
	return options
}
