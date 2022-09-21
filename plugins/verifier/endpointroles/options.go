package endpointroles

type Options struct {
	DefaultDeny bool
}

type Option func(o *Options)

func NoDefaultDeny() Option {
	return func(o *Options) {
		o.DefaultDeny = false
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
