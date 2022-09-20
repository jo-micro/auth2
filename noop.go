package auth

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
	"go-micro.dev/v4"
	"go-micro.dev/v4/server"
)

func init() {
	ClientAuthRegistry().Register(newNoopClientPlugin())
	ServiceAuthRegistry().Register(newNoopServicePlugin())
	RouterAuthRegistry().Register(newNoopRouterPlugin())
}

func newNoopClientPlugin() ClientPlugin {
	return new(noopClientPlugin)
}

type noopClientPlugin struct{}

func (p *noopClientPlugin) String() string {
	return "noop"
}

func (p *noopClientPlugin) Flags() []cli.Flag {
	return []cli.Flag{}
}

func (p *noopClientPlugin) Init(cli *cli.Context, service micro.Service) error {
	return nil
}

func (p *noopClientPlugin) Stop() error {
	return nil
}

func (p *noopClientPlugin) Health(ctx context.Context) (string, error) {
	return "All fine", nil
}

func (p *noopClientPlugin) Inspect(ctx context.Context) (*User, error) {
	return &User{Id: uuid.New().String(), Issuer: p.String()}, nil
}

func (p *noopClientPlugin) Wrapper() server.HandlerWrapper {
	return func(h server.HandlerFunc) server.HandlerFunc {
		return func(ctx context.Context, req server.Request, rsp interface{}) error {
			return h(ctx, req, rsp)
		}
	}
}

func newNoopServicePlugin() ServerPlugin {
	return new(noopServicePlugin)
}

type noopServicePlugin struct{}

func (p *noopServicePlugin) String() string {
	return "noop"
}

func (p *noopServicePlugin) Flags() []cli.Flag {
	return []cli.Flag{}
}

func (p *noopServicePlugin) Init(cli *cli.Context, service micro.Service) error {
	return nil
}

func (p *noopServicePlugin) Stop() error {
	return nil
}

func (p *noopServicePlugin) Health(ctx context.Context) (string, error) {
	return "All fine", nil
}

func newNoopRouterPlugin() RouterPlugin {
	return new(noopRouterPlugin)
}

type noopRouterPlugin struct{}

func (p *noopRouterPlugin) String() string {
	return "noop"
}

func (p *noopRouterPlugin) Flags() []cli.Flag {
	return []cli.Flag{}
}

func (p *noopRouterPlugin) Init(cli *cli.Context, service micro.Service) error {
	return nil
}

func (p *noopRouterPlugin) Stop() error {
	return nil
}

func (p *noopRouterPlugin) Health(ctx context.Context) (string, error) {
	return "All fine", nil
}

func (p *noopRouterPlugin) Inspect(r *http.Request) (*User, error) {
	return &User{Id: uuid.New().String(), Issuer: p.String()}, nil
}

func (p *noopRouterPlugin) ForwardContext(r *http.Request, ctx context.Context) (context.Context, error) {
	return ctx, nil
}
