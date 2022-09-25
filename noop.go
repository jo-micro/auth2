package auth2

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
	"go-micro.dev/v4/errors"
	"go-micro.dev/v4/server"
	"jochum.dev/jo-micro/components"
)

func newNoopClientPlugin() ClientPlugin {
	return new(noopClientPlugin)
}

type noopClientPlugin struct{}

func (p *noopClientPlugin) String() string {
	return "noop"
}

func (p *noopClientPlugin) Flags(r *components.Registry) []cli.Flag {
	return []cli.Flag{}
}

func (p *noopClientPlugin) Init(r *components.Registry, cli *cli.Context) error {
	return nil
}

func (p *noopClientPlugin) Stop() error {
	return nil
}

func (p *noopClientPlugin) Health(ctx context.Context) error {
	return nil
}

func (p *noopClientPlugin) SetVerifier(v VerifierPlugin) {
}

func (p *noopClientPlugin) ServiceContext(ctx context.Context) (context.Context, error) {
	return ctx, nil
}

func (p *noopClientPlugin) Inspect(ctx context.Context) (*User, error) {
	return &User{Id: uuid.New().String(), Issuer: p.String()}, nil
}

func (p *noopClientPlugin) WrapHandlerFunc(ctx context.Context, req server.Request, rsp interface{}) error {
	return errors.MethodNotAllowed("NO_AUTH_METHOD", "no auth method - noop plugin")
}

func newNoopRouterPlugin() RouterPlugin {
	return new(noopRouterPlugin)
}

type noopRouterPlugin struct{}

func (p *noopRouterPlugin) String() string {
	return "noop"
}

func (p *noopRouterPlugin) Flags(r *components.Registry) []cli.Flag {
	return []cli.Flag{}
}

func (p *noopRouterPlugin) Init(r *components.Registry, cli *cli.Context) error {
	return nil
}

func (p *noopRouterPlugin) Stop() error {
	return nil
}

func (p *noopRouterPlugin) Health(ctx context.Context) error {
	return nil
}

func (p *noopRouterPlugin) Inspect(r *http.Request) (*User, error) {
	return &User{Id: uuid.New().String(), Issuer: p.String()}, nil
}

func (p *noopRouterPlugin) ForwardContext(u *User, r *http.Request, ctx context.Context) (context.Context, error) {
	return ctx, nil
}
