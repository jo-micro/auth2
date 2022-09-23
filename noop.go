package auth2

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
	"go-micro.dev/v4/server"
)

func init() {
	ClientAuthRegistry().Register(newNoopClientPlugin())
	RouterAuthRegistry().Register(newNoopRouterPlugin())
}

func newNoopClientPlugin() ClientPlugin {
	return new(noopClientPlugin)
}

type noopClientPlugin struct{}

func (p *noopClientPlugin) String() string {
	return "noop"
}

func (p *noopClientPlugin) MergeFlags(flags []cli.Flag) []cli.Flag {
	return flags
}

func (p *noopClientPlugin) Init(opts ...InitOption) error {
	return nil
}

func (p *noopClientPlugin) Stop() error {
	return nil
}

func (p *noopClientPlugin) Health(ctx context.Context) (string, error) {
	return "All fine", nil
}

func (p *noopClientPlugin) SetVerifier(v VerifierPlugin) {
}

func (p *noopClientPlugin) ServiceContext(ctx context.Context) (context.Context, error) {
	return ctx, nil
}

func (p *noopClientPlugin) Inspect(ctx context.Context) (*User, error) {
	return &User{Id: uuid.New().String(), Issuer: p.String()}, nil
}

func (p *noopClientPlugin) WrapperFunc(h server.HandlerFunc, ctx context.Context, req server.Request, rsp interface{}) error {
	return h(ctx, req, rsp)
}

func newNoopRouterPlugin() RouterPlugin {
	return new(noopRouterPlugin)
}

type noopRouterPlugin struct{}

func (p *noopRouterPlugin) String() string {
	return "noop"
}

func (p *noopRouterPlugin) MergeFlags(flags []cli.Flag) []cli.Flag {
	return flags
}

func (p *noopRouterPlugin) Init(opts ...InitOption) error {
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
