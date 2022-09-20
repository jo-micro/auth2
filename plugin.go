package auth

import (
	"context"
	"net/http"

	"github.com/urfave/cli/v2"
	"go-micro.dev/v4"
	"go-micro.dev/v4/server"
)

type User struct {
	Id       string            `json:"id,omitempty"`
	Type     string            `json:"type,omitempty"`
	Issuer   string            `json:"issuer,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Scopes   []string          `json:"scopes,omitempty"`
	Roles    []string          `json:"roles,omitempty"`
}

type registryFuncs interface {
	// String returns the name of the plugin
	String() string

	// Flags returns a list of cli.Flag's for micro.Service
	Flags() []cli.Flag

	// Init should be executed in micro.Init
	Init(cli *cli.Context, service micro.Service) error

	// Stop should be executed after service.Run()
	Stop() error

	// Health returns the health of the plugin
	Health(ctx context.Context) (string, error)
}

// ClientPlugin is for services that act as client's behind GinRouter
type ClientPlugin interface {
	registryFuncs

	// Inspect a context
	Inspect(ctx context.Context) (*User, error)

	// Wrapper returns the Auth Wrapper for your service
	Wrapper() server.HandlerWrapper
}

// ServerPlugin is for authservers
type ServerPlugin interface {
	registryFuncs
}

// RouterPlugin is for routers that forward the token or do other stuff required by ClientPlugin
type RouterPlugin interface {
	registryFuncs

	// Inspect a http.Request
	Inspect(r *http.Request) (*User, error)

	// ForwardContext should forward all required informations from http.Request to the resulting context.
	ForwardContext(r *http.Request, ctx context.Context) (context.Context, error)
}
