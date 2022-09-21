package auth2

import (
	"context"
	"net/http"

	"github.com/urfave/cli/v2"
	"go-micro.dev/v4"
	"go-micro.dev/v4/server"
)

type registryFuncs interface {
	// String returns the name of the plugin
	String() string

	// AppendFlags appends a list of cli.Flag's for micro.Service
	AppendFlags(flags []cli.Flag) []cli.Flag

	// Init should be executed in micro.Init
	Init(cli *cli.Context, service micro.Service) error

	// Stop should be executed after service.Run()
	Stop() error

	// Health returns the health of the plugin
	Health(ctx context.Context) (string, error)
}

type VerifierPlugin interface {
	// Verify verifies that the user is allowed to access the request, it MUST handle AnonUser
	Verify(ctx context.Context, u *User, req server.Request) error
}

// ClientPlugin is for services that act as client's behind GinRouter
type ClientPlugin interface {
	registryFuncs

	// Set the Verifier for this Client
	SetVerifier(v VerifierPlugin)

	// ServiceContext adds the ServiceUser to the context (when using JWT's it will overwrite the Authorization Header)
	ServiceContext(ctx context.Context) (context.Context, error)

	// Inspect a context
	Inspect(ctx context.Context) (*User, error)

	// Wrapper returns the Auth Wrapper for your service
	Wrapper() server.HandlerWrapper
}

// RouterPlugin is for routers that forward the token or do other stuff required by ClientPlugin
type RouterPlugin interface {
	registryFuncs

	// Inspect a http.Request
	Inspect(r *http.Request) (*User, error)

	// ForwardContext should forward all required informations from http.Request to the resulting context.
	ForwardContext(r *http.Request, ctx context.Context) (context.Context, error)
}
