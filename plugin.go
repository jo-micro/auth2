package auth2

import (
	"context"
	"net/http"

	"github.com/urfave/cli/v2"
	"go-micro.dev/v4/server"
	"jochum.dev/jo-micro/components"
)

type registryFuncs interface {
	// String returns the name of the plugin
	String() string

	// MergeFlags merges a list of cli.Flag's for micro.Service
	Flags(r *components.Registry) []cli.Flag

	// Init should be executed in micro.Init
	Init(r *components.Registry, cli *cli.Context) error

	// Stop should be executed after service.Run()
	Stop() error

	// Health returns the health of the plugin
	Health(ctx context.Context) error
}

type VerifierPlugin interface {
	// Verify verifies that the user is allowed to access the request, it MUST handle AnonUser
	// @return
	// 		error 	nil if its allowed, else an error
	//		bool	if the error given is a default error
	Verify(ctx context.Context, u *User, req server.Request) (error, bool)
}

// ClientPlugin is for services that act as client's behind GinRouter
type ClientPlugin interface {
	registryFuncs

	// Set the Verifier for this Client
	AddVerifier(v VerifierPlugin)

	// ServiceContext adds the ServiceUser to the context (when using JWT's it will overwrite the Authorization Header)
	ServiceContext(ctx context.Context) (context.Context, error)

	// Inspect a context
	Inspect(ctx context.Context) (*User, error)

	// WrapHandlerFunc runs the authentication
	WrapHandlerFunc(ctx context.Context, req server.Request, rsp interface{}) error
}

// RouterPlugin is for routers that forward the token or do other stuff required by ClientPlugin
type RouterPlugin interface {
	registryFuncs

	// Inspect a http.Request
	Inspect(r *http.Request) (*User, error)

	// ForwardContext should forward all required informations from http.Request to the resulting context.
	ForwardContext(u *User, r *http.Request, ctx context.Context) (context.Context, error)
}
