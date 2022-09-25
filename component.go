package auth2

import (
	"context"
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"
	"go-micro.dev/v4/errors"
	"go-micro.dev/v4/server"
	"jochum.dev/jo-micro/components"
)

const ClientAuthName = "clientauth"
const RouterAuthName = "routerauth"

func ClientAuthComponent() *AuthRegistry[ClientPlugin] {
	c := &AuthRegistry[ClientPlugin]{initialized: false, kind: "client", name: ClientAuthName, plugins: make(map[string]ClientPlugin)}
	c.Register(newNoopClientPlugin())

	return c
}

func ClientAuthMust(ctx context.Context) *AuthRegistry[ClientPlugin] {
	return components.Must(ctx).Must(ClientAuthName).(*AuthRegistry[ClientPlugin])
}

func ClientAuthMustReg(cReg *components.Registry) *AuthRegistry[ClientPlugin] {
	return cReg.Must(ClientAuthName).(*AuthRegistry[ClientPlugin])
}

func RouterAuthComponent() *AuthRegistry[RouterPlugin] {
	c := &AuthRegistry[RouterPlugin]{initialized: false, kind: "router", name: RouterAuthName, plugins: make(map[string]RouterPlugin)}
	c.Register(newNoopRouterPlugin())

	return c
}

func RouterAuthMust(ctx context.Context) *AuthRegistry[RouterPlugin] {
	return components.Must(ctx).Must(RouterAuthName).(*AuthRegistry[RouterPlugin])
}

func RouterAuthMustReg(cReg *components.Registry) *AuthRegistry[RouterPlugin] {
	return cReg.Must(RouterAuthName).(*AuthRegistry[RouterPlugin])
}

type AuthRegistry[T any] struct {
	initialized  bool
	forcedPlugin string
	kind         string
	name         string
	plugin       T
	pluginName   string
	plugins      map[string]T
}

func (r *AuthRegistry[T]) ForcePlugin(pName string) error {
	r.forcedPlugin = pName

	m, ok := r.plugins[pName]
	if !ok {
		return fmt.Errorf("unknown plugin '%s'", pName)
	}

	r.pluginName = pName
	r.plugin = m

	return nil
}

// Register registers a plugin within AuthRegistry
func (r *AuthRegistry[T]) Register(plugin T) {
	if s, ok := any(plugin).(registryFuncs); ok {
		r.plugins[s.String()] = plugin
	} else {
		panic("Unknown plugin")
	}
}

func (r *AuthRegistry[T]) Priority() int {
	return 100
}

func (r *AuthRegistry[T]) Name() string {
	return r.name
}

func (r *AuthRegistry[T]) Initialized() bool {
	return r.initialized
}

// Flags returns a list of cli.Flag's for micro.Service
func (r *AuthRegistry[T]) Flags(c *components.Registry) []cli.Flag {

	flags := []cli.Flag{}
	if r.forcedPlugin == "" {
		flags = []cli.Flag{
			&cli.StringFlag{
				Name:    fmt.Sprintf("auth2_%s", r.kind),
				Usage:   fmt.Sprintf("Auth %s Plugin to use", r.kind),
				EnvVars: []string{fmt.Sprintf("MICRO_AUTH2_%s", strings.ToUpper(r.kind))},
				Value:   "noop",
			},
		}
	}

	for _, p := range r.plugins {
		if p2, ok := any(p).(registryFuncs); ok {
			flags = append(flags, p2.Flags(c)...)
		}
	}

	return flags
}

// Plugin returns the current active Plugin
func (r *AuthRegistry[T]) Plugin() T {
	return r.plugin
}

// Init should be executed in micro.Init
func (r *AuthRegistry[T]) Init(c *components.Registry, cli *cli.Context) error {
	if r.forcedPlugin == "" {
		plugin := cli.String(fmt.Sprintf("auth2_%s", r.kind))
		m, ok := r.plugins[plugin]
		if !ok {
			return fmt.Errorf("unknown MICRO_AUTH2_%s plugin '%s'", strings.ToUpper(r.kind), plugin)
		}

		r.plugin = m
		r.pluginName = plugin
	}

	m2, _ := any(r.plugin).(registryFuncs)
	return m2.Init(c, cli)
}

// Stop should be executed after service.Run()
func (r *AuthRegistry[T]) Stop() error {
	m, _ := any(r.plugin).(registryFuncs)
	return m.Stop()
}

// Health returns the health of the plugin
func (r *AuthRegistry[T]) Health(ctx context.Context) error {
	m, _ := any(r.plugin).(registryFuncs)
	return m.Health(ctx)
}

// WrapHandlerFunc returns a server.HandleWrapper, this works only for ClientPlugin
func (r *AuthRegistry[T]) WrapHandlerFunc(ctx context.Context, req server.Request, rsp interface{}) error {
	m, ok := any(r.plugin).(ClientPlugin)
	if !ok {
		return errors.InternalServerError("NO_SUCH_AUTH_PLUGIN", fmt.Sprintf("No plugin '%s' found", r.pluginName))
	}

	return m.WrapHandlerFunc(ctx, req, rsp)
}
