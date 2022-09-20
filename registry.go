package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"
	"go-micro.dev/v4"
)

var car = &AuthRegistry[ClientPlugin]{kind: "client", plugins: make(map[string]ClientPlugin)}
var sar = &AuthRegistry[ServerPlugin]{kind: "service", plugins: make(map[string]ServerPlugin)}
var rar = &AuthRegistry[RouterPlugin]{kind: "router", plugins: make(map[string]RouterPlugin)}

func ClientAuthRegistry() *AuthRegistry[ClientPlugin] {
	return car
}

func ServiceAuthRegistry() *AuthRegistry[ServerPlugin] {
	return sar
}

func RouterAuthRegistry() *AuthRegistry[RouterPlugin] {
	return rar
}

type AuthRegistry[T any] struct {
	kind    string
	plugin  T
	plugins map[string]T
}

// Register registers a plugin within AuthRegistry
func (r *AuthRegistry[T]) Register(plugin T) {
	if s, ok := any(plugin).(registryFuncs); ok {
		r.plugins[s.String()] = plugin
	}
}

// Flags returns a list of cli.Flag's for micro.Service
func (r *AuthRegistry[T]) Flags() []cli.Flag {
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:    fmt.Sprintf("auth2_%s", r.kind),
			Usage:   fmt.Sprintf("Auth %s Plugin to use", r.kind),
			EnvVars: []string{fmt.Sprintf("MICRO_AUTH2_%s", strings.ToUpper(r.kind))},
			Value:   "noop",
		},
	}
	for _, p := range r.plugins {
		if p2, ok := any(p).(registryFuncs); ok {
			flags = append(flags, p2.Flags()...)
		}
	}

	return flags
}

// Plugin returns the current active Plugin
func (r *AuthRegistry[T]) Plugin() T {
	return r.plugin
}

// Init should be executed in micro.Init
func (r *AuthRegistry[T]) Init(cli *cli.Context, service micro.Service) error {
	plugin := cli.String(fmt.Sprintf("auth2_%s", r.kind))

	m, ok := r.plugins[plugin]
	if !ok {
		return fmt.Errorf("unknown MICRO_AUTH2_%s plugin '%s'", strings.ToUpper(r.kind), plugin)
	}

	r.plugin = m

	m2, _ := any(m).(registryFuncs)
	return m2.Init(cli, service)
}

// Stop should be executed after service.Run()
func (r *AuthRegistry[T]) Stop() error {
	m, _ := any(r.plugin).(registryFuncs)
	return m.Stop()
}

// Health returns the health of the plugin
func (r *AuthRegistry[T]) Health(ctx context.Context) (string, error) {
	m, _ := any(r.plugin).(registryFuncs)
	return m.Health(ctx)
}
