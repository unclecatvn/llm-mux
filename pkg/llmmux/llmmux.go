// Package llmmux provides the public API for embedding llm-mux as a library.
// It wraps the internal service implementation with a stable, minimal API surface.
package llmmux

import (
	"context"

	"github.com/nghyane/llm-mux/internal/access"
	"github.com/nghyane/llm-mux/internal/auth/login"
	"github.com/nghyane/llm-mux/internal/config"
	"github.com/nghyane/llm-mux/internal/provider"
	"github.com/nghyane/llm-mux/internal/service"
)

// Service wraps the proxy server lifecycle for external embedding.
type Service = service.Service

// Builder constructs a Service instance with customizable providers.
type Builder = service.Builder

// Hooks allows callers to plug into service lifecycle stages.
type Hooks = service.Hooks

// Config is the application configuration.
type Config = config.Config

// Auth represents a single credential entry.
type Auth = provider.Auth

// Manager orchestrates auth lifecycle, selection, execution, and persistence.
type Manager = provider.Manager

// Authenticator manages login and optional refresh flows for a provider.
type Authenticator = login.Authenticator

// LoginOptions captures generic knobs shared across authenticators.
type LoginOptions = login.LoginOptions

// AccessManager handles API key validation for incoming requests.
type AccessManager = access.Manager

// NewBuilder creates a new service builder with default dependencies.
func NewBuilder() *Builder {
	return service.NewBuilder()
}

// NewConfig creates a new default configuration.
func NewConfig() *Config {
	return config.NewDefaultConfig()
}

// LoadConfig loads configuration from the specified path.
func LoadConfig(path string) (*Config, error) {
	return config.LoadConfig(path)
}

// NewAuthManager creates a new authentication manager for login flows.
func NewAuthManager(store provider.Store, authenticators ...Authenticator) *login.Manager {
	return login.NewManager(store, authenticators...)
}

// NewProviderManager creates a new provider manager for request execution.
func NewProviderManager(store provider.Store) *Manager {
	return provider.NewManager(store, nil, nil)
}

// Run is a convenience function to create and run a service with default settings.
func Run(ctx context.Context, cfg *Config) error {
	svc, err := NewBuilder().
		WithConfig(cfg).
		Build()
	if err != nil {
		return err
	}
	return svc.Run(ctx)
}
