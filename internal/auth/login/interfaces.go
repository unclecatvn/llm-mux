package login

import (
	"context"
	"errors"
	"time"

	"github.com/nghyane/llm-mux/internal/config"
	"github.com/nghyane/llm-mux/internal/provider"
)

var ErrRefreshNotSupported = errors.New("cliproxy auth: refresh not supported")

type LoginOptions struct {
	NoBrowser bool
	ProjectID string
	Metadata  map[string]string
	Prompt    func(prompt string) (string, error)
}

type Authenticator interface {
	Provider() string
	Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*provider.Auth, error)
	RefreshLead() *time.Duration
}
