package login

import (
	"context"
	"fmt"
	"time"

	"github.com/nghyane/llm-mux/internal/auth/gemini"
	"github.com/nghyane/llm-mux/internal/config"
	"github.com/nghyane/llm-mux/internal/provider"
)

type GeminiAuthenticator struct{}

func NewGeminiAuthenticator() *GeminiAuthenticator {
	return &GeminiAuthenticator{}
}

func (a *GeminiAuthenticator) Provider() string {
	return "gemini-cli"
}

func (a *GeminiAuthenticator) RefreshLead() *time.Duration {
	return nil
}

func (a *GeminiAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*provider.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	var ts gemini.GeminiTokenStorage
	if opts.ProjectID != "" {
		ts.ProjectID = opts.ProjectID
	}

	geminiAuth := gemini.NewGeminiAuth()
	_, err := geminiAuth.GetAuthenticatedClient(ctx, &ts, cfg, opts.NoBrowser)
	if err != nil {
		return nil, fmt.Errorf("gemini authentication failed: %w", err)
	}

	fileName := fmt.Sprintf("%s-%s.json", ts.Email, ts.ProjectID)
	metadata := map[string]any{
		"email":      ts.Email,
		"project_id": ts.ProjectID,
	}

	fmt.Println("Gemini authentication successful")

	return &provider.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Storage:  &ts,
		Metadata: metadata,
	}, nil
}
