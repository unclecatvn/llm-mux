package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/nghyane/llm-mux/internal/auth/codex"
	"github.com/nghyane/llm-mux/internal/auth/login"
	"github.com/nghyane/llm-mux/internal/config"
	log "github.com/nghyane/llm-mux/internal/logging"
)

// LoginOptions contains options for the login processes.
// It provides configuration for authentication flows including browser behavior
// and interactive prompting capabilities.
type LoginOptions struct {
	// NoBrowser indicates whether to skip opening the browser automatically.
	NoBrowser bool

	// Prompt allows the caller to provide interactive input when needed.
	Prompt func(prompt string) (string, error)
}

// DoCodexLogin triggers the Codex OAuth flow through the shared authentication manager.
// It initiates the OAuth authentication process for OpenAI Codex services and saves
// the authentication tokens to the configured auth directory.
// Parameters:
//   - cfg: The application configuration
//   - options: Login options including browser behavior and prompts
func DoCodexLogin(cfg *config.Config, options *LoginOptions) {
	if options == nil {
		options = &LoginOptions{}
	}

	manager := newAuthManager()

	authOpts := &login.LoginOptions{
		NoBrowser: options.NoBrowser,
		Metadata:  map[string]string{},
		Prompt:    options.Prompt,
	}

	_, savedPath, err := manager.Login(context.Background(), "codex", cfg, authOpts)
	if err != nil {
		var authErr *codex.AuthenticationError
		if errors.As(err, &authErr) {
			log.Error(codex.GetUserFriendlyMessage(authErr))
			if authErr.Type == codex.ErrPortInUse.Type {
				os.Exit(codex.ErrPortInUse.Code)
			}
			return
		}
		fmt.Printf("Codex authentication failed: %v\n", err)
		return
	}

	if savedPath != "" {
		fmt.Printf("Authentication saved to %s\n", savedPath)
	}
	fmt.Println("Codex authentication successful!")
}
