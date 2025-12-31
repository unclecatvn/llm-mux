package cmd

import (
	"context"
	"fmt"

	"github.com/nghyane/llm-mux/internal/auth/login"
	"github.com/nghyane/llm-mux/internal/config"
	log "github.com/nghyane/llm-mux/internal/logging"
)

// DoAntigravityLogin triggers the OAuth flow for the antigravity provider and saves tokens.
func DoAntigravityLogin(cfg *config.Config, options *LoginOptions) {
	if options == nil {
		options = &LoginOptions{}
	}

	manager := newAuthManager()
	authOpts := &login.LoginOptions{
		NoBrowser: options.NoBrowser,
		Metadata:  map[string]string{},
		Prompt:    options.Prompt,
	}

	record, savedPath, err := manager.Login(context.Background(), "antigravity", cfg, authOpts)
	if err != nil {
		log.Errorf("Antigravity authentication failed: %v", err)
		return
	}

	if savedPath != "" {
		fmt.Printf("Authentication saved to %s\n", savedPath)
	}
	if record != nil && record.Label != "" {
		fmt.Printf("Authenticated as %s\n", record.Label)
	}
	fmt.Println("Antigravity authentication successful!")
}
