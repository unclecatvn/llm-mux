package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/nghyane/llm-mux/internal/auth/login"
	"github.com/nghyane/llm-mux/internal/config"
	log "github.com/nghyane/llm-mux/internal/logging"
)

// DoIFlowLogin performs the iFlow OAuth login via the shared authentication manager.
func DoIFlowLogin(cfg *config.Config, options *LoginOptions) {
	if options == nil {
		options = &LoginOptions{}
	}

	manager := newAuthManager()

	promptFn := options.Prompt
	if promptFn == nil {
		promptFn = func(prompt string) (string, error) {
			fmt.Println()
			fmt.Println(prompt)
			var value string
			_, err := fmt.Scanln(&value)
			return value, err
		}
	}

	authOpts := &login.LoginOptions{
		NoBrowser: options.NoBrowser,
		Metadata:  map[string]string{},
		Prompt:    promptFn,
	}

	_, savedPath, err := manager.Login(context.Background(), "iflow", cfg, authOpts)
	if err != nil {
		var emailErr *login.EmailRequiredError
		if errors.As(err, &emailErr) {
			log.Error(emailErr.Error())
			return
		}
		fmt.Printf("iFlow authentication failed: %v\n", err)
		return
	}

	if savedPath != "" {
		fmt.Printf("Authentication saved to %s\n", savedPath)
	}

	fmt.Println("iFlow authentication successful!")
}
